#![no_std]
#![no_main]
use aya_ebpf::{
    bindings::xdp_action, macros::xdp, programs::XdpContext,
};
use aya_log_ebpf::{error, info};
use core::net::Ipv4Addr;
use aya_ebpf::bindings::{BPF_F_PSEUDO_HDR, TC_ACT_OK};
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::bpf_redirect;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{LpmTrie, Array, HashMap};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::TcContext;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
    // vxlan::VxlanHdr,
    // geneve::GeneveHdr
};
use network_types::arp::ArpHdr;

static V_PORT: u16 = 80u16;

#[repr(C)]
#[derive(Clone, Copy)]
struct IpPort {
    ip:  Ipv4Addr,
    port: u16,
}

#[map]
static BACKEND_MAP: HashMap<IpPort, IpPortMAC> = HashMap::with_max_entries(60000, 0);

#[map]
static CONFIG_ARRAY: Array<u32> = Array::with_max_entries(20, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct IpPortMAC {
    ip:  Ipv4Addr,
    port: u16,
    mac: [u8; 6],
}
#[map]
static BACKENDS: Array<IpPortMAC>= Array::with_max_entries(1024, 0);

static mut BACKEND_INDEX: u32 = 0;
#[map]
static FIREWALL_RULE_MAP: LpmTrie<u32, u32>
= LpmTrie::with_max_entries(256, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[xdp]
pub fn my_xdp_app(ctx: XdpContext) -> u32 {
    match try_my_xdp_app(ctx) {
        Ok(ret) => ret,
        Err(_) => {
            error!(ctx, "something went wrong");
            xdp_action::XDP_ABORTED
        },
    }
}

fn try_my_xdp_app(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *mut EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *eth_hdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv4hdr).src_addr() };
            let dst_addr = unsafe { (*ipv4hdr).dst_addr() };
            let (source_port,dst_port) = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcp_hdr: *mut TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    (
                        u16::from_be_bytes(unsafe { (*tcp_hdr).source }),
                        u16::from_be_bytes(unsafe { (*tcp_hdr).dest })
                    )
                }
                IpProto::Udp => {
                    let udp_hdr: *mut UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    (
                        unsafe { (*udp_hdr).src_port() },
                        unsafe { (*udp_hdr).dst_port() }
                    )
                }
                // ICMP use 0 as port
                IpProto::Icmp => {(0,0)}
                // other protocols
                _ => return Ok(xdp_action::XDP_PASS),
            };

            info!(&ctx, "SRC IP: {:i}, DST IP: {:i}, SRC PORT: {}, DST PORT: {}",
                source_addr, dst_addr, source_port, dst_port);

            // firewall filter
            let key = Key::new(32, source_addr.to_bits().to_be());
            let action = match FIREWALL_RULE_MAP.get(&key){
                // match and apply rule
                Some(action) => *action,
                // not match pass
                None => {xdp_action::XDP_PASS}
            };
            info!(&ctx, "SRC action: {}", action);
            Ok(action)
        }
        Ok(EtherType::Arp) => {
            let arp_hdr: *const ArpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*arp_hdr).spa};
            let dst_addr = unsafe { (*arp_hdr).tpa};
            info!(&ctx, "ARP: SRC IP: {:i}, DST IP: {:i}", source_addr, dst_addr);
            Ok(xdp_action::XDP_PASS)
        }
        // not IPV4
        _ => Ok(xdp_action::XDP_PASS)
    }
}

#[classifier]
pub fn my_ingress_app(ctx: TcContext) -> i32 {
    try_my_ingress_app(ctx).unwrap_or_else(|ret| ret)
}

fn try_my_ingress_app(mut ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "enter ingress TC");
    let eth_hdr = ctx.load::<EthHdr>(0).map_err(|_| TC_ACT_OK)?;
    // only support ipv4
    if eth_hdr.ether_type()? != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }
    let ipv4hdr = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| TC_ACT_OK)?;
    let src_addr = ipv4hdr.src_addr();
    let dst_addr = ipv4hdr.dst_addr();
    // only for VIP
    let vip_bits = match CONFIG_ARRAY.get(8) {
        None => {info!(&ctx, "no config array"); 0u32}
        Some(r) => {*r}
    };
    let vip = Ipv4Addr::from(vip_bits);
    info!(&ctx, "VIP IPv4 address: {}", vip);
    if dst_addr != vip{
        return Ok(TC_ACT_OK);
    }
    // only deal with tcp
    let (src_port, dst_port) = match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcp = ctx.load::<TcpHdr>(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| TC_ACT_OK)?;
            (u16::from_be_bytes(tcp.source), u16::from_be_bytes(tcp.dest))
        }
        // IpProto::Udp => {
        //     let udp = ctx.load::<UdpHdr>(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| TC_ACT_OK)?;
        //     (udp.src_port(), udp.dst_port())
        // }
        _ => return Ok(TC_ACT_OK),
    };
    let checksum = ipv4hdr.checksum();

    // also check the port
    if dst_port != V_PORT {
        return Ok(TC_ACT_OK);
    }

    let number_of_backend = match CONFIG_ARRAY.get(6) {
        None => {1u32}
        Some(num) => {*num}
    };

    let current_backend_idx = match CONFIG_ARRAY.get(19) {
        None => {0}
        Some(num) => {*num}
    };

    let client_ip_port = IpPort{ip: src_addr, port: src_port};
    let backend = match unsafe { BACKEND_MAP.get(&client_ip_port) } {
        None => {
            // new connection
            match BACKENDS.get(unsafe { current_backend_idx }) {
                None => {
                    // no backend, pass
                    info!(&ctx, "backend not found");
                    return Ok(TC_ACT_OK);
                }
                // allocate a backend and record mapping
                Some(backend) => {
                    match BACKEND_MAP.insert(&client_ip_port, backend, 0) {
                        Ok(_) => {
                            info!(&ctx, "new connection successful");
                        }
                        Err(_) => {
                            info!(&ctx, "invalid client ip port mapping");
                        }
                    }
                    backend
                }
            }
        }
        Some(backend) => {
            info!(&ctx, "found backend mapping");
            backend
        }
    };

    let mut next_backend_idx = current_backend_idx + 1;
    if next_backend_idx >= number_of_backend {
        next_backend_idx = 0;
    }
    match CONFIG_ARRAY.set(19, &next_backend_idx, 0) {
        Ok(_) => {}
        Err(_) => {
            info!(&ctx, "updating backend index error");
            return Ok(TC_ACT_OK);
        }
    };
    // unsafe { BACKEND_INDEX = (BACKEND_INDEX + 1) % 2; }

    info!(&ctx, "DNAT {}:{} -> {}:{}, backendMAC {:x}:{:x}:{:x}:{:x}:{:x}:{:x}, checksum {:x}",
        dst_addr, dst_port,
        backend.ip, backend.port,
        backend.mac[0], backend.mac[1], backend.mac[2],
        backend.mac[3], backend.mac[4], backend.mac[5], checksum
    );
    let new_dst:[u8;4] = backend.ip.to_bits().to_be_bytes();
    let old_be = u32::from_le_bytes(dst_addr.octets());
    let new_be = u32::from_le_bytes(backend.ip.octets());
    // d nat ip
    match ctx.skb.store(EthHdr::LEN + 16, &new_dst, 0) {
        Ok(_) => {
            info!(&ctx, "dest stored successful");
            match ctx.skb.l3_csum_replace(EthHdr::LEN + 10, old_be as u64, new_be as u64, 4) {
                Ok(_) => {
                    info!(&ctx, "l3_csum_replace with {:x}->{:x}", old_be, new_be);
                }
                Err(e) => {
                    info!(&ctx, "l3_csum_replace failed with code {}", e);
                }
            };
            match ctx.skb.l4_csum_replace(EthHdr::LEN + Ipv4Hdr::LEN + 16, old_be as u64, new_be as u64, 4 | BPF_F_PSEUDO_HDR as u64) {
                Ok(_) => {
                    info!(&ctx, "l4_csum_replace with {:x}->{:x}", old_be, new_be);
                }
                Err(e) => {
                    info!(&ctx, "l4_csum_replace failed with code {}", e);
                }
            };
        }
        Err(_) => {
            info!(&ctx, "dest stored failed");
        }
    }
    // d nat mac
    match ctx.skb.store(0, &backend.mac, 0) {
        Ok(_) => {}
        Err(_) => {
            info!(&ctx, "mac stored failed");
        }
    }

    let eth_hdr = ctx.load::<EthHdr>(0).map_err(|_| TC_ACT_OK)?;
    // only support ipv4
    if eth_hdr.ether_type()? != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }
    let ipv4hdr = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| TC_ACT_OK)?;
    let src_addr = ipv4hdr.src_addr();
    let dst_addr = ipv4hdr.dst_addr();
    let checksum = ipv4hdr.checksum();

    info!(&ctx, "new SRC IP: {}, DST IP: {}, checksum: {:x}", src_addr, dst_addr, checksum);
    let docker_iface_idx = match CONFIG_ARRAY.get(7) {
        None => {
            info!(&ctx, "iface idx not found");
            0
        }
        Some(idx) => {*idx}
    };
    Ok(unsafe { bpf_redirect(docker_iface_idx, 0) as i32 })
}

#[classifier]
pub fn my_egress_app(ctx: TcContext) -> i32 {
    try_my_egress_app(ctx).unwrap_or_else(|ret| ret)
}

fn try_my_egress_app(mut ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "enter engress TC");
    let eth_hdr = ctx.load::<EthHdr>(0).map_err(|_| TC_ACT_OK)?;
    // only support ipv4
    if eth_hdr.ether_type()? != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }
    let ipv4hdr = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| TC_ACT_OK)?;
    let src_addr = ipv4hdr.src_addr();
    let dst_addr = ipv4hdr.dst_addr();
    // only for VIP
    let vip_bits = match CONFIG_ARRAY.get(8) {
        None => {info!(&ctx, "no config array"); 0u32}
        Some(r) => {*r}
    };
    // only deal with tcp
    let (src_port, dst_port) = match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcp = ctx.load::<TcpHdr>(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| TC_ACT_OK)?;
            (u16::from_be_bytes(tcp.source), u16::from_be_bytes(tcp.dest))
        }
        _ => return Ok(TC_ACT_OK),
    };

    let lb_mac0 = *CONFIG_ARRAY.get(0).ok_or(TC_ACT_OK)? as u8;
    let lb_mac1 = *CONFIG_ARRAY.get(1).ok_or(TC_ACT_OK)? as u8;
    let lb_mac2 = *CONFIG_ARRAY.get(2).ok_or(TC_ACT_OK)? as u8;
    let lb_mac3 = *CONFIG_ARRAY.get(3).ok_or(TC_ACT_OK)? as u8;
    let lb_mac4 = *CONFIG_ARRAY.get(4).ok_or(TC_ACT_OK)? as u8;
    let lb_mac5 = *CONFIG_ARRAY.get(5).ok_or(TC_ACT_OK)? as u8;
    info!(&ctx, "SRC IP: {:i}, DST IP: {:i}, SRC PORT: {}, DST PORT: {}",
        src_addr, dst_addr, src_port, dst_port
    );

    let client_ip_port = IpPort{ip: dst_addr, port: dst_port};

    unsafe {
        match BACKEND_MAP.get(&client_ip_port) {
            None => {return Ok(TC_ACT_OK)}
            // exist mapping, do SNAT
            Some(_) => {
                let vip = Ipv4Addr::from(vip_bits);
                info!(&ctx, "SNAT {}->{} LB_MAC {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",src_addr , vip,
                    lb_mac0, lb_mac1, lb_mac2, lb_mac3, lb_mac4, lb_mac5
                );
                // SNAT IP
                let old_be = u32::from_le_bytes(src_addr.octets());
                let new_be = u32::from_le_bytes(vip.octets());
                match ctx.skb.store(EthHdr::LEN + 12, &vip, 0) {
                    Ok(_) => {
                        info!(&ctx, "dest stored successful");
                        match ctx.skb.l3_csum_replace(EthHdr::LEN + 10, old_be as u64, new_be as u64, 4) {
                            Ok(_) => {
                                info!(&ctx, "l3_csum_replace with {:x}->{:x}", old_be, new_be);
                            }
                            Err(e) => {
                                info!(&ctx, "l3_csum_replace failed with code {}", e);
                            }
                        };
                        match ctx.skb.l4_csum_replace(EthHdr::LEN + Ipv4Hdr::LEN + 16, old_be as u64, new_be as u64, 4 | BPF_F_PSEUDO_HDR as u64) {
                            Ok(_) => {
                                info!(&ctx, "l4_csum_replace with {:x}->{:x}", old_be, new_be);
                            }
                            Err(e) => {
                                info!(&ctx, "l4_csum_replace failed with code {}", e);
                            }
                        };
                    }
                    Err(_) => {
                        info!(&ctx, "dest stored failed");
                    }
                }
                match ctx.skb.store(6, &[lb_mac0,lb_mac1,lb_mac2,lb_mac3,lb_mac4,lb_mac5], 0) {
                    Ok(_) => {}
                    Err(_) => {
                        info!(&ctx, "mac stored failed");
                    }
                }

            }
        }
    }
    // read again
    let eth_hdr = ctx.load::<EthHdr>(0).map_err(|_| TC_ACT_OK)?;
    // only support ipv4
    if eth_hdr.ether_type()? != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }
    let ipv4hdr = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| TC_ACT_OK)?;
    let src_addr = ipv4hdr.src_addr();
    let dst_addr = ipv4hdr.dst_addr();
    let src_mac = eth_hdr.src_addr;
    let dst_mac = eth_hdr.dst_addr;
    // only deal with tcp
    let (src_port, dst_port) = match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcp = ctx.load::<TcpHdr>(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| TC_ACT_OK)?;
            (u16::from_be_bytes(tcp.source), u16::from_be_bytes(tcp.dest))
        }
        _ => return Ok(TC_ACT_OK),
    };

    info!(&ctx, "new SRC: {}:{} MAC: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}, DST: {}:{} MAC: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        src_addr, src_port, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
        dst_addr, dst_port, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]
    );
    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

