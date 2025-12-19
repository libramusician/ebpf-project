#![no_std]
#![no_main]
use aya_ebpf::{
    bindings::xdp_action, macros::xdp, programs::XdpContext,
};
use aya_log_ebpf::{error, info};
use core::mem;
use core::net::Ipv4Addr;
use aya_ebpf::bindings::{BPF_F_PSEUDO_HDR, TC_ACT_OK};
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

static VIP: Ipv4Addr =  Ipv4Addr::new(192, 168, 3, 100);
static V_PORT: u16 = 80u16;

#[repr(C)]
#[derive(Clone, Copy)]
struct IpPort {
    ip:  Ipv4Addr,
    port: u16,
}

#[map]
static BACKEND_MAP: HashMap<IpPort, IpPortMAC> = HashMap::with_max_entries(60000, 0);

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
static mut BACKEND_NUMBER: u32 = 1;
#[map]
static FIREWALL_RULE_MAP: LpmTrie<u32, u32>
= LpmTrie::with_max_entries(256, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

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
    info!(&ctx, "enter TC");
    let eth_hdr = ctx.load::<EthHdr>(0).map_err(|_| TC_ACT_OK)?;
    // only support ipv4
    if eth_hdr.ether_type()? != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }
    let ipv4hdr = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| TC_ACT_OK)?;
    let src_addr = ipv4hdr.src_addr();
    let dst_addr = ipv4hdr.dst_addr();
    // only for VIP
    if dst_addr != VIP{
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

    let client_ip_port = IpPort{ip: src_addr, port: src_port};
    let backend = match unsafe { BACKEND_MAP.get(&client_ip_port) } {
        None => {
            // new connection
            match BACKENDS.get(unsafe { BACKEND_INDEX }) {
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

    unsafe { BACKEND_INDEX = (BACKEND_INDEX + 1) % BACKEND_NUMBER; }

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
    // Ok(unsafe { bpf_redirect(59, 0) as i32 })
    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

