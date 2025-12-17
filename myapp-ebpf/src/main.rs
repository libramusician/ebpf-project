#![no_std]
#![no_main]
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use core::net::Ipv4Addr;
use aya_ebpf::cty::c_long;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{LpmTrie, Array, HashMap, LruHashMap};
use aya_ebpf::maps::lpm_trie::Key;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
    // vxlan::VxlanHdr,
    // geneve::GeneveHdr
};
use network_types::arp::ArpHdr;

static VIP: Ipv4Addr =  Ipv4Addr::new(192, 168, 1, 100);
static IIP: Ipv4Addr =  Ipv4Addr::new(172, 18, 0, 1);
static V_PORT: u16 = 80u16;

// keep track of unused ports, assume never conflict.
static SOCKET_COUNT: u16 = 20000;
static COUNT: u8 = 0u8;

#[repr(C)]
#[derive(Clone, Copy)]
struct IpPort {
    ip:  Ipv4Addr,
    port: u16,
}


// client address to LB internal address
#[map]
static INGRESS_MAP: LruHashMap<IpPort,IpPort> = LruHashMap::with_max_entries(10, 0);
// LB internal address to client address
#[map]
static EGRESS_MAP: LruHashMap<IpPort,IpPort> = LruHashMap::with_max_entries(10, 0);
// LB internal address to backend
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
static mut BACKEND_NUMBER: u32 = 2;
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
pub fn myapp(ctx: XdpContext) -> u32 {
    match try_myapp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_myapp(ctx: XdpContext) -> Result<u32, ()> {
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

            // ingress packet
            if dst_addr == VIP && dst_port == V_PORT {
                let client_ip_port = IpPort{
                    ip: source_addr,
                    port: source_port,
                };
                unsafe {
                    match INGRESS_MAP.get(&client_ip_port) {
                        // new connection
                        None => {
                            // allocate a port
                            let p = SOCKET_COUNT+1;
                            let internal_ip_port = IpPort {
                                ip: IIP,
                                port: p,
                            };
                            // bidirectional mapping
                            match INGRESS_MAP.insert(&client_ip_port, &internal_ip_port, 0) {
                                Ok(_) => {}
                                Err(_) => {}
                            };
                            match EGRESS_MAP.insert(&internal_ip_port, &client_ip_port, 0) {
                                Ok(_) => {}
                                Err(_) => {}
                            };
                            // allocated a backend
                            let default_ip_port = IpPortMAC{ip: Ipv4Addr::new(127,0,0,1), port: 80, mac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]};
                            let backend = BACKENDS.get(BACKEND_INDEX).unwrap_or(&default_ip_port);
                            BACKEND_INDEX = (BACKEND_INDEX + 1) % BACKEND_NUMBER;
                            match BACKEND_MAP.insert(&internal_ip_port, backend, 0) {
                                Ok(_) => {}
                                Err(_) => {}
                            }
                            do_nat_and_recalculate_csum(&ctx, eth_hdr, ipv4hdr, &internal_ip_port, backend)?;
                            info!(&ctx,"backendMAC {}:{}:{}:{}:{}:{}",
                            backend.mac[0], backend.mac[1], backend.mac[2],
                                backend.mac[3], backend.mac[4], backend.mac[5]);

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
                                _ => {(0u16,0u16)}
                            };
                            info!(&ctx, "new: SRC IP: {:i}, DST IP: {:i}, SRC PORT: {}, DST PORT: {}",
                            source_addr, dst_addr, source_port, dst_port);
                            return Ok(xdp_action::XDP_TX);
                        }
                        // exist connection
                        Some(internal_ip_port) => {
                            match BACKEND_MAP.get(&internal_ip_port) {
                                None => {}
                                Some(backend) => {
                                    do_nat_and_recalculate_csum(&ctx, eth_hdr, ipv4hdr, internal_ip_port, backend)?;
                                    info!(&ctx,"backendMAC {}:{}:{}:{}:{}:{}",
                            backend.mac[0], backend.mac[1], backend.mac[2],
                                backend.mac[3], backend.mac[4], backend.mac[5]);}
                            };
                            return Ok(xdp_action::XDP_TX);
                        }
                    }
                }
            }


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

/// do a nat on a packet, put new src ip port and new dst ip port mac in packet,
/// only for tcp and udp
fn do_nat_and_recalculate_csum(ctx: &XdpContext, eth_hdr: *mut EthHdr, ipv4hdr: *mut Ipv4Hdr, src_ip_port: &IpPort,
          dst_ip_port_mac: &IpPortMAC) -> Result<(), ()> {
    // NAT
    unsafe {
        (*ipv4hdr).src_addr = src_ip_port.ip.to_bits().to_be_bytes();
        (*ipv4hdr).dst_addr = dst_ip_port_mac.ip.to_bits().to_be_bytes();
        (*eth_hdr).dst_addr = dst_ip_port_mac.mac;

        match (*ipv4hdr).proto {
            IpProto::Tcp => {
                let tcp_hdr: *mut TcpHdr =
                    unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                (*tcp_hdr).source = src_ip_port.port.to_be_bytes();
                (*tcp_hdr).dest = dst_ip_port_mac.port.to_be_bytes();
            }
            IpProto::Udp => {
                let udp_hdr: *mut UdpHdr =
                    unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                (*udp_hdr).src = src_ip_port.port.to_be_bytes();
                (*udp_hdr).dst = dst_ip_port_mac.port.to_be_bytes();
            }
            _ => {}
        }

    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
