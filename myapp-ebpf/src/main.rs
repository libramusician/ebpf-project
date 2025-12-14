#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use core::net::IpAddr;
use aya_ebpf::macros::map;
use aya_ebpf::maps::LpmTrie;
use aya_ebpf::maps::lpm_trie::Key;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
    // vxlan::VxlanHdr,
    // geneve::GeneveHdr
};

#[map]
static FIREWALL_RULE_MAP: LpmTrie<u32, u32>
= LpmTrie::with_max_entries(256, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn myapp(ctx: XdpContext) -> u32 {
    match try_myapp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_myapp(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *eth_hdr }.ether_type() {
        Ok(EtherType::Ipv4) => {

            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv4hdr).src_addr() };
            let dst_addr = unsafe { (*ipv4hdr).dst_addr() };
            let source_port = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcp_hdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    u16::from_be_bytes(unsafe { (*tcp_hdr).source })
                }
                IpProto::Udp => {
                    let udp_hdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    unsafe { (*udp_hdr).src_port() }
                }
                IpProto::Icmp => {0}
                _ => return Ok(xdp_action::XDP_PASS),
            };
            let dst_port = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcp_hdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    u16::from_be_bytes(unsafe { (*tcp_hdr).dest })
                }
                IpProto::Udp => {
                    let udp_hdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    unsafe { (*udp_hdr).dst_port() }
                }
                IpProto::Icmp => {0}
                _ => return Ok(xdp_action::XDP_PASS),
            };

            info!(&ctx, "SRC IP: {:i}, DST IP: {:i}, SRC PORT: {}, DST PORT: {}",
                source_addr, dst_addr, source_port, dst_port);
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
        // not IPV4
        _ => Ok(xdp_action::XDP_PASS)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
