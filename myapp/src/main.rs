use anyhow::Context as _;
use aya::maps::lpm_trie::{LpmTrie, Key};
use std::net::Ipv4Addr;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/myapp"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            println!("aya-log init ok");
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("myapp").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut rule_map:LpmTrie<_, u32,u32> = LpmTrie::try_from(ebpf.map_mut("FIREWALL_RULE_MAP").unwrap())?;
    // let ipaddr = Ipv4Addr::new(192, 168, 1, 0);
    // let key = Key::new(24, u32::from(ipaddr).to_be());
    // rule_map.insert(&key, 1, 0)?;

    let mut src_addr_text = "".to_owned();
    let mut action_text = "".to_owned();
    let mut src_addr_prefix_length = "".to_owned();



    let options = eframe::NativeOptions::default();
    eframe::run_simple_native("Packet Rule App", options, move |ctx, _frame| {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("packet rules");
            ui.horizontal(|ui| {
                let src_addr_label = ui.label("source address");
                ui.text_edit_singleline(&mut src_addr_text)
                    .labelled_by(src_addr_label.id);
                let src_addr_prefix_label = ui.label("prefix_length");
                ui.text_edit_singleline(&mut src_addr_prefix_length)
                    .labelled_by(src_addr_prefix_label.id);
                let action_label = ui.label("action");
                ui.text_edit_singleline(&mut action_text)
                    .labelled_by(action_label.id);
                let add_button = ui.button("add");
                if add_button.clicked() {
                    println!("{}, {}", &src_addr_text, &action_text);
                    let src_addr = src_addr_text.parse::<Ipv4Addr>()
                        .expect("invalid source address");
                }
            });
        });
    }).expect("TODO: panic message");

    // let ctrl_c = signal::ctrl_c();
    // println!("Waiting for Ctrl-C...");
    // ctrl_c.await?;
    // println!("Exiting...");
    //
    Ok(())
}
