use anyhow::Context as _;
use aya::maps::lpm_trie::{LpmTrie, Key};
use std::net::Ipv4Addr;
use std::sync::Arc;
use axum::extract::State;
use aya::maps::{MapData};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use egui::mutex::Mutex;
#[rustfmt::skip]
use log::{debug, warn};
use serde::Deserialize;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[derive(Debug, Deserialize)]
struct RuleReq {
    src: String,
    prefix_len: u32,
    action: u32,
}
type RuleMap = LpmTrie<MapData, u32, u32>;

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

    let rule_map:RuleMap = LpmTrie::try_from(ebpf.take_map("FIREWALL_RULE_MAP").unwrap())?;

    let state = Arc::new(Mutex::new(rule_map));

    let app = axum::Router::new()
        .route("/rules/drop/add", axum::routing::post(add_drop_rule)).with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    log::info!("HTTP server listening on 8000");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn add_drop_rule(State(state): State<Arc<Mutex<RuleMap>>
                       >,
                       axum::Json(req): axum::Json<RuleReq>,)
                       -> Result<axum::http::StatusCode, (axum::http::StatusCode, String)>
{
    let ip: Ipv4Addr = req
        .src
        .parse()
        .map_err(|_| (axum::http::StatusCode::BAD_REQUEST, "bad src ip".to_string()))?;

    if req.prefix_len > 32 {
        return Err((axum::http::StatusCode::BAD_REQUEST, "prefix_len > 32".to_string()));
    }

    let key = Key::new(req.prefix_len as u32, u32::from(ip).to_be());
    state.lock()
        .insert(&key, req.action, 0)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("map insert: {}", e)))?;

    log::info!("rule added: {}/{} -> {}", req.src, req.prefix_len, req.action);
    Ok(axum::http::StatusCode::CREATED)
}