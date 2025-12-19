use anyhow::Context as _;
use aya::maps::lpm_trie::{LpmTrie, Key};
use std::net::Ipv4Addr;
use std::sync::Arc;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use aya::maps::{Array, MapData};
use aya::Pod;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use clap::Parser;
use egui::mutex::Mutex;
#[rustfmt::skip]
use log::{debug, warn};
use serde::{Deserialize, Serialize};

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

#[repr(C)]
#[derive(Clone, Copy)]
struct IpPortMAC {
    ip:  Ipv4Addr,
    port: u16,
    mac: [u8; 6],
}

unsafe impl Pod for IpPortMAC {}

#[derive(Serialize)]
struct RuleDto {
    src: String,          // "192.168.1.0"
    prefix_len: u32,      // 24
    action: u32,          // 0/1
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
    let xdp_program: &mut Xdp = ebpf.program_mut("my_xdp_app").unwrap().try_into()?;
    xdp_program.load()?;
    xdp_program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    let _ = tc::qdisc_add_clsact(&iface);
    let ingress_program: &mut SchedClassifier = ebpf.program_mut("my_ingress_app").unwrap().try_into()?;
    ingress_program.load()?;
    ingress_program.attach(&iface, TcAttachType::Ingress)?;

    let rule_map:RuleMap = LpmTrie::try_from(ebpf.take_map("FIREWALL_RULE_MAP").unwrap())?;

    let mut backends: Array<_, IpPortMAC> = Array::try_from(ebpf.take_map("BACKENDS").unwrap())?;
    let backend1 = IpPortMAC{ip: Ipv4Addr::new(192,168,3,101), port: 80, mac: [0x00,0x15,0x5d,0x01,0x6a,0x0c]};
    // let backend2 = IpPortMAC{ip: Ipv4Addr::new(172,18,0,4), port: 80, mac: [0x1a,0x74,0x61,0x49,0x78,0x7c]};
    // let backend1 = IpPortMAC{ip: Ipv4Addr::new(192,168,3,101), port: 80, mac: [0x00,0x15,0x5d,0x01,0x6a,0x04]};
    backends.set(0, &backend1, 0)?;
    // backends.set(1, &backend2, 0);

    let state = Arc::new(Mutex::new(rule_map));

    let app = axum::Router::new()
        .route("/rules/drop/add", axum::routing::post(add_drop_rule))
        .route("/rules/drop/list", axum::routing::get(list_drop_rule))
        .route("/rules/drop/delete", axum::routing::delete(delete_drop_rule))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    log::info!("HTTP server listening on 8000");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn add_drop_rule(State(state): State<Arc<Mutex<RuleMap>>
                       >,
                       Json(req): Json<RuleReq>,)
                       -> Result<StatusCode, (StatusCode, String)>
{
    let ip: Ipv4Addr = req
        .src
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad src ip".to_string()))?;

    if req.prefix_len > 32 {
        return Err((StatusCode::BAD_REQUEST, "prefix_len > 32".to_string()));
    }

    let key = Key::new(req.prefix_len, u32::from(ip).to_be());
    state.lock()
        .insert(&key, req.action, 0)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("map insert: {}", e)))?;

    log::info!("rule added: {}/{} -> {}", req.src, req.prefix_len, req.action);
    Ok(StatusCode::CREATED)
}

async fn list_drop_rule(
    State(state): State<Arc<Mutex<RuleMap>>>,
) -> Result<(StatusCode, Json<Vec<RuleDto>>), (StatusCode, String)> {
    let mut rules = Vec::new();
    let map = state.lock();
    for r in map.keys() {
        match r {
            Ok(key) => {
                rules.push(RuleDto{
                    src: Ipv4Addr::from(key.data().to_be()).to_string(),
                    prefix_len: key.prefix_len(),
                    action: map.get(&key, 0).unwrap()
                })
            }
            Err(e) => {
                eprintln!("failed to get key: {e}");
            }
        }
    }
    Ok((StatusCode::OK, Json(rules)))
}

async fn delete_drop_rule(State(state): State<Arc<Mutex<RuleMap>>
>,
                       Json(req): Json<RuleReq>,)
                       -> Result<StatusCode, (StatusCode, String)>
{
    let ip: Ipv4Addr = req
        .src
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad src ip".to_string()))?;

    if req.prefix_len > 32 {
        return Err((StatusCode::BAD_REQUEST, "prefix_len > 32".to_string()));
    }

    let key = Key::new(req.prefix_len, u32::from(ip).to_be());
    state.lock()
        .remove(&key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("map insert: {}", e)))?;

    log::info!("rule deleted: {}/{} -> {}", req.src, req.prefix_len, req.action);
    Ok(StatusCode::OK)
}