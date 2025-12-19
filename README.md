#### important
cargo generate https://github.com/aya-rs/aya-template.git
set RUST_LOG=info

RUST_LOG=info cargo run  --config 'target."cfg(all())".runner="sudo -E"'
RUST_LOG=info sudo -E target/debug/myapp --iface eth0
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1

no panic