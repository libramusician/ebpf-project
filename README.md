#### important
cargo generate https://github.com/aya-rs/aya-template.git
set RUST_LOG=info

RUST_LOG=info cargo run  --config 'target."cfg(all())".runner="sudo -E"'
RUST_LOG=info sudo -E target/debug/myapp --iface eth0
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1

no panic
no % operation
config array:
0-5: LB MAC
6: NUMBER_OF_BACKENDS
7: DOCKER_BR_INDEX
8: VIP u32