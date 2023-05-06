use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::thread;
use std::time::Duration;

use ipnet::Ipv6Net;
use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_netlinkd::error::Result;
use rsdsl_netlinkd::{addr, link, route};
use serde::{Deserialize, Serialize};
use tun_tap::{Iface, Mode};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    pub serv: Ipv4Addr,
    pub tn64: Ipv6Addr,
    pub rt64: Ipv6Addr,
    pub rt48: Ipv6Addr,
}

#[derive(Clone, Debug)]
struct UsableConfig {
    pub serv: Ipv4Addr,
    pub tn64: Ipv6Net,
    pub rt64: Ipv6Net,
    pub rt48: Ipv6Net,
}

impl From<Config> for UsableConfig {
    fn from(config: Config) -> Self {
        Self {
            serv: config.serv,
            tn64: Ipv6Net::new(config.tn64, 64).unwrap(),
            rt64: Ipv6Net::new(config.rt64, 64).unwrap(),
            rt48: Ipv6Net::new(config.rt48, 48).unwrap(),
        }
    }
}

fn main() -> Result<()> {
    let mut file = File::open("/data/he6in4.conf")?;
    let config: Config = serde_json::from_reader(&mut file)?;
    let config: UsableConfig = config.into();

    let ip_config = Path::new(rsdsl_ip_config::LOCATION);
    while !ip_config.exists() {
        println!("[6in4] wait for pppoe");
        thread::sleep(Duration::from_secs(8));
    }

    let tun = Iface::new("he6in4", Mode::Tun)?;

    configure_tunnel(&config);

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) => match event.kind {
            EventKind::Create(kind) if kind == CreateKind::File => {
                // configure_tunnel(&config);
            }
            EventKind::Modify(kind) if matches!(kind, ModifyKind::Data(_)) => {
                // configure_tunnel(&config);
            }
            _ => {}
        },
        Err(e) => println!("[6in4] watch error: {:?}", e),
    })?;

    watcher.watch(ip_config, RecursiveMode::NonRecursive)?;

    loop {
        thread::sleep(Duration::MAX)
    }
}

fn configure_tunnel(config: &UsableConfig) {
    match configure_he6in4(config) {
        Ok(_) => {
            println!("[6in4] configure he6in4 ({})", config.serv);
            println!("[6in4] tunnel /64: {}", config.tn64);
            println!("[6in4] routed /64: {}", config.rt64);
            println!("[6in4] routed /48: {}", config.rt48);
        }
        Err(e) => println!("[6in4] can't configure he6in4: {:?}", e),
    }
}

fn configure_he6in4(config: &UsableConfig) -> Result<()> {
    let local_v6: Ipv6Addr = (u128::from_be_bytes(config.tn64.trunc().addr().octets()) | 2).into();
    let remote_v6: Ipv6Addr = (u128::from_be_bytes(config.tn64.trunc().addr().octets()) | 1).into();

    link::set_mtu("he6in4".into(), 1472)?;
    link::up("he6in4".into())?;

    addr::flush("he6in4".into())?;
    addr::add("he6in4".into(), local_v6.into(), 64)?;

    route::add6(Ipv6Addr::UNSPECIFIED, 0, Some(remote_v6), "he6in4".into())?;

    Ok(())
}
