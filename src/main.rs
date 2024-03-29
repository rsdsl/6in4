use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::path::Path;
use std::thread;
use std::time::Duration;

use byteorder::{ByteOrder, NetworkEndian as NE};
use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_he_config::{Config, UsableConfig};
use rsdsl_ip_config::DsConfig;
use rsdsl_netlinkd::{addr, link, route};
use rsdsl_netlinkd_sys::Sit;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("notify: {0}")]
    Notify(#[from] notify::Error),
    #[error("reqwest: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("rsdsl_netlinkd: {0}")]
    RsdslNetlinkd(#[from] rsdsl_netlinkd::error::Error),
    #[error("rsdsl_netlinkd_sys: {0}")]
    RsdslNetlinkdSys(#[from] rsdsl_netlinkd_sys::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let mut file = File::open("/data/he6in4.conf")?;
    let config: Config = serde_json::from_reader(&mut file)?;
    let config: UsableConfig = config.into();

    let ds_config = Path::new(rsdsl_ip_config::LOCATION);
    while !ds_config.exists() {
        println!("wait for pppoe");
        thread::sleep(Duration::from_secs(8));
    }

    let mut tnl = None;

    configure_lan(&config);
    configure_vlans(&config);

    let do_setup = |tnl: &mut Option<Sit>, config: &UsableConfig| -> Result<()> {
        *tnl = None;

        let mut file = File::open(rsdsl_ip_config::LOCATION)?;
        let dsconfig: DsConfig = serde_json::from_reader(&mut file)?;

        if let Some(ref v4) = dsconfig.v4 {
            let local = v4.addr;
            let remote = config.serv;
            *tnl = Some(Sit::new("he6in4", "ppp0", local, remote)?);

            configure_endpoint(config);
            configure_tunnel(config, &dsconfig);
        } else {
            println!("no native ipv4");
        }

        Ok(())
    };
    let setup = move |tnl: &mut Option<Sit>, config: &UsableConfig| match do_setup(tnl, config) {
        Ok(_) => {}
        Err(e) => println!("can't create he6in4: {}", e),
    };

    setup(&mut tnl, &config);

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) => match event.kind {
            EventKind::Create(kind) if kind == CreateKind::File => setup(&mut tnl, &config),
            EventKind::Modify(kind) if matches!(kind, ModifyKind::Data(_)) => {
                setup(&mut tnl, &config)
            }
            _ => {}
        },
        Err(e) => println!("watch error: {:?}", e),
    })?;

    watcher.watch(ds_config, RecursiveMode::NonRecursive)?;

    loop {
        thread::sleep(Duration::MAX)
    }
}

fn configure_endpoint(config: &UsableConfig) {
    match configure_local(config) {
        Ok(_) => println!("update local endpoint"),
        Err(e) => println!("can't update local endpoint: {:?}", e),
    }
}

fn configure_local(config: &UsableConfig) -> Result<()> {
    for i in 0..3 {
        match reqwest::blocking::Client::builder()
            .resolve(
                "ipv4.tunnelbroker.net",
                SocketAddrV4::new(Ipv4Addr::new(64, 62, 200, 2), 443).into(),
            )
            .build()?
            .get(&config.updt)
            .send()
        {
            Ok(v) => {
                v.error_for_status()?;
                break;
            }
            Err(e) => {
                if i == 2 {
                    return Err(e.into());
                }

                thread::sleep(Duration::from_secs(8));
            }
        }
    }

    Ok(())
}

fn configure_tunnel(config: &UsableConfig, dsconfig: &DsConfig) {
    match configure_he6in4(config, dsconfig) {
        Ok(_) => {
            println!("configure he6in4 ({})", config.serv);
            println!("tunnel /64: {}", config.tn64);
            println!("routed /64: {}", config.rt64);
            println!("routed /48: {}", config.rt48);
        }
        Err(e) => println!("can't configure he6in4: {:?}", e),
    }
}

fn configure_he6in4(config: &UsableConfig, dsconfig: &DsConfig) -> Result<()> {
    let local_v6: Ipv6Addr = (u128::from_be_bytes(config.tn64.trunc().addr().octets()) | 2).into();
    let remote_v6: Ipv6Addr = (u128::from_be_bytes(config.tn64.trunc().addr().octets()) | 1).into();

    link::up("he6in4".into())?;

    addr::flush("he6in4".into())?;
    addr::add("he6in4".into(), local_v6.into(), 64)?;

    // Check for native connectivity to avoid breaking netlinkd.
    if dsconfig.v6.is_none() {
        route::add6(Ipv6Addr::UNSPECIFIED, 0, Some(remote_v6), "he6in4".into())?;
    }

    Ok(())
}

fn configure_lan(config: &UsableConfig) {
    match configure_eth0(config) {
        Ok(_) => {}
        Err(e) => println!("can't configure eth0: {:?}", e),
    }
}

fn configure_eth0(config: &UsableConfig) -> Result<()> {
    let addr_dbg: Ipv6Addr = (u128::from_be_bytes(config.rt64.trunc().addr().octets()) | 1).into();
    let addr: Ipv6Addr = (u128::from_be_bytes(config.rt48.trunc().addr().octets()) | 1).into();

    println!("wait for eth0");
    link::wait_exists("eth0".into())?;

    fs::write("/proc/sys/net/ipv6/conf/eth0/accept_ra", "0")?;

    addr::add("eth0".into(), addr_dbg.into(), 64)?;
    addr::add("eth0".into(), addr.into(), 64)?;

    println!("configure eth0 ({}/64, dbg {}/64)", addr, addr_dbg);
    Ok(())
}

fn configure_vlans(config: &UsableConfig) {
    match configure_eth0_vlans(config) {
        Ok(_) => {}
        Err(e) => println!("can't configure vlans: {:?}", e),
    }
}

fn configure_eth0_vlans(config: &UsableConfig) -> Result<()> {
    let zones = ["trusted", "untrusted", "isolated", "exposed"];

    for (i, zone) in zones.iter().enumerate() {
        let vlan_id = 10 * (i + 1);
        let vlan_name = format!("eth0.{}", vlan_id);

        let mut octets = config.rt48.trunc().addr().octets();
        NE::write_u16(&mut octets[6..8], vlan_id as u16);

        let vlan_addr = Ipv6Addr::from(u128::from_be_bytes(octets) | 1);

        println!("wait for {}", vlan_name);
        link::wait_exists(vlan_name.clone())?;

        fs::write(
            format!("/proc/sys/net/ipv6/conf/{}/accept_ra", vlan_name),
            "0",
        )?;

        addr::add(vlan_name.clone(), vlan_addr.into(), 64)?;

        println!("configure {} ({}/64) zone {}", vlan_name, vlan_addr, zone);
    }

    Ok(())
}
