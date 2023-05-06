use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use byteorder::{ByteOrder, NetworkEndian as NE};
use ipnet::Ipv6Net;
use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_netlinkd::error::Result;
use rsdsl_netlinkd::{addr, link, route};
use serde::{Deserialize, Serialize};
use socket2::{Socket, Type};
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

fn tun2he(tun: Arc<Iface>) -> Result<()> {
    let local = Ipv4Addr::new(10, 128, 10, 237);
    let remote = Ipv4Addr::new(10, 128, 10, 185);

    let mut sock = Socket::new(
        libc::AF_PACKET.into(),
        Type::DGRAM,
        Some(((libc::ETH_P_IPV6 as u16).to_be() as i32).into()),
    )?;

    let mut buf = [0; 4 + 1492];
    loop {
        let n = match tun.recv(&mut buf[20..]) {
            Ok(v) => v,
            Err(e) => {
                println!("[6in4] tun2he warning: {}", e);
                continue;
            }
        };
        let buf = &mut buf[..20 + n];

        let ether_type = NE::read_u16(&buf[22..24]);
        if ether_type != libc::ETH_P_IPV6 as u16 {
            println!(
                "[6in4] drop outbound non-ipv6 pkt, ethertype: 0x{:04x}",
                ether_type
            );
            continue;
        }

        // Construct IP(v4) header.
        buf[4] = 0b01000101; // Version = 4, IHL = 5
        buf[5] = 0; // DSCP / ECP = 0
        NE::write_u16(&mut buf[6..8], (n - 4 + 20) as u16); // Size = dynamic
        NE::write_u16(&mut buf[8..10], 0); // ID = 0
        buf[10] = 0b01000000; // Flags = DF, Fragment Offset = 0...
        buf[11] = 0; // Fragment Offset = ...0
        buf[12] = 64; // TTL = 64
        buf[13] = 41; // Protocol = 41 (6in4)
        NE::write_u16(&mut buf[14..16], 0); // Checksum = 0 (computed later)
        buf[16..20].copy_from_slice(&local.octets()); // Source IP Address = dynamic
        buf[20..24].copy_from_slice(&remote.octets()); // Destination IP Address = HE

        let mut sum = 0i32;
        for i in 0..10 {
            let j = 4 + (i * 2);
            sum += NE::read_u16(&buf[j..2 + j]) as i32;
        }

        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        NE::write_u16(&mut buf[14..16], !(sum as u16));

        match sock.write(&buf[4..]) {
            Ok(sent) if sent != buf[4..].len() => println!(
                "[6in4] tun2he warning: partial transmission ({} < {})",
                sent,
                buf[4..].len()
            ),
            Ok(_) => {}
            Err(e) => println!("[6in4] tun2he warning: {}", e),
        }
    }
}

fn he2tun(tun: Arc<Iface>) -> Result<()> {
    let mut sock = Socket::new(
        libc::AF_PACKET.into(),
        Type::DGRAM,
        Some(((libc::ETH_P_IP as u16).to_be() as i32).into()),
    )?;

    let mut buf = [0; 4 + 1500];
    NE::write_u16(&mut buf[2..4], libc::ETH_P_IPV6 as u16);

    loop {
        let n = match sock.read(&mut buf[4..]) {
            Ok(v) => v,
            Err(e) => {
                println!("[6in4] he2tun warning: {}", e);
                continue;
            }
        };
        let buf = &mut buf[..4 + n];

        // Only process 6in4.
        if buf[13] != 41 {
            continue;
        }

        NE::write_u16(&mut buf[22..24], libc::ETH_P_IPV6 as u16);
        match tun.send(&buf[20..]) {
            Ok(sent) if sent != buf.len() - 20 => println!(
                "[6in4] he2tun warning: partial transmission ({} < {})",
                sent,
                buf.len() - 20
            ),
            Ok(_) => {}
            Err(e) => println!("[6in4] he2tun warning: {}", e),
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

    let tun = Arc::new(Iface::new("he6in4", Mode::Tun)?);
    let tun2 = tun.clone();

    configure_tunnel(&config);

    thread::spawn(move || match tun2he(tun2) {
        Ok(_) => {}
        Err(e) => panic!("tun2he error: {}", e),
    });

    thread::spawn(move || match he2tun(tun) {
        Ok(_) => {}
        Err(e) => panic!("he2tun error: {}", e),
    });

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
