use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{self, Read};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use byteorder::{ByteOrder, NetworkEndian as NE};
use ipnet::Ipv6Net;
use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_ip_config::IpConfig;
use rsdsl_netlinkd::error::Result;
use rsdsl_netlinkd::{addr, link, route};
use serde::{Deserialize, Serialize};
use socket2::{Socket, Type};
use thiserror::Error;
use tun_tap::{Iface, Mode};

#[derive(Debug, Error)]
enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("reqwest: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("rsdsl_netlinkd: {0}")]
    RsdslNetlinkd(#[from] rsdsl_netlinkd::error::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    pub serv: Ipv4Addr,
    pub tn64: Ipv6Addr,
    pub rt64: Ipv6Addr,
    pub rt48: Ipv6Addr,
    pub updt: String,
}

#[derive(Clone, Debug)]
struct UsableConfig {
    pub serv: Ipv4Addr,
    pub tn64: Ipv6Net,
    pub rt64: Ipv6Net,
    pub rt48: Ipv6Net,
    pub updt: String,
}

impl From<Config> for UsableConfig {
    fn from(config: Config) -> Self {
        Self {
            serv: config.serv,
            tn64: Ipv6Net::new(config.tn64, 64).unwrap(),
            rt64: Ipv6Net::new(config.rt64, 64).unwrap(),
            rt48: Ipv6Net::new(config.rt48, 48).unwrap(),
            updt: config.updt,
        }
    }
}

const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

fn send_to(ifi: i32, sock: &Socket, buf: &[u8]) -> io::Result<usize> {
    let mut sa = libc::sockaddr_ll {
        sll_family: (libc::AF_PACKET as u16).to_be(),
        sll_protocol: (libc::ETH_P_IP as u16).to_be(),
        sll_ifindex: ifi,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0x00; 8],
    };

    unsafe {
        match libc::sendto(
            sock.as_raw_fd(),
            buf as *const _ as *const c_void,
            mem::size_of_val(buf),
            0,
            &mut sa as *mut libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of_val(&sa) as u32,
        ) {
            n if n < 0 => Err(io::Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}

fn tun2he(tun: Arc<Iface>, local: Arc<Mutex<Ipv4Addr>>, remote: &Ipv4Addr) -> Result<()> {
    let ifi = link::index("rsppp0".into())? as i32;

    let sock = Socket::new(
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

        // Construct outer IPv4 header.
        buf[4] = 0b01000101; // Version = 4, IHL = 5
        buf[5] = 0; // DSCP / ECP = 0
        NE::write_u16(&mut buf[6..8], (n - 4 + 20) as u16); // Size = dynamic
        NE::write_u16(&mut buf[8..10], 0); // ID = 0
        buf[10] = 0b01000000; // Flags = DF, Fragment Offset = 0...
        buf[11] = 0; // Fragment Offset = ...0
        buf[12] = 64; // TTL = 64
        buf[13] = 41; // Protocol = 41 (6in4)
        NE::write_u16(&mut buf[14..16], 0); // Checksum = 0 (computed later)
        buf[16..20].copy_from_slice(&local.lock().unwrap().octets()); // Source IP Address = dynamic
        buf[20..24].copy_from_slice(&remote.octets()); // Destination IP Address = HE

        // Compute IPv4 header checksum.
        let mut sum = 0i32;
        for i in 0..10 {
            let j = 4 + (i * 2);
            sum += NE::read_u16(&buf[j..2 + j]) as i32;
        }

        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        NE::write_u16(&mut buf[14..16], !(sum as u16));

        match send_to(ifi, &sock, &buf[4..]) {
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

    let local = Arc::new(Mutex::new(Ipv4Addr::UNSPECIFIED));
    let local2 = local.clone();

    configure_endpoint(&config, local.clone());
    configure_tunnel(&config);
    configure_lan(&config);
    configure_vlans(&config);

    fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;

    thread::spawn(move || match tun2he(tun2, local.clone(), &config.serv) {
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
                configure_endpoint(&config, local2.clone());
            }
            EventKind::Modify(kind) if matches!(kind, ModifyKind::Data(_)) => {
                configure_endpoint(&config, local2.clone());
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

fn configure_endpoint(config: &UsableConfig, local: Arc<Mutex<Ipv4Addr>>) {
    match configure_local(config, local.clone()) {
        Ok(_) => println!("[6in4] update local endpoint {}", local.lock().unwrap()),
        Err(e) => println!("[6in4] can't update local endpoint: {:?}", e),
    }
}

fn configure_local(
    config: &UsableConfig,
    local: Arc<Mutex<Ipv4Addr>>,
) -> std::result::Result<(), Error> {
    let mut file = File::open(rsdsl_ip_config::LOCATION)?;
    let ip_config: IpConfig = serde_json::from_reader(&mut file)?;

    *local.lock().unwrap() = ip_config.addr;

    reqwest::blocking::get(&config.updt)?.error_for_status()?;

    Ok(())
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

fn configure_lan(config: &UsableConfig) {
    match configure_eth0(config) {
        Ok(_) => {}
        Err(e) => println!("[6in4] can't configure eth0: {:?}", e),
    }
}

fn configure_eth0(config: &UsableConfig) -> Result<()> {
    let addr_dbg: Ipv6Addr = (u128::from_be_bytes(config.rt64.trunc().addr().octets()) | 1).into();
    let addr: Ipv6Addr = (u128::from_be_bytes(config.rt48.trunc().addr().octets()) | 1).into();

    println!("[6in4] wait for eth0");
    link::wait_exists("eth0".into())?;

    fs::write("/proc/sys/net/ipv6/conf/eth0/accept_ra", "0")?;

    addr::add_link_local("eth0".into(), LINK_LOCAL.into(), 64)?;
    addr::add("eth0".into(), addr_dbg.into(), 64)?;
    addr::add("eth0".into(), addr.into(), 64)?;

    println!("[6in4] configure eth0 ({}/64, dbg {}/64)", addr, addr_dbg);
    Ok(())
}

fn configure_vlans(config: &UsableConfig) {
    match configure_eth0_vlans(config) {
        Ok(_) => {}
        Err(e) => println!("[6in4] can't configure vlans: {:?}", e),
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

        println!("[6in4] wait for {}", vlan_name);
        link::wait_exists(vlan_name.clone())?;

        fs::write(
            format!("/proc/sys/net/ipv6/conf/{}/accept_ra", vlan_name),
            "0",
        )?;

        addr::add_link_local(vlan_name.clone(), LINK_LOCAL.into(), 64)?;
        addr::add(vlan_name.clone(), vlan_addr.into(), 64)?;

        println!(
            "[6in4] configure {} ({}/64) zone {}",
            vlan_name, vlan_addr, zone
        );
    }

    Ok(())
}
