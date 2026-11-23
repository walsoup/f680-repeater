// udhcpc.rs - minimal standalone DHCP client for the F680 repeater.
//
// Build (soft-float static ARMv7 musl):
//   rustc --target armv7-unknown-linux-musleabi \
//     -C linker=<rust-lld> -C linker-flavor=ld.lld \
//     -C opt-level=z -C panic=abort --edition 2021 udhcpc.rs -o udhcpc
//
// BusyBox udhcpc-compatible subset:
//   -i IFACE -s SCRIPT -n -q -f
// Script gets $1 = bound|renew and env: interface ip subnet router dns
// broadcast lease serverid. It is invoked as /bin/sh SCRIPT STATE.

use std::convert::TryInto;
use std::env;
use std::ffi::{c_void, CString};
use std::fs::File;
use std::io::{self, Read};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAGIC: [u8; 4] = [99, 130, 83, 99];
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;

const SOL_SOCKET: i32 = 1;
const SO_BINDTODEVICE: i32 = 25;

extern "C" {
    fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const c_void, optlen: u32) -> i32;
}

#[derive(Clone, Default)]
struct Lease {
    ip: Option<Ipv4Addr>,
    subnet: Option<Ipv4Addr>,
    router: Vec<Ipv4Addr>,
    dns: Vec<Ipv4Addr>,
    broadcast: Option<Ipv4Addr>,
    lease: Option<u32>,
    server: Option<Ipv4Addr>,
}

struct Cfg {
    iface: String,
    script: Option<String>,
    one_shot: bool,
    no_lease_exit: bool,
    bind_port: u16,
    server_port: u16,
    server_ip: Ipv4Addr,
    bind_device: bool,
    tries: u32,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            iface: "apcli0".to_string(),
            script: None,
            one_shot: false,
            no_lease_exit: false,
            bind_port: 68,
            server_port: 67,
            server_ip: Ipv4Addr::new(255, 255, 255, 255),
            bind_device: true,
            tries: 4,
        }
    }
}

fn usage() {
    eprintln!("usage: udhcpc -i IFACE [-s SCRIPT] [-n] [-q] [-f] [--bind-port N] [--server-port N] [--server-ip IP] [--no-bind-device]");
}

fn parse_args() -> Cfg {
    let mut c = Cfg::default();
    let a: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "-i" => {
                i += 1;
                if i < a.len() { c.iface = a[i].clone(); }
            }
            "-s" => {
                i += 1;
                if i < a.len() { c.script = Some(a[i].clone()); }
            }
            "-n" => c.no_lease_exit = true,
            "-q" => c.one_shot = true,
            "-f" => {}
            "-t" => {
                i += 1;
                if i < a.len() { c.tries = a[i].parse().unwrap_or(4); }
            }
            "--bind-port" => {
                i += 1;
                if i < a.len() { c.bind_port = a[i].parse().unwrap_or(68); }
            }
            "--server-port" => {
                i += 1;
                if i < a.len() { c.server_port = a[i].parse().unwrap_or(67); }
            }
            "--server-ip" => {
                i += 1;
                if i < a.len() { c.server_ip = a[i].parse().unwrap_or(Ipv4Addr::new(255,255,255,255)); }
            }
            "--no-bind-device" => c.bind_device = false,
            "-h" | "--help" => { usage(); std::process::exit(0); }
            _ => {}
        }
        i += 1;
    }
    c
}

fn read_mac(iface: &str) -> Option<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface)).ok()?;
    let mut m = [0u8; 6];
    for (i, p) in s.trim().split(':').enumerate() {
        if i >= 6 { break; }
        m[i] = u8::from_str_radix(p, 16).ok()?;
    }
    if m.iter().all(|x| *x == 0) { None } else { Some(m) }
}

fn make_xid() -> u32 {
    let mut b = [0u8; 4];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
    u32::from_le_bytes(b) ^ t ^ std::process::id()
}

fn opt(v: &mut Vec<u8>, code: u8, data: &[u8]) {
    v.push(code);
    v.push(data.len() as u8);
    v.extend_from_slice(data);
}

fn build(xid: u32, mac: [u8; 6], msg: u8, req: Option<Ipv4Addr>, server: Option<Ipv4Addr>) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 1;          // BOOTREQUEST
    p[1] = 1;          // Ethernet
    p[2] = 6;          // hlen
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast reply
    p[28..34].copy_from_slice(&mac);
    let mut o = Vec::new();
    opt(&mut o, 53, &[msg]);
    let mut cid = vec![1u8];
    cid.extend_from_slice(&mac);
    opt(&mut o, 61, &cid); // client identifier
    opt(&mut o, 55, &[1, 3, 6, 15, 28, 51, 54]); // param request list
    if let Some(ip) = req { opt(&mut o, 50, &ip.octets()); }
    if let Some(ip) = server { opt(&mut o, 54, &ip.octets()); }
    o.push(255);
    p[236..240].copy_from_slice(&MAGIC);
    p.extend_from_slice(&o);
    p
}

fn parse(buf: &[u8], xid: u32, mac: [u8; 6]) -> Option<(u8, Lease)> {
    if buf.len() < 240 || buf[0] != 2 { return None; }
    if u32::from_be_bytes(buf[4..8].try_into().ok()?) != xid { return None; }
    if buf[28..34] != mac { return None; }
    if buf[236..240] != MAGIC { return None; }
    let mut l = Lease::default();
    l.ip = Some(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
    let mut msg = 0u8;
    let mut i = 240usize;
    while i + 1 < buf.len() {
        let c = buf[i];
        if c == 0 { i += 1; continue; }
        if c == 255 { break; }
        let len = buf[i + 1] as usize;
        if i + 2 + len > buf.len() { break; }
        let d = &buf[i + 2..i + 2 + len];
        match c {
            53 if len >= 1 => msg = d[0],
            1 if len >= 4 => l.subnet = Some(Ipv4Addr::new(d[0], d[1], d[2], d[3])),
            3 if len >= 4 => {
                let mut j = 0;
                while j + 4 <= len { l.router.push(Ipv4Addr::new(d[j], d[j+1], d[j+2], d[j+3])); j += 4; }
            }
            6 if len >= 4 => {
                let mut j = 0;
                while j + 4 <= len { l.dns.push(Ipv4Addr::new(d[j], d[j+1], d[j+2], d[j+3])); j += 4; }
            }
            28 if len >= 4 => l.broadcast = Some(Ipv4Addr::new(d[0], d[1], d[2], d[3])),
            51 if len >= 4 => l.lease = Some(u32::from_be_bytes(d[0..4].try_into().ok()?)),
            54 if len >= 4 => l.server = Some(Ipv4Addr::new(d[0], d[1], d[2], d[3])),
            _ => {}
        }
        i += 2 + len;
    }
    if l.broadcast.is_none() {
        if let (Some(ip), Some(mask)) = (l.ip, l.subnet) {
            l.broadcast = Some(Ipv4Addr::from(u32::from(ip) | !u32::from(mask)));
        }
    }
    Some((msg, l))
}

fn make_socket(cfg: &Cfg) -> io::Result<UdpSocket> {
    let s = UdpSocket::bind(("0.0.0.0", cfg.bind_port))?;
    s.set_broadcast(true)?;
    s.set_read_timeout(Some(Duration::from_secs(4)))?;
    if cfg.bind_device {
        let c = CString::new(cfg.iface.clone()).unwrap();
        let r = unsafe {
            setsockopt(s.as_raw_fd(), SOL_SOCKET, SO_BINDTODEVICE,
                       c.as_ptr() as *const c_void, (c.as_bytes().len() + 1) as u32)
        };
        if r != 0 {
            eprintln!("udhcpc: warn: SO_BINDTODEVICE({}): {}", cfg.iface, io::Error::last_os_error());
        }
    }
    Ok(s)
}

fn mask_prefix(m: Ipv4Addr) -> u8 {
    u32::from(m).count_ones() as u8
}

fn run_script(cfg: &Cfg, state: &str, l: &Lease) {
    let Some(ref script) = cfg.script else { return; };
    let routers: Vec<String> = l.router.iter().map(|x| x.to_string()).collect();
    let dns: Vec<String> = l.dns.iter().map(|x| x.to_string()).collect();
    let st = Command::new("/bin/sh")
        .arg(script)
        .arg(state)
        .env("interface", &cfg.iface)
        .env("ip", l.ip.map(|x| x.to_string()).unwrap_or_default())
        .env("subnet", l.subnet.map(|x| x.to_string()).unwrap_or_default())
        .env("prefix", l.subnet.map(|x| mask_prefix(x).to_string()).unwrap_or_default())
        .env("router", routers.first().cloned().unwrap_or_default())
        .env("dns", dns.join(" "))
        .env("broadcast", l.broadcast.map(|x| x.to_string()).unwrap_or_default())
        .env("lease", l.lease.unwrap_or(0).to_string())
        .env("serverid", l.server.map(|x| x.to_string()).unwrap_or_default())
        .status();
    match st {
        Ok(s) if s.success() => eprintln!("udhcpc: script {} {} ok", script, state),
        Ok(s) => eprintln!("udhcpc: script {} {} rc={:?}", script, state, s.code()),
        Err(e) => eprintln!("udhcpc: script {} {} error: {}", script, state, e),
    }
}

fn acquire(cfg: &Cfg, sock: &UdpSocket, mac: [u8; 6]) -> Option<Lease> {
    let xid = make_xid();
    let pkt = build(xid, mac, DISCOVER, None, None);
    let dst = (cfg.server_ip, cfg.server_port);
    for _ in 0..cfg.tries {
        if let Err(e) = sock.send_to(&pkt, dst) {
            eprintln!("udhcpc: send DISCOVER: {}", e);
            continue;
        }
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            let mut b = [0u8; 1500];
            let n = match sock.recv_from(&mut b) {
                Ok((n, _)) => n,
                Err(_) => break,
            };
            let Some((m, offer)) = parse(&b[..n], xid, mac) else { continue; };
            if m != OFFER { continue; }
            eprintln!("udhcpc: OFFER {:?} server {:?}", offer.ip, offer.server);
            let req = build(xid, mac, REQUEST, offer.ip, offer.server);
            if let Err(e) = sock.send_to(&req, dst) {
                eprintln!("udhcpc: send REQUEST: {}", e);
                continue;
            }
            let d2 = Instant::now() + Duration::from_secs(4);
            while Instant::now() < d2 {
                let mut b2 = [0u8; 1500];
                let n2 = match sock.recv_from(&mut b2) {
                    Ok((n2, _)) => n2,
                    Err(_) => break,
                };
                let Some((m2, ack)) = parse(&b2[..n2], xid, mac) else { continue; };
                if m2 == ACK {
                    eprintln!("udhcpc: ACK {:?} router {:?} dns {:?} lease {:?}",
                              ack.ip, ack.router, ack.dns, ack.lease);
                    return Some(ack);
                }
            }
        }
    }
    None
}

fn main() {
    let cfg = parse_args();
    let mac = match read_mac(&cfg.iface) {
        Some(m) => m,
        None => {
            eprintln!("udhcpc: cannot read MAC for {}", cfg.iface);
            std::process::exit(1);
        }
    };
    eprintln!("udhcpc: iface {} mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
              cfg.iface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    let sock = match make_socket(&cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("udhcpc: socket: {}", e);
            std::process::exit(1);
        }
    };
    loop {
        match acquire(&cfg, &sock, mac) {
            Some(l) => {
                run_script(&cfg, "bound", &l);
                if cfg.one_shot {
                    return;
                }
                let sleep = l.lease.unwrap_or(300).max(120) / 2;
                eprintln!("udhcpc: renew in {}s", sleep);
                thread::sleep(Duration::from_secs(sleep as u64));
            }
            None => {
                eprintln!("udhcpc: no lease");
                if cfg.no_lease_exit {
                    std::process::exit(1);
                }
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}
