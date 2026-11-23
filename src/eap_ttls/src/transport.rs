//! transport.rs - AF_PACKET raw socket & mock socket transport for EAPOL frames.

use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const ETH_P_PAE: u16 = 0x888e;

pub trait EapolTransport {
    fn send_raw_frame(&mut self, frame: &[u8]) -> Result<(), String>;
    fn recv_raw_frame(&mut self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, String>;
    fn bssid(&self) -> [u8; 6];
    fn iface_mac(&self) -> [u8; 6];

    /// Build Ethernet II frame with EAPOL header and send.
    fn send_eapol(&mut self, eapol_type: u8, payload: &[u8]) -> Result<(), String> {
        let mut frame = Vec::with_capacity(14 + 4 + payload.len());
        // Ethernet II Header: Dest BSSID, Src IFACE, EtherType 0x888e
        frame.extend_from_slice(&self.bssid());
        frame.extend_from_slice(&self.iface_mac());
        frame.extend_from_slice(&ETH_P_PAE.to_be_bytes());

        // EAPOL Header: Version 1, Type, Length
        frame.push(1); // Version 1
        frame.push(eapol_type);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);

        self.send_raw_frame(&frame)
    }

    /// Send EAPOL-Start (Version 1, Type 1, Length 0)
    fn send_eapol_start(&mut self) -> Result<(), String> {
        self.send_eapol(1, &[])
    }

    /// Send EAP packet (EAPOL Type 0)
    fn send_eap_packet(&mut self, eap_data: &[u8]) -> Result<(), String> {
        self.send_eapol(0, eap_data)
    }

    /// Receive and filter incoming EAPOL frame.
    /// Returns extracted EAP packet bytes if valid.
    /// Ignores frames where src != bssid or EAPOL type != 0 (e.g. Type 3 EAPOL-Key).
    /// Strictly slices payload using EAPOL body_len and EAP header length so trailing
    /// 60-byte Ethernet frame padding never corrupts EAP-TTLS parsing.
    fn recv_eap_packet(&mut self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, String> {
        let bssid = self.bssid();
        let deadline = timeout.map(|d| Instant::now() + d);

        loop {
            let rem = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        return Ok(None);
                    }
                    Some(dl.duration_since(now))
                }
                None => None,
            };

            let frame = match self.recv_raw_frame(rem)? {
                Some(f) => f,
                None => return Ok(None),
            };

            // Ethernet II header: 14 bytes (Dest: 6, Src: 6, EtherType: 2)
            // EAPOL header: 4 bytes (Version: 1, Type: 1, Length: 2)
            if frame.len() < 18 {
                continue;
            }

            // Check EtherType: frame[12..14]
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            if ethertype != ETH_P_PAE {
                continue;
            }

            // Check source MAC: frame[6..12] == BSSID
            if frame[6..12] != bssid {
                continue;
            }

            // Check EAPOL Type: frame[15] == 0 (EAP-Packet)
            let eapol_type = frame[15];
            if eapol_type != 0 {
                // Ignore non-EAP types (e.g. Type 1 EAPOL-Start, Type 3 EAPOL-Key) without aborting
                continue;
            }

            let eapol_body_len = u16::from_be_bytes([frame[16], frame[17]]) as usize;
            let available = frame.len() - 18;
            if available < eapol_body_len {
                // Truncated EAPOL frame
                continue;
            }

            // Slice payload using EAPOL body_len
            let eapol_body = &frame[18..18 + eapol_body_len];

            // Check EAP header (Code: 1, ID: 1, Length: 2)
            if eapol_body.len() < 4 {
                continue;
            }

            let eap_len = u16::from_be_bytes([eapol_body[2], eapol_body[3]]) as usize;
            if eap_len < 4 || eap_len > eapol_body.len() {
                // Invalid or truncated EAP length
                continue;
            }

            // Strictly slice payload using EAP header length
            let eap = eapol_body[..eap_len].to_vec();
            return Ok(Some(eap));
        }
    }
}

pub fn get_ifindex(iface: &str) -> Result<i32, String> {
    let c_iface = std::ffi::CString::new(iface).map_err(|e| e.to_string())?;
    let idx = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if idx > 0 {
        return Ok(idx as i32);
    }
    // Fallback: read /sys/class/net/<iface>/ifindex
    let sys_path = format!("/sys/class/net/{}/ifindex", iface);
    if let Ok(s) = fs::read_to_string(&sys_path) {
        if let Ok(v) = s.trim().parse::<i32>() {
            return Ok(v);
        }
    }
    Err(format!("Interface '{}' not found (if_nametoindex returned 0)", iface))
}

/// Linux raw AF_PACKET transport bound to network interface.
pub struct RawSocketTransport {
    fd: i32,
    bssid: [u8; 6],
    iface_mac: [u8; 6],
    if_index: i32,
}

impl RawSocketTransport {
    pub fn new(iface: &str, bssid: [u8; 6], mac_override: Option<[u8; 6]>) -> Result<Self, String> {
        let iface_mac = if let Some(mac) = mac_override {
            mac
        } else {
            read_iface_mac(iface)?
        };

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (ETH_P_PAE as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(format!("Failed to open AF_PACKET socket (requires root/CAP_NET_RAW): error {}", fd));
        }

        let if_index = get_ifindex(iface)?;

        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (ETH_P_PAE as u16).to_be();
        sll.sll_ifindex = if_index;

        let ret = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd); }
            return Err(format!("Failed to bind AF_PACKET socket to interface '{}' (ifindex {})", iface, if_index));
        }

        Ok(Self {
            fd,
            bssid,
            iface_mac,
            if_index,
        })
    }
}

impl Drop for RawSocketTransport {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl EapolTransport for RawSocketTransport {
    fn bssid(&self) -> [u8; 6] {
        self.bssid
    }

    fn iface_mac(&self) -> [u8; 6] {
        self.iface_mac
    }

    fn send_raw_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (ETH_P_PAE as u16).to_be();
        sll.sll_ifindex = self.if_index;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&self.bssid);

        let ret = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const _,
                frame.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 || ret as usize != frame.len() {
            let err = io::Error::last_os_error();
            return Err(format!("Raw socket sendto failed: {} ({})", ret, err));
        }
        Ok(())
    }

    fn recv_raw_frame(&mut self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, String> {
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut buf = vec![0u8; 2048];

        loop {
            let timeout_ms = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        return Ok(None);
                    }
                    dl.duration_since(now).as_millis().min(i32::MAX as u128) as i32
                }
                None => -1,
            };

            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!("poll failed on raw socket: {}", err));
            }
            if ret == 0 {
                return Ok(None); // timeout
            }

            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut sll_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

            let r = unsafe {
                libc::recvfrom(
                    self.fd,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    0,
                    &mut sll as *mut _ as *mut libc::sockaddr,
                    &mut sll_len,
                )
            };

            if r < 0 {
                let err = io::Error::last_os_error();
                if let Some(code) = err.raw_os_error() {
                    if code == libc::EINTR || code == libc::EAGAIN || code == libc::EWOULDBLOCK {
                        continue;
                    }
                }
                return Err(format!("Raw socket recvfrom failed: {}", err));
            }

            // PACKET_OUTGOING frames (sll_pkttype == 4) must be ignored!
            if sll.sll_pkttype == libc::PACKET_OUTGOING as u8 {
                continue;
            }

            let mut out = buf.clone();
            out.truncate(r as usize);
            return Ok(Some(out));
        }
    }
}

/// Mock transport over Unix domain datagram socket for offline testing.
pub struct MockSocketTransport {
    sock: UnixDatagram,
    client_path: PathBuf,
    bssid: [u8; 6],
    iface_mac: [u8; 6],
}

impl MockSocketTransport {
    pub fn new(server_path: &str, bssid: [u8; 6], iface_mac: [u8; 6]) -> Result<Self, String> {
        let pid = std::process::id();
        let client_path = PathBuf::from(format!("/tmp/eap_ttls_client_{}.sock", pid));
        let _ = fs::remove_file(&client_path);

        let sock = UnixDatagram::bind(&client_path)
            .map_err(|e| format!("Failed to bind mock client socket: {}", e))?;
        sock.connect(server_path)
            .map_err(|e| format!("Failed to connect to mock server socket '{}': {}", server_path, e))?;

        Ok(Self {
            sock,
            client_path,
            bssid,
            iface_mac,
        })
    }
}

impl Drop for MockSocketTransport {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.client_path);
    }
}

impl EapolTransport for MockSocketTransport {
    fn bssid(&self) -> [u8; 6] {
        self.bssid
    }

    fn iface_mac(&self) -> [u8; 6] {
        self.iface_mac
    }

    fn send_raw_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.sock.send(frame).map_err(|e| format!("Mock socket send failed: {}", e))?;
        Ok(())
    }

    fn recv_raw_frame(&mut self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, String> {
        let deadline = timeout.map(|d| Instant::now() + d);
        let fd = self.sock.as_raw_fd();
        let mut buf = vec![0u8; 2048];

        loop {
            let timeout_ms = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        return Ok(None);
                    }
                    dl.duration_since(now).as_millis().min(i32::MAX as u128) as i32
                }
                None => -1,
            };

            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!("poll failed on mock socket: {}", err));
            }
            if ret == 0 {
                return Ok(None);
            }

            match self.sock.recv(&mut buf) {
                Ok(r) => {
                    let mut out = buf.clone();
                    out.truncate(r);
                    return Ok(Some(out));
                }
                Err(err) => {
                    if let Some(code) = err.raw_os_error() {
                        if code == libc::EINTR || code == libc::EAGAIN || code == libc::EWOULDBLOCK {
                            continue;
                        }
                    }
                    return Err(format!("Mock socket recv failed: {}", err));
                }
            }
        }
    }
}

pub fn read_iface_mac(iface: &str) -> Result<[u8; 6], String> {
    let path = format!("/sys/class/net/{}/address", iface);
    if let Ok(s) = fs::read_to_string(&path) {
        if let Ok(mac) = parse_mac(s.trim()) {
            return Ok(mac);
        }
    }
    // Fallback: ioctl SIOCGIFHWADDR
    let c_iface = std::ffi::CString::new(iface).map_err(|e| e.to_string())?;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd >= 0 {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        unsafe {
            libc::strncpy(
                ifr.ifr_name.as_mut_ptr(),
                c_iface.as_ptr(),
                libc::IFNAMSIZ - 1,
            );
            let ret = libc::ioctl(fd, libc::SIOCGIFHWADDR as _, &mut ifr);
            libc::close(fd);
            if ret == 0 {
                let sa_data = ifr.ifr_ifru.ifru_hwaddr.sa_data;
                let mac = [
                    sa_data[0] as u8,
                    sa_data[1] as u8,
                    sa_data[2] as u8,
                    sa_data[3] as u8,
                    sa_data[4] as u8,
                    sa_data[5] as u8,
                ];
                return Ok(mac);
            }
        }
    }
    Err(format!("Failed to read interface MAC for '{}'", iface))
}

pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("Invalid MAC format '{}'", s));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16)
            .map_err(|e| format!("Invalid hex octet '{}' in MAC '{}': {}", p, s, e))?;
    }
    Ok(mac)
}
