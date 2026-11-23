//! mock_server.rs - Standalone mock EAP-TTLS + PAP authenticator server for testing.

use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConfig;
use rustls::{ProtocolVersion, ServerConnection};
use rustls_rustcrypto::provider;

const ETH_P_PAE: u16 = 0x888e;

struct ServerArgs {
    socket_path: String,
    cert_path: String,
    key_path: String,
    expected_user: String,
    expected_pass: String,
    out_pmk_path: String,
    tls12_only: bool,
    fragment_size: usize,
    send_ticket: bool,
    retransmit_dup: bool,
}

fn parse_args() -> Result<ServerArgs, String> {
    let mut args = env::args().skip(1);
    let mut socket_path = String::new();
    let mut cert_path = String::new();
    let mut key_path = String::new();
    let mut expected_user = "testuser@campus.edu".to_string();
    let mut expected_pass = "secret123".to_string();
    let mut out_pmk_path = "/tmp/mock_server_pmk.bin".to_string();
    let mut tls12_only = false;
    let mut fragment_size = 0;
    let mut send_ticket = false;
    let mut retransmit_dup = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => socket_path = args.next().ok_or("Missing --socket")?,
            "--cert" => cert_path = args.next().ok_or("Missing --cert")?,
            "--key" => key_path = args.next().ok_or("Missing --key")?,
            "--expected-user" => expected_user = args.next().ok_or("Missing --expected-user")?,
            "--expected-pass" => expected_pass = args.next().ok_or("Missing --expected-pass")?,
            "--out-pmk" => out_pmk_path = args.next().ok_or("Missing --out-pmk")?,
            "--tls12-only" => tls12_only = true,
            "--fragment-size" => {
                let s = args.next().ok_or("Missing --fragment-size")?;
                fragment_size = s.parse().map_err(|e| format!("Invalid --fragment-size: {}", e))?;
            }
            "--send-ticket" => send_ticket = true,
            "--retransmit-dup" => retransmit_dup = true,
            other => return Err(format!("Unknown option '{}'", other)),
        }
    }

    if socket_path.is_empty() || cert_path.is_empty() || key_path.is_empty() {
        return Err("Usage: mock_server --socket <path> --cert <cert.pem> --key <key.pem> [options]".into());
    }

    Ok(ServerArgs {
        socket_path,
        cert_path,
        key_path,
        expected_user,
        expected_pass,
        out_pmk_path,
        tls12_only,
        fragment_size,
        send_ticket,
        retransmit_dup,
    })
}

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    let mut r = BufReader::new(File::open(path).expect("Failed to open cert file"));
    rustls_pemfile::certs(&mut r)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse certs")
}

fn load_key(path: &str) -> PrivateKeyDer<'static> {
    let mut r = BufReader::new(File::open(path).expect("Failed to open key file"));
    rustls_pemfile::private_key(&mut r)
        .expect("Failed to read key")
        .expect("No private key found")
}

fn parse_diameter_avps(mut data: &[u8]) -> (Option<String>, Option<String>) {
    let mut user = None;
    let mut pass = None;

    while data.len() >= 8 {
        let code = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let len = u32::from_be_bytes([0, data[5], data[6], data[7]]) as usize;
        if len < 8 || len > data.len() {
            break;
        }
        let payload = &data[8..len];
        if code == 1 {
            user = Some(String::from_utf8_lossy(payload).to_string());
        } else if code == 2 {
            pass = Some(String::from_utf8_lossy(payload).to_string());
        }
        let pad = (4 - (len % 4)) % 4;
        let total = len + pad;
        if total > data.len() {
            break;
        }
        data = &data[total..];
    }
    (user, pass)
}

fn send_frame(
    sock: &UnixDatagram,
    dst_mac: &[u8; 6],
    server_bssid: &[u8; 6],
    eapol_type: u8,
    eap_body: &[u8],
    addr: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut frame = Vec::with_capacity(14 + 4 + eap_body.len());
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(server_bssid);
    frame.extend_from_slice(&ETH_P_PAE.to_be_bytes());
    frame.push(1); // EAPOL version 1
    frame.push(eapol_type);
    frame.extend_from_slice(&(eap_body.len() as u16).to_be_bytes());
    frame.extend_from_slice(eap_body);
    sock.send_to(&frame, addr)?;
    Ok(())
}

fn send_server_flight(
    sock: &UnixDatagram,
    dst_mac: &[u8; 6],
    server_bssid: &[u8; 6],
    eap_id: u8,
    tls_data: &[u8],
    addr: &PathBuf,
    fragment_size: usize,
    pending_tx: &mut Vec<Vec<u8>>,
    last_sent: &mut Option<(u8, Vec<u8>)>,
) -> Result<(), Box<dyn std::error::Error>> {
    pending_tx.clear();
    if fragment_size > 0 && tls_data.len() > fragment_size {
        let total_bytes = tls_data.len() as u32;
        let chunk0_len = (6 + 4 + fragment_size) as u16;
        let mut pkt0 = Vec::with_capacity(chunk0_len as usize);
        pkt0.push(1); // Request
        pkt0.push(eap_id);
        pkt0.extend_from_slice(&chunk0_len.to_be_bytes());
        pkt0.push(21); // EAP-TTLS
        pkt0.push(0xc0); // Flags: L=1, M=1
        pkt0.extend_from_slice(&total_bytes.to_be_bytes());
        pkt0.extend_from_slice(&tls_data[0..fragment_size]);
        send_frame(sock, dst_mac, server_bssid, 0, &pkt0, addr)?;
        *last_sent = Some((eap_id, pkt0));

        let mut offset = fragment_size;
        while offset < tls_data.len() {
            let chunk = &tls_data[offset..];
            if chunk.len() > fragment_size {
                let this_chunk = &chunk[0..fragment_size];
                let len = (6 + fragment_size) as u16;
                let mut pkt = Vec::with_capacity(len as usize);
                pkt.push(1); // Request
                pkt.push(eap_id);
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.push(21);
                pkt.push(0x40); // Flags: M=1
                pkt.extend_from_slice(this_chunk);
                pending_tx.push(pkt);
                offset += fragment_size;
            } else {
                let len = (6 + chunk.len()) as u16;
                let mut pkt = Vec::with_capacity(len as usize);
                pkt.push(1); // Request
                pkt.push(eap_id);
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.push(21);
                pkt.push(0x00); // Flags: M=0
                pkt.extend_from_slice(chunk);
                pending_tx.push(pkt);
                break;
            }
        }
    } else {
        let total_len = (6 + tls_data.len()) as u16;
        let mut req = Vec::new();
        req.push(1); // Request
        req.push(eap_id);
        req.extend_from_slice(&total_len.to_be_bytes());
        req.push(21); // EAP-TTLS
        req.push(0); // Flags: 0
        req.extend_from_slice(tls_data);
        send_frame(sock, dst_mac, server_bssid, 0, &req, addr)?;
        *last_sent = Some((eap_id, req));
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;

    let _ = fs::remove_file(&args.socket_path);
    let sock = UnixDatagram::bind(&args.socket_path)?;
    sock.set_read_timeout(Some(Duration::from_secs(15)))?;

    eprintln!("[mock_server] Listening on '{}'", args.socket_path);

    // Setup TLS ServerConfig
    let certs = load_certs(&args.cert_path);
    let key = load_key(&args.key_path);
    let p = Arc::new(provider());
    let builder = if args.tls12_only {
        ServerConfig::builder_with_provider(p)
            .with_protocol_versions(&[&rustls::version::TLS12])?
    } else {
        ServerConfig::builder_with_provider(p)
            .with_safe_default_protocol_versions()?
    };
    let server_config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let server_config = Arc::new(server_config);

    let mut server_conn = ServerConnection::new(server_config)?;
    let mut client_addr: Option<PathBuf> = None;
    let mut client_mac = [0x12, 0x00, 0x7d, 0xf6, 0xc9, 0xf8];
    let server_bssid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    let mut buf = [0u8; 4096];
    let mut eap_id = 1u8;
    let mut pmk_derived: Option<[u8; 32]> = None;
    let mut incoming_flight = Vec::new();
    let mut server_pending_tx: Vec<Vec<u8>> = Vec::new();
    let mut last_sent_request_frame: Option<(u8, Vec<u8>)> = None;
    let mut has_retransmitted = false;
    let mut pap_verified = false;

    loop {
        let (len, src) = match sock.recv_from(&mut buf) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("[mock_server] Recv timeout or error: {}", e);
                break;
            }
        };

        if let Some(src_path) = src.as_pathname() {
            client_addr = Some(src_path.to_path_buf());
        }
        let addr = match client_addr.as_ref() {
            Some(a) => a,
            None => continue,
        };

        let frame = &buf[..len];
        if frame.len() < 18 {
            continue;
        }

        // Parse MAC
        client_mac.copy_from_slice(&frame[6..12]);
        let eapol_type = frame[15];

        if eapol_type == 1 {
            // EAPOL-Start received!
            eprintln!("[mock_server] Received EAPOL-Start from {:02x?}", client_mac);
            // Send EAP-Request/Identity (Code 1, ID 1, Type 1)
            let mut req = Vec::new();
            req.push(1); // Request
            req.push(eap_id);
            req.extend_from_slice(&5u16.to_be_bytes());
            req.push(1); // Type: Identity
            send_frame(&sock, &client_mac, &server_bssid, 0, &req, addr)?;
            continue;
        }

        if eapol_type != 0 {
            continue;
        }

        let eapol_len = u16::from_be_bytes([frame[16], frame[17]]) as usize;
        let eap = &frame[18..18 + eapol_len.min(frame.len() - 18)];
        if eap.len() < 4 {
            continue;
        }

        let code = eap[0];
        let id = eap[1];
        let length = u16::from_be_bytes([eap[2], eap[3]]) as usize;
        let eap_type = if length > 4 && eap.len() > 4 { eap[4] } else { 0 };

        if code == 2 && eap_type == 1 {
            // EAP-Response/Identity
            let outer_id = String::from_utf8_lossy(&eap[5..length]);
            eprintln!("[mock_server] Received EAP-Response/Identity: '{}'", outer_id);

            // Send EAP-Request/TTLS Start (Code 1, ID, Type 21, Flags S=0x20)
            eap_id = id.wrapping_add(1);
            let mut req = Vec::new();
            req.push(1); // Request
            req.push(eap_id);
            req.extend_from_slice(&6u16.to_be_bytes());
            req.push(21); // EAP-TTLS
            req.push(0x20); // Flags: S=1
            send_frame(&sock, &client_mac, &server_bssid, 0, &req, addr)?;
            continue;
        }

        if code == 2 && eap_type == 21 {
            // Check for duplicate request retransmission test
            if args.retransmit_dup && !has_retransmitted && last_sent_request_frame.is_some() {
                has_retransmitted = true;
                let (prev_id, ref prev_pkt) = last_sent_request_frame.as_ref().unwrap();
                eprintln!("[mock_server] Injecting duplicate EAP-Request retransmit (id={}) mid-handshake...", prev_id);
                send_frame(&sock, &client_mac, &server_bssid, 0, prev_pkt, addr)?;
                continue;
            }

            // EAP-Response/TTLS
            let flags = eap[5];
            let l_flag = flags & 0x80 != 0;
            let m_flag = flags & 0x40 != 0;
            let data_off = if l_flag { 6 + 4 } else { 6 };
            let tls_data = if length >= data_off && eap.len() >= data_off {
                &eap[data_off..length.min(eap.len())]
            } else {
                &[]
            };

            // Check if this is an ACK for a server-sent fragment
            if tls_data.is_empty() && !m_flag && !server_pending_tx.is_empty() {
                let mut next_frag = server_pending_tx.remove(0);
                eap_id = id.wrapping_add(1);
                next_frag[1] = eap_id;
                send_frame(&sock, &client_mac, &server_bssid, 0, &next_frag, addr)?;
                last_sent_request_frame = Some((eap_id, next_frag));
                continue;
            }

            // Check if this is an ACK for a post-handshake message (e.g. NewSessionTicket)
            if pap_verified && tls_data.is_empty() && !m_flag {
                eprintln!("[mock_server] Received client ACK for post-handshake message. Sending EAP-Success.");
                eap_id = id.wrapping_add(1);
                let mut succ = Vec::new();
                succ.push(3); // EAP-Success
                succ.push(eap_id);
                succ.extend_from_slice(&4u16.to_be_bytes());
                send_frame(&sock, &client_mac, &server_bssid, 0, &succ, addr)?;
                eprintln!("[mock_server] SUCCESS: EAP-Success dispatched.");
                std::thread::sleep(Duration::from_millis(500));
                return Ok(());
            }

            if m_flag {
                // Client fragment
                incoming_flight.extend_from_slice(tls_data);
                // Send ACK
                eap_id = id;
                let mut ack = Vec::new();
                ack.push(1); // Request (ACK)
                ack.push(eap_id);
                ack.extend_from_slice(&6u16.to_be_bytes());
                ack.push(21);
                ack.push(0);
                send_frame(&sock, &client_mac, &server_bssid, 0, &ack, addr)?;
                continue;
            }

            if !tls_data.is_empty() {
                incoming_flight.extend_from_slice(tls_data);
            }

            if !incoming_flight.is_empty() {
                let mut cursor = std::io::Cursor::new(&incoming_flight);
                server_conn.read_tls(&mut cursor)?;
                server_conn.process_new_packets()?;
                incoming_flight.clear();
            }

            // Check if TLS handshake finished
            if !server_conn.is_handshaking() && pmk_derived.is_none() {
                eprintln!("[mock_server] TLS handshake completed! Protocol: {:?}", server_conn.protocol_version());
                let mut buf = [0u8; 128];
                let is_tls13 = server_conn.protocol_version() == Some(ProtocolVersion::TLSv1_3);
                if is_tls13 {
                    server_conn.export_keying_material(&mut buf, b"EXPORTER_EAP_TLS_Key_Material", Some(&[0x15]))?;
                } else {
                    server_conn.export_keying_material(&mut buf, b"ttls keying material", None)?;
                }
                let mut pmk = [0u8; 32];
                pmk.copy_from_slice(&buf[0..32]);
                eprintln!("[mock_server] Server derived PMK: {:02x?}...", &pmk[..8]);
                fs::write(&args.out_pmk_path, &pmk)?;
                pmk_derived = Some(pmk);
            }

            // Check if server needs to write TLS data
            let mut out_tls = Vec::new();
            server_conn.write_tls(&mut out_tls)?;

            // Check for decrypted inner PAP payload first
            let mut decrypted = Vec::new();
            let _ = server_conn.reader().read_to_end(&mut decrypted);
            if !decrypted.is_empty() {
                eprintln!("[mock_server] Received inner PAP data: {} bytes", decrypted.len());
                let (user, pass) = parse_diameter_avps(&decrypted);
                eprintln!("[mock_server] Decoded User-Name: '{:?}', User-Password: '{:?}'", user, pass);

                if user.as_deref() == Some(&args.expected_user) && pass.as_deref() == Some(&args.expected_pass) {
                    eprintln!("[mock_server] Credentials MATCH!");
                    if !out_tls.is_empty() || args.send_ticket {
                        let ticket_data = if !out_tls.is_empty() {
                            out_tls
                        } else {
                            vec![0x17, 0x03, 0x03, 0x00, 0x20, 0x01, 0x02, 0x03]
                        };
                        eprintln!("[mock_server] Sending post-handshake TLS message ({} bytes) in EAP-Request...", ticket_data.len());
                        eap_id = id.wrapping_add(1);
                        pap_verified = true;
                        send_server_flight(
                            &sock,
                            &client_mac,
                            &server_bssid,
                            eap_id,
                            &ticket_data,
                            addr,
                            args.fragment_size,
                            &mut server_pending_tx,
                            &mut last_sent_request_frame,
                        )?;
                        continue;
                    } else {
                        eap_id = id.wrapping_add(1);
                        let mut succ = Vec::new();
                        succ.push(3); // EAP-Success
                        succ.push(eap_id);
                        succ.extend_from_slice(&4u16.to_be_bytes());
                        send_frame(&sock, &client_mac, &server_bssid, 0, &succ, addr)?;
                        eprintln!("[mock_server] SUCCESS: EAP-Success dispatched.");
                        std::thread::sleep(Duration::from_millis(500));
                        return Ok(());
                    }
                } else {
                    eprintln!("[mock_server] Credentials MISMATCH! Sending EAP-Failure.");
                    eap_id = id.wrapping_add(1);
                    let mut fail = Vec::new();
                    fail.push(4); // EAP-Failure
                    fail.push(eap_id);
                    fail.extend_from_slice(&4u16.to_be_bytes());
                    send_frame(&sock, &client_mac, &server_bssid, 0, &fail, addr)?;
                    return Err("Credentials rejected".into());
                }
            } else if !out_tls.is_empty() {
                // Send server flight in EAP-Request/TTLS (fragmented if requested)
                eap_id = id.wrapping_add(1);
                send_server_flight(
                    &sock,
                    &client_mac,
                    &server_bssid,
                    eap_id,
                    &out_tls,
                    addr,
                    args.fragment_size,
                    &mut server_pending_tx,
                    &mut last_sent_request_frame,
                )?;
            }
        }
    }

    Ok(())
}
