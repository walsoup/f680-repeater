//! ttls.rs - EAP-TTLS (RFC 5281 + RFC 9190) state machine and authentication driver.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::ClientConfig;
use rustls::ClientConnection;
use rustls_pki_types::ServerName;

use crate::crypto::derive_pmk;
use crate::diameter::build_pap_avps;
use crate::kmem::KmemDevice;
use crate::transport::EapolTransport;

pub const DEFAULT_CHUNK_SIZE: usize = 1000;

pub fn run_eap_ttls<T: EapolTransport + ?Sized>(
    transport: &mut T,
    kmem: &KmemDevice,
    client_config: Arc<ClientConfig>,
    identity: &str,
    password: &str,
    anon_identity: &str,
    timeout_secs: u64,
    chunk_size: usize,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    // 1. Initial EAPOL-Start with periodic retry (every 2s) until first EAP-Request arrives or timeout
    let mut initial_pkt: Option<Vec<u8>> = None;
    let mut attempt = 1;
    while Instant::now() < deadline {
        eprintln!("[eap] Sending EAPOL-Start (attempt {})...", attempt);
        attempt += 1;
        transport.send_eapol_start()?;

        let poll_interval = Duration::from_secs(2);
        let poll_start = Instant::now();
        while poll_start.elapsed() < poll_interval && Instant::now() < deadline {
            let rem = poll_interval.saturating_sub(poll_start.elapsed())
                .min(deadline.saturating_duration_since(Instant::now()));
            if let Some(pkt) = transport.recv_eap_packet(Some(rem))? {
                if pkt.len() >= 4 && pkt[0] == 1 {
                    // Received EAP-Request
                    initial_pkt = Some(pkt);
                    break;
                }
            }
        }
        if initial_pkt.is_some() {
            break;
        }
    }

    if initial_pkt.is_none() {
        return Err("Timed out waiting for initial EAP-Request".into());
    }

    let mut next_pkt = initial_pkt;
    let mut conn: Option<ClientConnection> = None;
    let mut incoming_flight = Vec::new();
    let mut pending_tx_fragments = Vec::new();
    let mut authenticated = false;

    // Retransmission cache for handling duplicate EAP-Requests on noisy wireless links
    let mut last_rx_id: Option<u8> = None;
    let mut last_sent_response: Option<Vec<u8>> = None;

    loop {
        if Instant::now() >= deadline {
            return Err("EAP-TTLS authentication timed out".into());
        }

        let pkt = if let Some(p) = next_pkt.take() {
            p
        } else {
            let rem = deadline.saturating_duration_since(Instant::now());
            match transport.recv_eap_packet(Some(rem))? {
                Some(p) => p,
                None => return Err("Timed out waiting for next EAP frame".into()),
            }
        };

        if pkt.len() < 4 {
            continue;
        }

        let code = pkt[0];
        let id = pkt[1];
        let length = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        eprintln!("[eap] RX packet: code={}, id={}, len={}, raw_len={}", code, id, length, pkt.len());
        let eap_type = if length > 4 && pkt.len() > 4 { pkt[4] } else { 0 };

        // Duplicate EAP-Request detection: re-send last response without desyncing TLS state machine
        if code == 1 && last_rx_id == Some(id) {
            if let Some(ref resp) = last_sent_response {
                eprintln!("[eap] Duplicate EAP-Request (id={}): re-transmitting cached response ({} bytes)", id, resp.len());
                transport.send_eap_packet(resp)?;
                continue;
            }
        }

        match code {
            3 => {
                // EAP-Success
                eprintln!("[eap] EAP-Success received (id={})! Authentication successful.", id);
                return Ok(());
            }
            4 => {
                // EAP-Failure
                return Err(format!("[eap] EAP-Failure received (id={})! Server rejected credentials.", id));
            }
            1 => {
                // EAP-Request
                match eap_type {
                    1 => {
                        // EAP-Request/Identity
                        eprintln!("[eap] EAP-Request/Identity (id={}): responding with outer identity '{}'", id, anon_identity);
                        let resp_len = (5 + anon_identity.len()) as u16;
                        let mut resp = Vec::with_capacity(resp_len as usize);
                        resp.push(2); // Code: Response
                        resp.push(id);
                        resp.extend_from_slice(&resp_len.to_be_bytes());
                        resp.push(1); // Type: Identity
                        resp.extend_from_slice(anon_identity.as_bytes());
                        last_rx_id = Some(id);
                        last_sent_response = Some(resp.clone());
                        transport.send_eap_packet(&resp)?;
                    }
                    21 => {
                        // EAP-Request/TTLS
                        if pkt.len() < 6 {
                            continue;
                        }
                        let flags = pkt[5];
                        let l_flag = flags & 0x80 != 0;
                        let m_flag = flags & 0x40 != 0;
                        let s_flag = flags & 0x20 != 0;

                        // Defensively handle L=1 even on continuation fragments
                        let data_off = if l_flag { 6 + 4 } else { 6 };
                        let tls_data = if length >= data_off && pkt.len() >= data_off {
                            let end = length.min(pkt.len());
                            &pkt[data_off..end]
                        } else {
                            &[]
                        };

                        if s_flag {
                            // TTLS Start
                            eprintln!("[ttls] EAP-TTLS Start (id={}), initializing TLS client...", id);
                            let server_name = ServerName::try_from("radius.local").unwrap();
                            let mut new_conn = ClientConnection::new(client_config.clone(), server_name)
                                .map_err(|e| format!("TLS client init failed: {}", e))?;

                            let mut out_tls = Vec::new();
                            new_conn.write_tls(&mut out_tls)
                                .map_err(|e| format!("ClientHello write failed: {}", e))?;

                            send_ttls_response(
                                transport,
                                id,
                                &out_tls,
                                &mut pending_tx_fragments,
                                &mut last_rx_id,
                                &mut last_sent_response,
                                chunk_size,
                            )?;
                            conn = Some(new_conn);
                        } else if m_flag {
                            // Incoming server fragment: reassemble and send empty EAP-Response/TTLS ACK
                            incoming_flight.extend_from_slice(tls_data);
                            let mut ack = Vec::with_capacity(6);
                            ack.push(2); // Response
                            ack.push(id);
                            ack.extend_from_slice(&6u16.to_be_bytes());
                            ack.push(21); // EAP-TTLS
                            ack.push(0); // Flags: 0x00
                            last_rx_id = Some(id);
                            last_sent_response = Some(ack.clone());
                            transport.send_eap_packet(&ack)?;
                        } else {
                            // Server flight complete or server ACK
                            if !tls_data.is_empty() {
                                incoming_flight.extend_from_slice(tls_data);
                            }

                            // If we have pending outgoing fragments waiting for server ACK:
                            if !pending_tx_fragments.is_empty() {
                                let mut next_frag = pending_tx_fragments.remove(0);
                                next_frag[1] = id; // update id to match request
                                last_rx_id = Some(id);
                                last_sent_response = Some(next_frag.clone());
                                transport.send_eap_packet(&next_frag)?;
                                continue;
                            }

                            let tls_conn = match conn.as_mut() {
                                Some(c) => c,
                                None => return Err("Received EAP-TTLS data before Start".into()),
                            };

                            // Feed complete incoming flight to TLS engine
                            if !incoming_flight.is_empty() {
                                let mut cursor = std::io::Cursor::new(&incoming_flight);
                                tls_conn.read_tls(&mut cursor)
                                    .map_err(|e| format!("TLS read error: {}", e))?;
                                tls_conn.process_new_packets()
                                    .map_err(|e| format!("TLS process error: {}", e))?;
                                incoming_flight.clear();
                            }

                            if tls_conn.is_handshaking() {
                                let mut out_tls = Vec::new();
                                tls_conn.write_tls(&mut out_tls)
                                    .map_err(|e| format!("TLS write error: {}", e))?;
                                if !out_tls.is_empty() {
                                    send_ttls_response(
                                        transport,
                                        id,
                                        &out_tls,
                                        &mut pending_tx_fragments,
                                        &mut last_rx_id,
                                        &mut last_sent_response,
                                        chunk_size,
                                    )?;
                                }
                            } else if !authenticated {
                                // Handshake finished!
                                eprintln!("[ttls] TLS handshake completed! Negotiated protocol: {:?}", tls_conn.protocol_version());

                                // Derive PMK using 128-byte exporter buffer
                                let pmk = derive_pmk(tls_conn)?;
                                eprintln!("[ttls] Derived 32-byte PMK: {:02x?}...", &pmk[..8]);

                                // Build inner PAP AVPs
                                let pap_avps = build_pap_avps(identity, password);
                                tls_conn.writer().write_all(&pap_avps)
                                    .map_err(|e| format!("PAP AVPs write error: {}", e))?;

                                let mut out_tls = Vec::new();
                                tls_conn.write_tls(&mut out_tls)
                                    .map_err(|e| format!("TLS write error for encrypted PAP: {}", e))?;

                                // Send encrypted PAP AVPs response
                                send_ttls_response(
                                    transport,
                                    id,
                                    &out_tls,
                                    &mut pending_tx_fragments,
                                    &mut last_rx_id,
                                    &mut last_sent_response,
                                    chunk_size,
                                )?;

                                // Injects PMK into /dev/kmem IMMEDIATELY before waiting for EAP-Success!
                                eprintln!("[ttls] Injecting PMK into /dev/kmem immediately...");
                                kmem.inject_pmk(&pmk)?;

                                authenticated = true;
                            } else {
                                // Already authenticated. Handle post-handshake messages (e.g. NewSessionTicket).
                                let mut dummy = Vec::new();
                                let _ = tls_conn.reader().read_to_end(&mut dummy);
                                let mut out_tls = Vec::new();
                                tls_conn.write_tls(&mut out_tls).ok();
                                if !out_tls.is_empty() {
                                    send_ttls_response(
                                        transport,
                                        id,
                                        &out_tls,
                                        &mut pending_tx_fragments,
                                        &mut last_rx_id,
                                        &mut last_sent_response,
                                        chunk_size,
                                    )?;
                                } else {
                                    // 0 plaintext bytes and no outgoing TLS: reply with empty EAP-Response/TTLS ACK
                                    eprintln!("[ttls] Post-handshake record processed (0 plaintext bytes), sending empty ACK (id={})", id);
                                    let mut ack = Vec::with_capacity(6);
                                    ack.push(2);
                                    ack.push(id);
                                    ack.extend_from_slice(&6u16.to_be_bytes());
                                    ack.push(21);
                                    ack.push(0);
                                    last_rx_id = Some(id);
                                    last_sent_response = Some(ack.clone());
                                    transport.send_eap_packet(&ack)?;
                                }
                            }
                        }
                    }
                    other => {
                        eprintln!("[eap] Ignoring unsupported EAP type {}", other);
                    }
                }
            }
            _ => {
                // Ignore other codes (e.g. unexpected responses)
            }
        }
    }
}

fn send_ttls_response<T: EapolTransport + ?Sized>(
    transport: &mut T,
    id: u8,
    tls_data: &[u8],
    pending_frags: &mut Vec<Vec<u8>>,
    last_rx_id: &mut Option<u8>,
    last_sent_response: &mut Option<Vec<u8>>,
    chunk_size: usize,
) -> Result<(), String> {
    pending_frags.clear();

    if tls_data.len() <= chunk_size {
        let total_len = (6 + tls_data.len()) as u16;
        let mut pkt = Vec::with_capacity(total_len as usize);
        pkt.push(2); // Response
        pkt.push(id);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.push(21); // EAP-TTLS
        pkt.push(0); // Flags: 0
        pkt.extend_from_slice(tls_data);
        *last_rx_id = Some(id);
        *last_sent_response = Some(pkt.clone());
        transport.send_eap_packet(&pkt)?;
    } else {
        let total_bytes = tls_data.len() as u32;
        let chunk0_len = (6 + 4 + chunk_size) as u16;
        let mut pkt0 = Vec::with_capacity(chunk0_len as usize);
        pkt0.push(2); // Response
        pkt0.push(id);
        pkt0.extend_from_slice(&chunk0_len.to_be_bytes());
        pkt0.push(21); // EAP-TTLS
        pkt0.push(0xc0); // Flags: L=1, M=1
        pkt0.extend_from_slice(&total_bytes.to_be_bytes());
        pkt0.extend_from_slice(&tls_data[0..chunk_size]);
        *last_rx_id = Some(id);
        *last_sent_response = Some(pkt0.clone());
        transport.send_eap_packet(&pkt0)?;

        let mut offset = chunk_size;
        while offset < tls_data.len() {
            let chunk = &tls_data[offset..];
            if chunk.len() > chunk_size {
                let this_chunk = &chunk[0..chunk_size];
                let len = (6 + chunk_size) as u16;
                let mut pkt = Vec::with_capacity(len as usize);
                pkt.push(2);
                pkt.push(id);
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.push(21);
                pkt.push(0x40); // Flags: M=1
                pkt.extend_from_slice(this_chunk);
                pending_frags.push(pkt);
                offset += chunk_size;
            } else {
                let len = (6 + chunk.len()) as u16;
                let mut pkt = Vec::with_capacity(len as usize);
                pkt.push(2);
                pkt.push(id);
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.push(21);
                pkt.push(0x00); // Flags: M=0
                pkt.extend_from_slice(chunk);
                pending_frags.push(pkt);
                break;
            }
        }
    }
    Ok(())
}
