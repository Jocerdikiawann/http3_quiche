#[macro_use]
extern crate log;

use std::{collections::HashMap, net};

use example_http3::model::client::{Client, ClientMap};
use ring::rand::*;

use quiche::h3::NameValue;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() {
    let mut stream_states: HashMap<u64, (Vec<quiche::h3::Header>, Vec<u8>)> = HashMap::new(); // (headers, body_buf)

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 0 {
        println!("Usage: {cmd}");
        println!("\nSee tools/apps/ for more complete implementations.");
        return;
    }

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket = mio::net::UdpSocket::bind("127.0.0.1:4433".parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file("src/bin/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("src/bin/cert.key")
        .unwrap();

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    let h3_config = quiche::h3::Config::new().unwrap();

    let rng = SystemRandom::new();
    let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();

    let local_addr = socket.local_addr().unwrap();

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                }
            };

            debug!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                }
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients.contains_key(&hdr.dcid) && !clients.contains_key(&conn_id) {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn =
                    quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut config).unwrap();

                let client = Client {
                    conn,
                    http3_conn: None,
                    partial_responses: HashMap::new(),
                };

                clients.insert(scid.clone(), client);

                clients.get_mut(&scid).unwrap()
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                }
            };

            debug!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new HTTP/3 connection as soon as the QUIC connection
            // is established.
            if (client.conn.is_in_early_data() || client.conn.is_established())
                && client.http3_conn.is_none()
            {
                debug!(
                    "{} QUIC handshake completed, now trying HTTP/3",
                    client.conn.trace_id()
                );

                let h3_conn =
                    match quiche::h3::Connection::with_transport(&mut client.conn, &h3_config) {
                        Ok(v) => v,

                        Err(e) => {
                            error!("failed to create HTTP/3 connection: {}", e);
                            continue 'read;
                        }
                    };

                // TODO: sanity check h3 connection before adding to map
                client.http3_conn = Some(h3_conn);
            }

            if client.http3_conn.is_some() {
                // Handle writable streams.
                for stream_id in client.conn.writable() {
                    handle_writable(client, stream_id);
                }

                // Process HTTP/3 events.
                loop {
                    let http3_conn = client.http3_conn.as_mut().unwrap();

                    match http3_conn.poll(&mut client.conn) {
                        Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                            handle_request_headers(
                                &list,
                                stream_id,
                                http3_conn,
                                &mut client.conn,
                                &mut stream_states,
                            );
                        }

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            handle_request_body(
                                stream_id,
                                http3_conn,
                                &mut client.conn,
                                &mut stream_states,
                            );
                        }

                        Ok((_stream_id, quiche::h3::Event::Finished)) => {
                            handle_stream_finished(
                                _stream_id,
                                http3_conn,
                                &mut client.conn,
                                &mut stream_states,
                            );
                        }

                        Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),

                        Ok((_prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => (),

                        Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),

                        Err(quiche::h3::Error::Done) => {
                            break;
                        }

                        Err(e) => {
                            error!("{} HTTP/3 error {:?}", client.conn.trace_id(), e);

                            break;
                        }
                    }
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for client in clients.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", client.conn.trace_id());
                        break;
                    }

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    }
                };

                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send() would block");
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }

                debug!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            debug!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
    }
}

fn handle_request_headers(
    headers: &[quiche::h3::Header],
    stream_id: u64,
    h3_conn: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    stream_states: &mut HashMap<u64, (Vec<quiche::h3::Header>, Vec<u8>)>,
) {
    stream_states.insert(stream_id, (headers.to_vec(), Vec::new()));

    let method = headers
        .iter()
        .find(|h| h.name() == b":method")
        .map(|h| std::str::from_utf8(h.value()).unwrap())
        .unwrap_or("");

    if method == "GET" {
        let (resp_headers, resp_body) = build_response(headers, None);
        h3_conn
            .send_response(conn, stream_id, &resp_headers, false)
            .unwrap();
        h3_conn
            .send_body(conn, stream_id, &resp_body, true)
            .unwrap();
        stream_states.remove(&stream_id); // cleanup
    }

    //NOTE: POST/PUT akan tunggu body di handle_request_body
}

fn handle_request_body(
    stream_id: u64,
    h3_conn: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    stream_states: &mut HashMap<u64, (Vec<quiche::h3::Header>, Vec<u8>)>,
) {
    let mut buf = [0; 4096];
    while let Ok(len) = h3_conn.recv_body(conn, stream_id, &mut buf) {
        if len == 0 {
            break;
        }
        if let Some(state) = stream_states.get_mut(&stream_id) {
            state.1.extend_from_slice(&buf[..len]); // append to body_buf
        }
    }
}

fn handle_stream_finished(
    stream_id: u64,
    h3_conn: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    stream_states: &mut HashMap<u64, (Vec<quiche::h3::Header>, Vec<u8>)>,
) {
    if let Some((headers, body_buf)) = stream_states.remove(&stream_id) {
        let (resp_headers, resp_body) = build_response(&headers, Some(&body_buf));
        h3_conn
            .send_response(conn, stream_id, &resp_headers, false)
            .unwrap();
        h3_conn
            .send_body(conn, stream_id, &resp_body, true)
            .unwrap();
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(src: &net::SocketAddr, token: &'a [u8]) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

/// Builds an HTTP/3 response given a request.
fn build_response(
    request: &[quiche::h3::Header],
    request_body: Option<&[u8]>,
) -> (Vec<quiche::h3::Header>, Vec<u8>) {
    let mut path = "";
    let mut method = "";

    for hdr in request {
        match hdr.name() {
            b":path" => path = std::str::from_utf8(hdr.value()).unwrap(),

            b":method" => method = std::str::from_utf8(hdr.value()).unwrap(),

            _ => (),
        }
    }

    info!("{} request path: {:?}", path, method);

    let (status, body) = match method {
        "GET" => (200, b"Hello World! From GET".to_vec()),
        "POST" => {
            if let Some(body) = request_body {
                println!("You received POST body: {:?}", std::str::from_utf8(body));
                (200, [b"Send back: ", body].concat())
            } else {
                (400, b"Missing body for POST".to_vec())
            }
        }
        "PUT" => {
            if let Some(body) = request_body {
                println!("You received PUT body: {:?}", std::str::from_utf8(body));
                (200, [b"Send back: ", body].concat())
            } else {
                (400, b"Missing body for PUT".to_vec())
            }
        }
        _ => (405, b"Method not allowed".to_vec()),
    };

    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ];

    (headers, body)
}

/// Handles newly writable streams.
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;
    let http3_conn = &mut client.http3_conn.as_mut().unwrap();

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();

    if let Some(ref headers) = resp.headers {
        match http3_conn.send_response(conn, stream_id, headers, false) {
            Ok(_) => (),

            Err(quiche::h3::Error::StreamBlocked) => {
                return;
            }

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        }
    }

    resp.headers = None;

    let body = &resp.body[resp.written..];

    let written = match http3_conn.send_body(conn, stream_id, body, true) {
        Ok(v) => v,

        Err(quiche::h3::Error::Done) => 0,

        Err(e) => {
            client.partial_responses.remove(&stream_id);

            error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}
