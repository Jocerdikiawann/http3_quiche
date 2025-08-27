#[macro_use]
extern crate log;

use example_http3::net::config::BaseConfig;
use quiche::{Config, h3::NameValue};

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 1 {
        eprintln!("Error: No arguments provided");
        return;
    }

    let method = args.get(1).cloned().unwrap_or("GET".to_string());
    let body_str = args.get(2).cloned().unwrap_or("".to_string());
    let body = body_str.as_bytes();

    let url = url::Url::parse("https://127.0.0.1:4433").unwrap();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let peer_addr = url.socket_addrs(|| None).unwrap()[0];

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connection.
    let base_config = BaseConfig {
        max_idle_timeout: 5000,
        max_recv_udp_payload_size: MAX_DATAGRAM_SIZE,
        max_send_udp_payload_size: MAX_DATAGRAM_SIZE,
        initial_max_data: 10_000_000,
        initial_max_stream_data_bidi_local: 1_000_000,
        initial_max_stream_data_bidi_remote: 1_000_000,
        initial_max_stream_data_uni: 1_000_000,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        disable_active_migration: true,
        enable_early_data: false,
        pub_key: None,
        private_key: None,
        protocol: &[b"h3"],
    };

    let mut config: Config = BaseConfig::client_new(&base_config);
    let mut http3_conn = None;

    let mut stream_id = None;
    // let mut req_sent = false;
    // let mut body_sent = false;
    let mut offset = 0;

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Get local address.
    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config).unwrap();

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }

    debug!("written {}", write);

    let h3_config = quiche::h3::Config::new().unwrap();

    // Prepare request.
    let mut path = String::from(url.path());

    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let req = vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(b":authority", url.host_str().unwrap().as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];

    let req_start = std::time::Instant::now();

    let mut req_sent = false;
    let mut body_sent = false;

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");

                conn.on_timeout();

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

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                }
            };

            debug!("processed {} bytes", read);
        }

        debug!("done reading");

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Create a new HTTP/3 connection once the QUIC connection is established.
        if conn.is_established() && http3_conn.is_none() {
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            );
        }

        // Send HTTP requests once the QUIC connection is established, and until
        // all requests have been sent.
        if let Some(h3_conn) = &mut http3_conn {
            if !req_sent {
                info!("sending HTTP request {:?}", req);

                stream_id = h3_conn.send_request(&mut conn, &req, body.is_empty()).ok();

                req_sent = true;
            }
        }

        // Send body
        if let Some(h3_conn) = &mut http3_conn {
            if !body_sent && !body.is_empty() && stream_id.is_some() {
                let sid = stream_id.unwrap();
                while offset < body.len() {
                    match h3_conn.send_body(
                        &mut conn,
                        sid,
                        &body[offset..],
                        offset + body.len() == body.len(),
                    ) {
                        Ok(written) => {
                            offset += written;
                            debug!(
                                "Sent {} bytes of body, total {}/{}",
                                written,
                                offset,
                                body.len()
                            );
                            if offset == body.len() {
                                body_sent = true;
                                info!("Body fully sent: {:?}", std::str::from_utf8(body));
                            }
                        }
                        Err(quiche::h3::Error::Done) => {
                            debug!("send_body blocked, will retry");
                            break;
                        }
                        Err(e) => {
                            error!("send_body failed: {:?}", e);
                            break;
                        }
                    }
                }
            }
        }

        if let Some(http3_conn) = &mut http3_conn {
            // Process HTTP/3 events.
            loop {
                match http3_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!(
                            "got response headers {:?} on stream id {}",
                            hdrs_to_strings(&list),
                            stream_id
                        );
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        while let Ok(read) = http3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                            debug!(
                                "got {} bytes of response data on stream {}",
                                read, stream_id
                            );

                            print!("Got response {}", unsafe {
                                std::str::from_utf8_unchecked(&buf[..read])
                            });
                        }
                    }

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        info!("response received in {:?}, closing...", req_start.elapsed());

                        conn.close(true, 0x100, b"kthxbye").unwrap();
                    }

                    Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                        error!("request was reset by peer with {}, closing...", e);

                        conn.close(true, 0x100, b"kthxbye").unwrap();
                    }

                    Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                    Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                        info!("GOAWAY id={}", goaway_id);
                    }

                    Err(quiche::h3::Error::Done) => {
                        break;
                    }

                    Err(e) => {
                        error!("HTTP/3 processing failed: {:?}", e);

                        break;
                    }
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                }

                Err(e) => {
                    error!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
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

            debug!("written {}", write);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
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
