use quiche::Config;

pub struct BaseConfig<'a> {
    pub max_idle_timeout: u64,
    pub max_recv_udp_payload_size: usize,
    pub max_send_udp_payload_size: usize,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub disable_active_migration: bool,
    pub enable_early_data: bool,
    pub pub_key: Option<String>,
    pub private_key: Option<String>,
    pub protocol: &'a [&'a [u8]],
}

impl<'a> BaseConfig<'a> {
    pub fn server_new(&self) -> Config {
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

        config.set_max_idle_timeout(self.max_idle_timeout);
        config.set_max_recv_udp_payload_size(self.max_recv_udp_payload_size);
        config.set_max_send_udp_payload_size(self.max_send_udp_payload_size);
        config.set_initial_max_data(self.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi_remote);
        config.set_initial_max_stream_data_uni(self.initial_max_stream_data_uni);
        config.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(self.initial_max_streams_uni);
        config.set_disable_active_migration(self.disable_active_migration);

        if self.enable_early_data {
            config.enable_early_data();
        }

        config
    }

    pub fn client_new(&self) -> Config {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        // *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();

        config.set_max_idle_timeout(self.max_idle_timeout);
        config.set_max_recv_udp_payload_size(self.max_recv_udp_payload_size);
        config.set_max_send_udp_payload_size(self.max_send_udp_payload_size);
        config.set_initial_max_data(self.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi_remote);
        config.set_initial_max_stream_data_uni(self.initial_max_stream_data_uni);
        config.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(self.initial_max_streams_uni);
        config.set_disable_active_migration(self.disable_active_migration);

        config
    }
}
