use super::response::PartialResponse;
use std::collections::HashMap;

pub struct Client {
    pub conn: quiche::Connection,

    pub http3_conn: Option<quiche::h3::Connection>,

    pub partial_responses: HashMap<u64, PartialResponse>,
}

pub type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;
