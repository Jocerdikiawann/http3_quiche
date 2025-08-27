pub struct PartialResponse {
    pub headers: Option<Vec<quiche::h3::Header>>,

    pub body: Vec<u8>,

    pub written: usize,
}
