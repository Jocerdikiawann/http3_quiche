pub struct Request<T> {
    pub body: T,
    pub headers: Option<Vec<quiche::h3::Header>>,
}
