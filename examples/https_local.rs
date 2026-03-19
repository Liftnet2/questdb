use questdb::{
    Result,
    ingress::{Sender, TimestampNanos},
};

/// HTTPS to a local QuestDB instance using a custom CA certificate.
///
/// For local/on-prem deployments with self-signed or internal CA certificates,
/// point `tls_roots` to the PEM file containing the CA cert that signed
/// the server's certificate.
///
/// Usage:
///   cargo run --example https_local -- <host> <port> <ca_cert_path>
///   cargo run --example https_local -- localhost 9000 /path/to/ca.pem
fn main() -> Result<()> {
    let host = std::env::args().nth(1).unwrap_or("localhost".to_string());
    let port = std::env::args().nth(2).unwrap_or("9000".to_string());
    let ca_path = std::env::args()
        .nth(3)
        .expect("Usage: https_local <host> <port> <ca_cert_path>");
    let mut sender = Sender::from_conf(format!("https::addr={host}:{port};tls_roots={ca_path};",))?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;
    Ok(())
}
