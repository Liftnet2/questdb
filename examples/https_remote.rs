use questdb::{
    Result,
    ingress::{Sender, TimestampNanos},
};

/// HTTPS to a remote QuestDB instance with a CA-signed certificate.
///
/// Uses webpki root certificates (default) to verify the server's TLS cert.
///
/// Usage:
///   cargo run --example https_remote -- <host> <port>
///   cargo run --example https_remote -- questdb.example.com 9000
fn main() -> Result<()> {
    let host = std::env::args().nth(1).unwrap_or("localhost".to_string());
    let port = std::env::args().nth(2).unwrap_or("9000".to_string());
    let mut sender = Sender::from_conf(format!("https::addr={host}:{port};",))?;
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
