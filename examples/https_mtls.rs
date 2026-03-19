use questdb::{
    Result,
    ingress::{Sender, TimestampNanos},
};

/// HTTPS with mutual TLS (mTLS) authentication.
///
/// Both the server and client present certificates. The client provides
/// its certificate and private key, while validating the server's cert
/// against a custom CA.
///
/// Works for both local and remote deployments — just change the CA cert
/// to `webpki_roots` (omit `tls_roots`) for a publicly-signed server cert.
///
/// Usage:
///   cargo run --example https_mtls -- <host> <port> <ca_cert> <client_cert> <client_key>
///   cargo run --example https_mtls -- localhost 9000 certs/ca.pem certs/client.pem certs/client-key.pem
fn main() -> Result<()> {
    let host = std::env::args().nth(1).unwrap_or("localhost".to_string());
    let port = std::env::args().nth(2).unwrap_or("9000".to_string());
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "Usage: {} <host> <port> <ca_cert_path> <client_cert_path> <client_key_path>",
            args[0]
        );
        std::process::exit(1);
    }
    let ca_path = &args[3];
    let client_cert = &args[4];
    let client_key = &args[5];

    let mut sender = Sender::from_conf(format!(
        concat!(
            "https::addr={host}:{port};",
            "tls_roots={ca};",
            "tls_client_cert={cert};",
            "tls_client_key={key};",
        ),
        host = host,
        port = port,
        ca = ca_path,
        cert = client_cert,
        key = client_key,
    ))?;
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
