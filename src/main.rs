use irc_server::{serve, Config};

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("IRC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(6697);
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>().unwrap();

    match serve(addr, Config::default()).await {
        Ok((bound, mut task)) => {
            eprintln!("{} listening on {}", irc_server::proto::VERSION, bound);
            // Block until interrupted or the server loop ends on its own.
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = &mut task => {},
            }
        }
        Err(e) => eprintln!("failed to bind {}: {}", addr, e),
    }
}
