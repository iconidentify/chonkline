//! The opt-in anti-bot registration challenge.
//!
//! Own test binary: it needs CHONKLINE_REG_CHALLENGE set, while every other
//! suite exercises the default (off) path.

mod common;
use common::*;

fn start_challenge_server() -> String {
    std::env::set_var("CHONKLINE_REG_CHALLENGE", "1");
    std::env::set_var("CHONKLINE_REG_TIMEOUT_SECS", "30");
    start_server()
}

#[test]
fn a_client_that_answers_ping_registers_normally() {
    let addr = start_challenge_server();

    let mut c = Client::new(&addr);
    c.send("NICK goodclient");
    c.send("USER goodclient 0 * :Answers PING");

    // The server challenges before completing registration.
    let ping = c.read_until(|l| l.contains("PING") || l.contains(" 001 "));
    assert!(ping.contains("PING"), "expected a registration challenge, got {ping:?}");

    // Every real client answers this automatically.
    let token = ping.split(':').next_back().unwrap_or("token").to_string();
    c.send(&format!("PONG :{}", token));

    let welcome = c.read_until(|l| l.contains(" 001 "));
    assert!(welcome.contains(" 001 "), "answering the challenge must complete registration");
}

#[test]
fn a_client_that_never_answers_does_not_register() {
    // The drone-flood case: blast NICK/USER/JOIN without ever reading.
    let addr = start_challenge_server();

    let mut bot = Client::new(&addr);
    bot.send("NICK dronebot");
    bot.send("USER dronebot 0 * :Never answers");
    bot.send("JOIN #flood");
    bot.send("PRIVMSG #flood :spam");

    // It may see the challenge, but never a welcome and never a JOIN echo.
    let line = bot.read_until(|l| l.contains(" 001 ") || l.contains("JOIN"));
    assert!(
        !line.contains(" 001 ") && !line.contains("JOIN"),
        "an unanswering client must not register or join: {line:?}"
    );
}

#[test]
fn any_pong_is_accepted_not_just_a_matching_token() {
    // Matching the cookie adds nothing against a bot that reads the socket, and
    // risks breaking a client that echoes the token oddly.
    let addr = start_challenge_server();

    let mut c = Client::new(&addr);
    c.send("NICK loosepong");
    c.send("USER loosepong 0 * :Loose");
    c.read_until(|l| l.contains("PING"));
    c.send("PONG :something-entirely-different");

    let welcome = c.read_until(|l| l.contains(" 001 "));
    assert!(welcome.contains(" 001 "), "any PONG must satisfy the challenge");
}
