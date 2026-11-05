//! Send a small burst of UDP datagrams for the live-capture proof.

use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

#[derive(Debug)]
struct Args {
    target: String,
    count: u64,
    size: usize,
    interval_ms: u64,
    listen: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            target: "127.0.0.1:45999".to_owned(),
            count: 10,
            size: 64,
            interval_ms: 0,
            listen: true,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    // Keep the destination port open on loopback: a closed UDP port makes the
    // kernel return ICMP port-unreachable, and later sends fail with
    // ECONNREFUSED before the capture filter can see them.
    let _listener = if args.listen {
        Some(UdpSocket::bind(&args.target)?)
    } else {
        None
    };
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.connect(&args.target)?;
    let mut payload = vec![b'P'; args.size];
    let mut sent_bytes = 0_usize;
    for sequence in 0..args.count {
        stamp_sequence(&mut payload, sequence);
        sent_bytes = sent_bytes.saturating_add(socket.send(&payload)?);
        if args.interval_ms > 0 {
            std::thread::sleep(Duration::from_millis(args.interval_ms));
        }
    }
    println!(
        "sent count={} bytes={} target={} size={}",
        args.count, sent_bytes, args.target, args.size
    );
    Ok(())
}

fn stamp_sequence(payload: &mut [u8], sequence: u64) {
    for (index, byte) in payload.iter_mut().take(8).enumerate() {
        let shift = u32::try_from(index.saturating_mul(8)).unwrap_or(0);
        *byte = u8::try_from((sequence >> shift) & 0xff).unwrap_or(0);
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args::default();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                println!(
                    "usage: udp-sender [--target HOST:PORT] [--count N] [--size BYTES] [--interval-ms N] [--no-listen]\n\
                     \n\
                     --target       destination (default 127.0.0.1:45999)\n\
                     --count        datagrams to send (default 10)\n\
                     --size         payload bytes (default 64)\n\
                     --interval-ms  delay between datagrams (default 0)\n\
                     --no-listen    do not bind the destination port; sends may fail with ECONNREFUSED"
                );
                std::process::exit(0);
            }
            "--target" => parsed.target = take_value(&mut args, "--target")?,
            "--count" => {
                parsed.count = parse_number(&take_value(&mut args, "--count")?, "--count")?;
            }
            "--size" => {
                parsed.size = parse_number(&take_value(&mut args, "--size")?, "--size")?;
            }
            "--interval-ms" => {
                parsed.interval_ms =
                    parse_number(&take_value(&mut args, "--interval-ms")?, "--interval-ms")?;
            }
            "--no-listen" => parsed.listen = false,
            other => return Err(format!("unrecognized argument '{other}'")),
        }
    }
    Ok(parsed)
}

fn take_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{option} needs a value"))
}

fn parse_number<T: std::str::FromStr>(value: &str, option: &str) -> Result<T, String> {
    value
        .parse::<T>()
        .map_err(|_| format!("{option} expects a non-negative decimal integer, got '{value}'"))
}
