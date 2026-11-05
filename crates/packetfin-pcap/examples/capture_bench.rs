//! Loopback burst benchmark for the live-capture crate.
//!
//! Measures handle-open latency, packet rate and the per-packet cost of
//! draining a non-blocking capture set while sending a burst of UDP datagrams
//! on loopback. Run it with `cargo run -p packetfin-pcap --example capture_bench`
//! from an account that may capture on loopback.

use std::error::Error;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use packetfin_pcap::{
    CaptureSet, LiveCapture, OpenOptions, StopHandle, buffer_bytes_from_mib, resolve_device,
};

#[derive(Debug)]
struct Args {
    device: String,
    filter: String,
    port: u16,
    count: u64,
    batch: u64,
    size: usize,
    buffer_mib: u64,
    snaplen: u32,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            device: default_loopback().to_owned(),
            filter: "udp port 45999".to_owned(),
            port: 45999,
            count: 2_000,
            batch: 100,
            size: 64,
            buffer_mib: 4,
            snaplen: 65_535,
        }
    }
}

fn default_loopback() -> &'static str {
    if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
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
    if args.count == 0 {
        return Err("--count must be at least 1".into());
    }
    if args.batch == 0 {
        return Err("--batch must be at least 1".into());
    }
    let device = resolve_device(&args.device)?;
    let buffer_bytes = buffer_bytes_from_mib(args.buffer_mib)?;
    let options = OpenOptions {
        snaplen: Some(args.snaplen),
        promisc: false,
        buffer_bytes: Some(buffer_bytes),
        timeout_ms: 1,
        ..OpenOptions::default()
    };
    let open_started = Instant::now();
    let capture = LiveCapture::open_nonblocking(&device, &options)?;
    let open_ns = open_started.elapsed().as_nanos();
    let stop = StopHandle::new()?;
    let mut set = CaptureSet::new(vec![capture], stop)?;
    set.set_filter(&args.filter)?;

    let target = format!("127.0.0.1:{}", args.port);
    // A closed UDP port produces ICMP port-unreachable, which makes later
    // sends fail before they reach the capture filter.
    let _listener = UdpSocket::bind(&target)?;
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.connect(&target)?;
    let mut payload = vec![b'P'; args.size];
    let mut sequence = 0_u64;
    let mut captured = 0_u64;
    let mut bytes = 0_u64;
    let mut send_ns = 0_u128;
    let mut receive_ns = 0_u128;
    let started = Instant::now();
    let deadline = Duration::from_secs(15);
    while captured < args.count && started.elapsed() < deadline {
        let to_send = args.batch.min(args.count - captured);
        let send_started = Instant::now();
        for _ in 0..to_send {
            stamp_sequence(&mut payload, sequence);
            socket.send(&payload)?;
            sequence = sequence.saturating_add(1);
        }
        send_ns = send_ns.saturating_add(send_started.elapsed().as_nanos());
        let mut batch_captured = 0_u64;
        while batch_captured < to_send {
            let receive_started = Instant::now();
            match set.next()? {
                Some((_index, packet)) => {
                    receive_ns = receive_ns.saturating_add(receive_started.elapsed().as_nanos());
                    captured = captured.saturating_add(1);
                    batch_captured = batch_captured.saturating_add(1);
                    bytes = bytes
                        .saturating_add(u64::try_from(packet.captured_len()).unwrap_or(u64::MAX));
                }
                None => {
                    receive_ns = receive_ns.saturating_add(receive_started.elapsed().as_nanos());
                    if set.stop_handle().is_stopped() || started.elapsed() >= deadline {
                        break;
                    }
                }
            }
        }
    }
    let elapsed = started.elapsed();
    let stats = set.stats()?;
    let per_packet = if captured == 0 {
        0
    } else {
        receive_ns / u128::from(captured)
    };
    let rate = if elapsed.as_secs_f64() > 0.0 {
        f64::from(u32::try_from(captured).unwrap_or(u32::MAX)) / elapsed.as_secs_f64()
    } else {
        0.0
    };
    println!(
        "bench device={} filter=\"{}\" target={} count={} captured={} bytes={} open_us={} elapsed_ms={} pps={rate:.0} ns_per_packet={per_packet} send_ns={send_ns} receive_ns={receive_ns}",
        device.name,
        args.filter,
        target,
        args.count,
        captured,
        bytes,
        open_ns / 1_000,
        elapsed.as_millis()
    );
    for (index, stat) in stats.iter().enumerate() {
        println!(
            "interface index={index} received={} dropped={} if_dropped={}",
            stat.received, stat.dropped, stat.interface_dropped
        );
    }
    if captured < args.count {
        return Err(format!("captured {captured} of {} datagrams", args.count).into());
    }
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
                    "usage: capture-bench [--device NAME] [--filter EXPR] [--port N] [--count N] [--batch N] [--size BYTES] [--buffer-mib N] [--snaplen N]"
                );
                std::process::exit(0);
            }
            "--device" => parsed.device = take_value(&mut args, "--device")?,
            "--filter" => parsed.filter = take_value(&mut args, "--filter")?,
            "--port" => parsed.port = parse_number(&take_value(&mut args, "--port")?, "--port")?,
            "--count" => {
                parsed.count = parse_number(&take_value(&mut args, "--count")?, "--count")?;
            }
            "--batch" => {
                parsed.batch = parse_number(&take_value(&mut args, "--batch")?, "--batch")?;
            }
            "--size" => {
                parsed.size = parse_number(&take_value(&mut args, "--size")?, "--size")?;
            }
            "--buffer-mib" => {
                parsed.buffer_mib =
                    parse_number(&take_value(&mut args, "--buffer-mib")?, "--buffer-mib")?;
            }
            "--snaplen" => {
                parsed.snaplen = parse_number(&take_value(&mut args, "--snaplen")?, "--snaplen")?;
            }
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
