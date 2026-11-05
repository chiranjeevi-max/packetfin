//! Manual live-capture probe for the `packetfin-pcap` API.
//!
//! It exercises the public `packetfin-pcap` API the way the CLI will: resolve
//! an interface, list link and timestamp types, compile a filter before
//! creating output, capture until a count, duration or signal, write a pcap
//! file and print counters. This is a proof harness, not a CLI.

use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use packetfin_pcap::{
    CapturedPacket, DEFAULT_SNAPLEN, Linktype, LiveCapture, OpenOptions, StopHandle,
    TimestampPrecision, default_device, devices, format_device_list, resolve_device,
    timestamp_type_from_name,
};

#[derive(Default)]
struct Args {
    device: Option<String>,
    filter: Option<String>,
    output: Option<PathBuf>,
    count: u64,
    seconds: u64,
    snaplen: Option<u32>,
    no_promisc: bool,
    monitor: bool,
    buffer_bytes: Option<u32>,
    link_type: Option<String>,
    tstamp_type: Option<String>,
    timeout_ms: i32,
    install_signals: bool,
    list_devices: bool,
    list_datalinks: bool,
    list_tstamp_types: bool,
    print_packets: bool,
    print_open_latency: bool,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    run(args)
}

fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if args.list_devices {
        let listed = devices()?;
        println!("{}", format_device_list(&listed));
        return Ok(());
    }
    let device = match args.device.as_deref() {
        Some(spec) => resolve_device(spec)?,
        None => default_device()?,
    };
    let options = OpenOptions {
        snaplen: args.snaplen.or(Some(DEFAULT_SNAPLEN)),
        promisc: !args.no_promisc,
        monitor: args.monitor,
        buffer_bytes: args.buffer_bytes,
        link_type: match &args.link_type {
            Some(name) => Some(Linktype::from_name(name)?),
            None => None,
        },
        tstamp_type: match &args.tstamp_type {
            Some(name) => Some(timestamp_type_from_name(name)?),
            None => None,
        },
        timeout_ms: args.timeout_ms,
    };
    let open_started = Instant::now();
    let mut capture = LiveCapture::open(&device, &options)?;
    let open_micros = open_started.elapsed().as_micros();
    for warning in capture.warnings() {
        eprintln!("warning: {warning}");
    }
    if args.list_datalinks {
        for info in capture.link_types()? {
            println!("{}", info.label());
        }
        return Ok(());
    }
    if args.list_tstamp_types {
        for info in capture.timestamp_types()? {
            println!("{}", info.label());
        }
        return Ok(());
    }
    if let Some(filter) = &args.filter {
        capture.set_filter(filter)?;
    }
    println!(
        "capturing device={} snaplen={} link_type={} precision={:?}",
        device.name,
        capture.snaplen(),
        capture.link_type(),
        capture.precision()
    );
    if args.print_open_latency {
        println!("open_us={open_micros}");
    }
    let stop = stop_handle(args.install_signals)?;
    let mut writer = match &args.output {
        Some(path) => Some(PcapWriter::create(
            path,
            capture.snaplen(),
            capture.link_type(),
            capture.precision(),
        )?),
        None => None,
    };
    let started = Instant::now();
    let mut captured = 0_u64;
    let mut bytes = 0_u64;
    loop {
        if stop.is_stopped() {
            break;
        }
        if args.count > 0 && captured >= args.count {
            break;
        }
        if args.seconds > 0 && started.elapsed() >= Duration::from_secs(args.seconds) {
            break;
        }
        if let Some(packet) = capture.next()? {
            if let Some(writer) = writer.as_mut() {
                writer.write_packet(&packet)?;
            }
            if args.print_packets {
                println!(
                    "packet index={captured} len={} caplen={} ts={}.{:09}",
                    packet.original_len,
                    packet.captured_len(),
                    packet.timestamp.seconds,
                    packet.timestamp.nanos
                );
            }
            captured = captured.saturating_add(1);
            bytes = bytes.saturating_add(u64::try_from(packet.captured_len()).unwrap_or(0));
        }
    }
    if let Some(writer) = writer.as_mut() {
        writer.finish()?;
    }
    let stats = capture.stats()?;
    println!(
        "stats received={} dropped={} if_dropped={}",
        stats.received, stats.dropped, stats.interface_dropped
    );
    println!(
        "captured={captured} bytes={bytes} elapsed_ms={} open_us={open_micros}",
        started.elapsed().as_millis()
    );
    Ok(())
}

#[cfg(unix)]
fn stop_handle(install: bool) -> Result<StopHandle, packetfin_pcap::OpenError> {
    if install {
        StopHandle::install_signal_handlers()
    } else {
        StopHandle::new()
    }
}

#[cfg(not(unix))]
fn stop_handle(install: bool) -> Result<StopHandle, packetfin_pcap::OpenError> {
    if install {
        eprintln!("note: signal handlers are Unix-only; use --count or --seconds on this platform");
    }
    StopHandle::new()
}

struct PcapWriter {
    output: BufWriter<File>,
    precision: TimestampPrecision,
}

impl PcapWriter {
    fn create(
        path: &Path,
        snaplen: u32,
        link_type: u32,
        precision: TimestampPrecision,
    ) -> Result<Self, Box<dyn Error>> {
        let file = File::create(path)?;
        let mut output = BufWriter::new(file);
        let magic: u32 = match precision {
            TimestampPrecision::Microsecond => 0xa1b2_c3d4,
            TimestampPrecision::Nanosecond => 0xa1b2_3c4d,
        };
        output.write_all(&magic.to_le_bytes())?;
        output.write_all(&2_u16.to_le_bytes())?;
        output.write_all(&4_u16.to_le_bytes())?;
        output.write_all(&0_i32.to_le_bytes())?;
        output.write_all(&0_u32.to_le_bytes())?;
        output.write_all(&snaplen.to_le_bytes())?;
        output.write_all(&link_type.to_le_bytes())?;
        Ok(Self { output, precision })
    }

    fn write_packet(&mut self, packet: &CapturedPacket<'_>) -> Result<(), Box<dyn Error>> {
        let seconds = u32::try_from(packet.timestamp.seconds).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "timestamp seconds are outside the classic pcap range",
            )
        })?;
        let fraction = match self.precision {
            TimestampPrecision::Microsecond => packet.timestamp.nanos / 1_000,
            TimestampPrecision::Nanosecond => packet.timestamp.nanos,
        };
        let captured = u32::try_from(packet.captured_len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "captured length exceeds 32 bits",
            )
        })?;
        for value in [seconds, fraction, captured, packet.original_len] {
            self.output.write_all(&value.to_le_bytes())?;
        }
        self.output.write_all(packet.data)?;
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        timeout_ms: 100,
        ..Args::default()
    };
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-i" | "--device" => parsed.device = Some(take_value(&mut args, "--device")?),
            "-f" | "--filter" => parsed.filter = Some(take_value(&mut args, "--filter")?),
            "-w" | "--output" => {
                parsed.output = Some(PathBuf::from(take_value(&mut args, "--output")?));
            }
            "-c" | "--count" => {
                parsed.count = parse_number(&take_value(&mut args, "--count")?, "--count")?;
            }
            "-a" | "--seconds" => {
                parsed.seconds = parse_number(&take_value(&mut args, "--seconds")?, "--seconds")?;
            }
            "-s" | "--snaplen" => {
                parsed.snaplen = Some(parse_number(
                    &take_value(&mut args, "--snaplen")?,
                    "--snaplen",
                )?);
            }
            "-p" | "--no-promisc" => parsed.no_promisc = true,
            "-I" | "--monitor" => parsed.monitor = true,
            "-B" | "--buffer-bytes" => {
                parsed.buffer_bytes = Some(parse_number(
                    &take_value(&mut args, "--buffer-bytes")?,
                    "--buffer-bytes",
                )?);
            }
            "-y" | "--link-type" => {
                parsed.link_type = Some(take_value(&mut args, "--link-type")?);
            }
            "--tstamp-type" => {
                parsed.tstamp_type = Some(take_value(&mut args, "--tstamp-type")?);
            }
            "--timeout-ms" => {
                parsed.timeout_ms =
                    parse_number(&take_value(&mut args, "--timeout-ms")?, "--timeout-ms")?;
            }
            "--install-signals" => parsed.install_signals = true,
            "--list-devices" => parsed.list_devices = true,
            "--list-datalinks" => parsed.list_datalinks = true,
            "--list-tstamp-types" => parsed.list_tstamp_types = true,
            "--print-packets" => parsed.print_packets = true,
            "--print-open-latency" => parsed.print_open_latency = true,
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

fn print_usage() {
    println!(
        "usage: live-capture [options]\n\
         \n\
         -i, --device NAME|INDEX   interface to capture (default: first non-loopback)\n\
         -f, --filter EXPR         BPF capture filter\n\
         -w, --output PATH         write a classic pcap file\n\
         -c, --count N             stop after N packets (0: no limit)\n\
         -a, --seconds N           stop after N seconds (0: no limit)\n\
         -s, --snaplen N           snapshot length (0: libpcap default)\n\
         -p, --no-promisc          disable promiscuous mode\n\
         -I, --monitor             request monitor mode\n\
         -B, --buffer-bytes N      kernel capture buffer size\n\
         -y, --link-type NAME      select a link type\n\
             --tstamp-type NAME    select a timestamp type\n\
             --timeout-ms N        wait bound for next (0: until packet or stop)\n\
             --install-signals     stop cleanly on SIGINT/SIGTERM\n\
             --list-devices        print interfaces and exit\n\
             --list-datalinks      print link types for the interface and exit\n\
             --list-tstamp-types   print timestamp types for the interface and exit\n\
             --print-packets       print one line per captured packet\n\
             --print-open-latency  print how long opening took"
    );
}
