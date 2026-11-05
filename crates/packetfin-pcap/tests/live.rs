//! Live loopback checks for `packetfin-pcap`.
//!
//! These are manual: `cargo test` ignores them. Run them on a machine where
//! libpcap can open the loopback interface with
//! `PACKETFIN_LIVE=1 cargo test -p packetfin-pcap --test live -- --ignored --test-threads=1`.
//! They send real UDP datagrams on port 45999, so they never belong in the
//! normal unit-test lane.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use packetfin_pcap::{
    CaptureSet, DeviceError, DeviceInfo, Linktype, LiveCapture, OpenError, OpenOptions,
    OpenWarning, StopHandle, default_device, devices, format_device_list, resolve_device_in,
    timestamp_type_from_name,
};

const PORT: u16 = 45999;
const FILTER: &str = "udp port 45999";

fn enabled() -> bool {
    if std::env::var_os("PACKETFIN_LIVE").is_some() {
        true
    } else {
        eprintln!("PACKETFIN_LIVE is not set; skipping live loopback check");
        false
    }
}

fn loopback() -> DeviceInfo {
    let listed = devices().unwrap_or_else(|error| unreachable!("{error}"));
    if let Some(device) = listed.iter().find(|device| device.loopback) {
        return device.clone();
    }
    unreachable!("no loopback interface in {listed:?}")
}

fn options() -> OpenOptions {
    OpenOptions {
        promisc: false,
        timeout_ms: 10,
        ..OpenOptions::default()
    }
}

fn send_datagrams(count: u64, size: usize) {
    // Keep the destination port open so Linux does not answer with ICMP
    // port-unreachable and fail the next send with ECONNREFUSED.
    let _listener =
        UdpSocket::bind(("127.0.0.1", PORT)).unwrap_or_else(|error| unreachable!("{error}"));
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|error| unreachable!("{error}"));
    socket
        .connect(("127.0.0.1", PORT))
        .unwrap_or_else(|error| unreachable!("{error}"));
    let payload = vec![b'P'; size];
    for _ in 0..count {
        socket
            .send(&payload)
            .unwrap_or_else(|error| unreachable!("{error}"));
    }
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn device_list_and_default_are_consistent() {
    if !enabled() {
        return;
    }
    let listed = devices().unwrap_or_else(|error| unreachable!("{error}"));
    assert!(!listed.is_empty(), "libpcap listed no interfaces");
    assert_eq!(format_device_list(&listed).lines().count(), listed.len());
    let default = default_device().unwrap_or_else(|error| unreachable!("{error}"));
    assert!(
        listed.iter().any(|device| device.name == default.name),
        "default device {} is not in the list",
        default.name
    );
    println!("devices:\n{}", format_device_list(&listed));
    println!("default={} label={}", default.name, default.label());
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn loopback_resolves_by_name_and_one_based_index() {
    if !enabled() {
        return;
    }
    let listed = devices().unwrap_or_else(|error| unreachable!("{error}"));
    let loopback = loopback();
    let position = listed
        .iter()
        .position(|device| device.name == loopback.name)
        .unwrap_or_else(|| unreachable!("loopback missing from the list"))
        .saturating_add(1);
    let by_name =
        resolve_device_in(&listed, &loopback.name).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(by_name.name, loopback.name);
    let by_index = resolve_device_in(&listed, &position.to_string())
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(by_index.name, loopback.name);
    assert!(matches!(
        resolve_device_in(&listed, "0"),
        Err(OpenError::Device(DeviceError::IndexOutOfRange { .. }))
    ));
    assert!(matches!(
        resolve_device_in(&listed, "999999"),
        Err(OpenError::Device(DeviceError::IndexOutOfRange { .. }))
    ));
    assert!(matches!(
        resolve_device_in(&listed, "definitely-not-an-interface"),
        Err(OpenError::Device(DeviceError::NotFound { .. }))
    ));
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn filter_compilation_fails_before_output_and_succeeds_after() {
    if !enabled() {
        return;
    }
    let device = loopback();
    let mut capture =
        LiveCapture::open(&device, &options()).unwrap_or_else(|error| unreachable!("{error}"));
    match capture.set_filter("not a filter") {
        Err(OpenError::Filter { .. }) => {}
        other => unreachable!("expected a filter error, got {other:?}"),
    }
    capture
        .set_filter(FILTER)
        .unwrap_or_else(|error| unreachable!("{error}"));
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn loopback_captures_udp_datagrams() {
    if !enabled() {
        return;
    }
    let device = loopback();
    let mut capture = LiveCapture::open_nonblocking(&device, &options())
        .unwrap_or_else(|error| unreachable!("{error}"));
    capture
        .set_filter(FILTER)
        .unwrap_or_else(|error| unreachable!("{error}"));
    send_datagrams(5, 64);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut lengths = Vec::new();
    while lengths.len() < 5 && Instant::now() < deadline {
        if let Some(packet) = capture
            .next()
            .unwrap_or_else(|error| unreachable!("{error}"))
        {
            assert!(
                packet.captured_len() > 64,
                "loopback capture did not include the link and IP headers: {}",
                packet.captured_len()
            );
            assert_eq!(
                packet.original_len,
                u32::try_from(packet.captured_len()).unwrap_or(0)
            );
            assert!(packet.timestamp.seconds > 1_600_000_000);
            lengths.push(packet.captured_len());
        }
    }
    assert_eq!(lengths.len(), 5, "captured only {lengths:?}");
    let stats = capture
        .stats()
        .unwrap_or_else(|error| unreachable!("{error}"));
    println!(
        "lengths={lengths:?} received={} dropped={} if_dropped={}",
        stats.received, stats.dropped, stats.interface_dropped
    );
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn capture_set_reads_one_or_more_interfaces() {
    if !enabled() {
        return;
    }
    let device = loopback();
    let stop = StopHandle::new().unwrap_or_else(|error| unreachable!("{error}"));
    let mut set = CaptureSet::open(&[device.clone(), device.clone()], &options(), stop)
        .unwrap_or_else(|error| unreachable!("{error}"));
    set.set_filter(FILTER)
        .unwrap_or_else(|error| unreachable!("{error}"));
    send_datagrams(20, 64);
    std::thread::sleep(Duration::from_millis(50));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = 0_u64;
    let mut indexes = Vec::new();
    while seen < 20 && Instant::now() < deadline {
        if let Some((index, packet)) = set.next().unwrap_or_else(|error| unreachable!("{error}")) {
            assert!(index < 2);
            assert_eq!(packet.device.name, device.name);
            indexes.push(index);
            seen = seen.saturating_add(1);
        }
    }
    assert!(seen >= 20, "captured only {seen} of 20 datagrams");
    let stats = set.stats().unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(stats.len(), 2);
    println!("seen={seen} indexes={indexes:?} stats={stats:?}");
    assert!(
        indexes.contains(&0) && indexes.contains(&1),
        "round-robin did not read both handles: {indexes:?} stats={stats:?}"
    );
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn stop_handle_ends_an_idle_set() {
    if !enabled() {
        return;
    }
    let device = loopback();
    let stop = StopHandle::new().unwrap_or_else(|error| unreachable!("{error}"));
    let mut set = CaptureSet::open(&[device], &options(), stop.clone())
        .unwrap_or_else(|error| unreachable!("{error}"));
    let started = Instant::now();
    stop.request_stop();
    assert!(
        set.next()
            .unwrap_or_else(|error| unreachable!("{error}"))
            .is_none()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn snaplen_buffer_and_promiscuous_options() {
    if !enabled() {
        return;
    }
    let device = loopback();
    let default_capture =
        LiveCapture::open(&device, &options()).unwrap_or_else(|error| unreachable!("{error}"));
    assert!(default_capture.snaplen() > 0);
    let explicit = LiveCapture::open(
        &device,
        &OpenOptions {
            snaplen: Some(40),
            promisc: false,
            timeout_ms: 10,
            ..OpenOptions::default()
        },
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(explicit.snaplen(), 40);
    let zero = LiveCapture::open(
        &device,
        &OpenOptions {
            snaplen: Some(0),
            promisc: false,
            timeout_ms: 10,
            ..OpenOptions::default()
        },
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(zero.snaplen() > 0);
    let zero_buffer = LiveCapture::open(
        &device,
        &OpenOptions {
            buffer_bytes: Some(0),
            promisc: false,
            timeout_ms: 10,
            ..OpenOptions::default()
        },
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(zero_buffer.snaplen() > 0);
    println!(
        "snaplen default={} explicit={} zero={} zero_buffer={}",
        default_capture.snaplen(),
        explicit.snaplen(),
        zero.snaplen(),
        zero_buffer.snaplen()
    );
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn link_and_timestamp_types_are_listed() {
    if !enabled() {
        return;
    }
    let device = loopback();
    let capture =
        LiveCapture::open(&device, &options()).unwrap_or_else(|error| unreachable!("{error}"));
    let links = capture
        .link_types()
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(!links.is_empty());
    assert!(links.iter().any(|link| link.value == capture.link_type()));
    let types = capture
        .timestamp_types()
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(!types.is_empty());
    assert!(types.iter().any(|info| info.name == "host"));
    println!(
        "links={:?} tstamps={:?}",
        links.iter().map(|link| link.label()).collect::<Vec<_>>(),
        types.iter().map(|info| info.label()).collect::<Vec<_>>()
    );
    assert_eq!(timestamp_type_from_name("host"), Ok(0));
    assert!(timestamp_type_from_name("not-a-timestamp-type").is_err());
    assert!(matches!(
        Linktype::from_name("NOT_A_LINKTYPE"),
        Err(OpenError::LinkType { .. })
    ));
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn monitor_mode_on_loopback_is_rejected() {
    if !enabled() {
        return;
    }
    let device = loopback();
    let result = LiveCapture::open(
        &device,
        &OpenOptions {
            monitor: true,
            promisc: false,
            timeout_ms: 10,
            ..OpenOptions::default()
        },
    );
    match result {
        Err(OpenError::Monitor { .. } | OpenError::Open { .. }) => {}
        other => unreachable!("expected monitor mode to fail on loopback, got {other:?}"),
    }
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn promiscuous_unsupported_is_a_warning() {
    if !enabled() {
        return;
    }
    let listed = devices().unwrap_or_else(|error| unreachable!("{error}"));
    let mut checked = false;
    for name in ["awdl0", "llw0", "anpi2", "any"] {
        let Some(device) = listed.iter().find(|device| device.name == name) else {
            continue;
        };
        let capture = match LiveCapture::open(
            device,
            &OpenOptions {
                promisc: true,
                timeout_ms: 10,
                ..OpenOptions::default()
            },
        ) {
            Ok(capture) => capture,
            Err(error) => {
                eprintln!("{name}: open failed: {error}");
                continue;
            }
        };
        if capture.warnings().is_empty() {
            continue;
        }
        assert!(matches!(
            capture.warnings().first(),
            Some(OpenWarning::PromiscuousNotSupported { .. })
        ));
        let plain = LiveCapture::open(
            device,
            &OpenOptions {
                promisc: false,
                timeout_ms: 10,
                ..OpenOptions::default()
            },
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(
            plain.warnings().is_empty(),
            "-p still reported {:?}",
            plain.warnings()
        );
        println!("{} warnings={:?}", device.name, capture.warnings());
        checked = true;
        break;
    }
    if cfg!(target_os = "macos") {
        assert!(
            checked,
            "expected a macOS interface (awdl0/llw0/anpi2) to reject promiscuous mode"
        );
    } else if !checked {
        eprintln!("no interface rejected promiscuous mode; check skipped");
    }
}

#[test]
#[ignore = "live loopback capture; needs PACKETFIN_LIVE=1 and --ignored"]
fn unnamed_link_types_use_the_dlt_fallback() {
    if !enabled() {
        return;
    }
    let listed = devices().unwrap_or_else(|error| unreachable!("{error}"));
    let mut checked = false;
    for name in ["awdl0", "nan0"] {
        let Some(device) = listed.iter().find(|device| device.name == name) else {
            continue;
        };
        let capture = match LiveCapture::open(
            device,
            &OpenOptions {
                promisc: false,
                timeout_ms: 10,
                ..OpenOptions::default()
            },
        ) {
            Ok(capture) => capture,
            Err(error) => {
                eprintln!("{name}: open failed: {error}");
                continue;
            }
        };
        for link in capture
            .link_types()
            .unwrap_or_else(|error| unreachable!("{error}"))
        {
            if link.name.starts_with("DLT ") {
                assert_eq!(link.description, "not supported");
                assert_eq!(link.label(), format!("{} (not supported)", link.name));
                checked = true;
                println!("{} -> {}", device.name, link.label());
            }
        }
    }
    if cfg!(target_os = "macos") {
        assert!(checked, "expected an unnamed DLT on awdl0 or nan0");
    } else if !checked {
        eprintln!("no unnamed DLT found; check skipped");
    }
}
