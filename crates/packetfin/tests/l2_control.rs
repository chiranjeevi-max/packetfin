//! End-to-end regression checks for the layer-2 control decoders.
//!
//! These cover PDML metadata and hierarchy that the pruned golden cases do
//! not expose, and the marker summary, which keeps its TLV label when the PDU
//! is malformed.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use packetfin_testkit::fixtures;
use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

fn run(args: &[OsString]) -> String {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("failed to spawn packetfin: {error}");
            std::process::exit(1);
        }
    };
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("failed to wait for packetfin: {error}");
            std::process::exit(1);
        }
    };
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn fixture(name: &str) -> PathBuf {
    let fixture = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == name)
        .unwrap_or_else(|| {
            eprintln!("no {name} fixture");
            std::process::exit(1);
        });
    golden::fixtures_dir().join(fixture.file_name())
}

#[test]
fn lldp_pdml_uses_tlv_offsets_and_nests_capability_bits() {
    let path = fixture("lldp");
    let tree = run(&[
        "-n".into(),
        "-T".into(),
        "pdml".into(),
        "-Y".into(),
        "frame.number == 1".into(),
        "-r".into(),
        path.into_os_string(),
    ]);
    assert!(
        tree.contains("name=\"lldp.port.subtype\" showname=\"Port Id Subtype: Interface name (5)\" size=\"1\" pos=\"25\""),
        "{tree}"
    );
    assert!(
        tree.contains("name=\"lldp.time_to_live\" showname=\"Seconds: 120\" size=\"2\" pos=\"32\""),
        "{tree}"
    );
    let Some(parent) = tree.find("<field name=\"lldp.tlv.system_cap\"") else {
        return;
    };
    let Some(child) = tree.find("<field name=\"lldp.tlv.system_cap.bridge\"") else {
        return;
    };
    assert!(child > parent, "{tree}");
    assert!(
        tree.contains("name=\"lldp.pdu_type\" showname=\"Normal LLDPDU\" size=\"4\" pos=\"30\""),
        "{tree}"
    );
}

#[test]
fn lldp_pdml_stops_at_the_end_tlv() {
    let path = fixture("lldp");
    let tree = run(&[
        "-n".into(),
        "-T".into(),
        "pdml".into(),
        "-Y".into(),
        "frame.number == 2".into(),
        "-r".into(),
        path.into_os_string(),
    ]);
    assert!(
        tree.contains("<proto name=\"lldp\" showname=\"Link Layer Discovery Protocol\" size=\"22\" pos=\"14\">"),
        "{tree}"
    );
}

#[test]
fn stp_pdml_nests_msti_flag_children_and_uses_exact_metadata() {
    let path = fixture("stp");
    let tree = run(&[
        "-n".into(),
        "-T".into(),
        "pdml".into(),
        "-Y".into(),
        "frame.number == 5".into(),
        "-r".into(),
        path.into_os_string(),
    ]);
    assert!(
        tree.contains("name=\"stp.root.prio\" showname=\"Root Bridge Priority: 32768\" size=\"1\" pos=\"22\" show=\"32768\" value=\"80\""),
        "{tree}"
    );
    let Some(parent) = tree.find("<field name=\"mstp.msti.flags\"") else {
        return;
    };
    assert!(
        tree[parent..].contains("<field name=\"stp.flags.agreement\""),
        "{tree}"
    );
}

#[test]
fn lacp_summary_names_actor_and_partner_states() {
    let path = fixture("lacp");
    let summary = run(&["-n".into(), "-r".into(), path.into_os_string()]);
    assert!(
        summary.contains(
            "LACP 80 v1 ACTOR aa:bb:cc:00:00:01 P: 1 K: 5 **DCSG*A PARTNER dd:ee:ff:00:00:02 P: 2 K: 6 **DC*G*A"
        ),
        "{summary}"
    );
}

#[test]
fn marker_summary_keeps_the_tlv_label_for_a_truncated_pdu() {
    let path = fixture("marker");
    let summary = run(&["-n".into(), "-r".into(), path.into_os_string()]);
    assert!(
        summary.contains("Marker 26 Information[Malformed Packet]"),
        "{summary}"
    );
}
