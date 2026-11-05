//! SNMP request/response transaction state.
//!
//! A get-response matches the most recent request with the same
//! request id on the same UDP conversation. The table is bounded by the
//! session ledger; a dropped transaction simply leaves the response
//! unlinked, matching the state-budget warning that follows a loss.

use std::net::IpAddr;

use crate::state::StateValue;

/// One pending SNMP request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SnmpTransaction {
    /// Display frame number of the request.
    pub pending_frame: u32,
    /// Capture frame number of the request.
    pub pending_file: u32,
    /// Capture time of the request in nanoseconds.
    pub pending_time_ns: i64,
}

impl StateValue for SnmpTransaction {
    fn state_bytes(&self) -> usize {
        0
    }
}

/// Unordered conversation endpoints plus the SNMP request id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SnmpTransactionKey {
    pub(crate) client_address: IpAddr,
    pub(crate) client_port: u16,
    pub(crate) server_address: IpAddr,
    pub(crate) request_id: i64,
}

impl SnmpTransactionKey {
    /// Key a message by its unordered UDP endpoints and request id.
    pub(crate) fn new(
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
        request_id: i64,
        response: bool,
    ) -> Self {
        // Only the response source port is a wildcard: the client
        // address/port, the server address and the request id identify the
        // transaction, while a response may arrive from any server port
        // (for example 162 instead of 161). A response from an unrelated
        // server address must not match.
        let (client_address, client_port, server_address) = if response {
            (destination, destination_port, source)
        } else {
            (source, source_port, destination)
        };
        Self {
            client_address,
            client_port,
            server_address,
            request_id,
        }
    }
}
