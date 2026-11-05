//! DNS transaction state shared by DNS, mDNS and LLMNR.
//!
//! DNS and mDNS transactions are keyed by the unordered address/port pair of
//! their UDP conversation and the DNS transaction id: a query and response
//! match when their conversation tuples are the same pair and the id matches,
//! while the question name and type do not participate (a response whose
//! question differs still links to the query).
//! LLMNR matches on the querier endpoint and service port only, so the usual
//! multicast query from the client and unicast response from another host
//! share a transaction; see [`DnsTransactionKey::llmnr`].
//!
//! Entries hold the pending query and the last response frame so the
//! dissector can classify a later identical query or response as a
//! retransmission.

use std::net::IpAddr;

use crate::state::StateValue;

/// Requests remembered per transaction.
///
/// A response link is recorded on every request of a transaction,
/// including its retransmissions. The cap keeps a hostile repeated-query
/// stream from retaining an unbounded list; later retransmissions still
/// classify correctly but do not receive their own response link.
pub(crate) const MAX_TRANSACTION_REQUESTS: usize = 8;

/// The normalized conversation and transaction id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum DnsTransactionKey {
    /// DNS and mDNS: the unordered address/port pair plus the id.
    Pair {
        first_address: IpAddr,
        first_port: u16,
        second_address: IpAddr,
        second_port: u16,
        id: u16,
    },
    /// LLMNR: the querier endpoint, the service port and the id.
    Llmnr {
        client_address: IpAddr,
        client_port: u16,
        service_port: u16,
        id: u16,
    },
}

impl DnsTransactionKey {
    /// Key a DNS or mDNS message.
    ///
    /// Endpoints are ordered by address and port, so a query in one direction
    /// and a response in the other produce the same key without assuming
    /// which side is the client.
    pub(crate) fn pair(
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
        id: u16,
    ) -> Self {
        let source_endpoint = (source, source_port);
        let destination_endpoint = (destination, destination_port);
        let (first, second) = if source_endpoint <= destination_endpoint {
            (source_endpoint, destination_endpoint)
        } else {
            (destination_endpoint, source_endpoint)
        };
        Self::Pair {
            first_address: first.0,
            first_port: first.1,
            second_address: second.0,
            second_port: second.1,
            id,
        }
    }

    /// Key an LLMNR message.
    ///
    /// The querier endpoint and the service port identify the transaction;
    /// the responder address is deliberately absent so the normal multicast
    /// query and unicast response from another host link. A query and a
    /// response compute the same key by swapping source and destination.
    pub(crate) fn llmnr(
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
        id: u16,
        response: bool,
    ) -> Self {
        let (client_address, client_port, service_port) = if response {
            (destination, destination_port, source_port)
        } else {
            (source, source_port, destination_port)
        };
        Self::Llmnr {
            client_address,
            client_port,
            service_port,
            id,
        }
    }
}

/// Retained state for one DNS transaction.
///
/// Frame references come in pairs: the pass-one display number for the tree
/// being decoded and the capture number for annotations and budget keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DnsTransaction {
    /// Display frame number of the earliest unanswered query, or zero.
    pub pending_frame: u32,
    /// Capture frame number of that query.
    pub pending_file: u32,
    /// Capture time of that query in nanoseconds.
    pub pending_time_ns: i64,
    /// Display request frames of the transaction, oldest first.
    requests: [u32; MAX_TRANSACTION_REQUESTS],
    /// Capture request frames, parallel to `requests`.
    request_files: [u32; MAX_TRANSACTION_REQUESTS],
    /// Number of entries in the request arrays.
    request_count: u8,
    /// Display frame of the first response, or zero.
    pub last_response_frame: u32,
    /// Capture frame of the transaction's original query.
    pub original_request_file: u32,
    /// Capture time of that query in nanoseconds.
    pub original_request_time_ns: i64,
}

impl Default for DnsTransaction {
    fn default() -> Self {
        Self {
            pending_frame: 0,
            pending_file: 0,
            pending_time_ns: 0,
            requests: [0; MAX_TRANSACTION_REQUESTS],
            request_files: [0; MAX_TRANSACTION_REQUESTS],
            request_count: 0,
            last_response_frame: 0,
            original_request_file: 0,
            original_request_time_ns: 0,
        }
    }
}

impl DnsTransaction {
    /// Start a new pending transaction at `frame`.
    pub(crate) fn start(&mut self, frame: u32, file: u32, time_ns: i64) {
        self.pending_frame = frame;
        self.pending_file = file;
        self.pending_time_ns = time_ns;
        self.request_count = 1;
        self.requests[0] = frame;
        self.request_files[0] = file;
        self.original_request_file = file;
        self.original_request_time_ns = time_ns;
    }

    /// Remember one more retransmitted request.
    pub(crate) fn push_request(&mut self, frame: u32, file: u32) {
        let index = usize::from(self.request_count);
        if let Some(slot) = self.requests.get_mut(index) {
            *slot = frame;
            if let Some(file_slot) = self.request_files.get_mut(index) {
                *file_slot = file;
            }
            self.request_count = self.request_count.saturating_add(1);
        }
    }

    /// The capture request frames, oldest first.
    pub(crate) fn request_files(&self) -> &[u32] {
        self.request_files
            .get(..usize::from(self.request_count))
            .unwrap_or_default()
    }

    /// Clear the pending request after a response matched.
    pub(crate) fn clear_pending(&mut self, response_frame: u32) {
        self.pending_frame = 0;
        self.pending_file = 0;
        self.pending_time_ns = 0;
        self.request_count = 0;
        self.last_response_frame = response_frame;
    }
}

impl StateValue for DnsTransaction {
    fn state_bytes(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn address(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn a_query_and_reversed_response_share_one_pair_key() {
        let query = DnsTransactionKey::pair(address(1), 49_152, address(2), 53, 0x1234);
        let response = DnsTransactionKey::pair(address(2), 53, address(1), 49_152, 0x1234);
        assert_eq!(query, response);
    }

    #[test]
    fn pair_keys_include_ports_and_the_transaction_id() {
        let base = DnsTransactionKey::pair(address(1), 49_152, address(2), 53, 0x1234);
        assert_ne!(
            base,
            DnsTransactionKey::pair(address(1), 49_153, address(2), 53, 0x1234)
        );
        assert_ne!(
            base,
            DnsTransactionKey::pair(address(1), 49_152, address(2), 53, 0x1235)
        );
    }

    #[test]
    fn llmnr_ignores_the_responder_address() {
        let query = DnsTransactionKey::llmnr(
            address(1),
            5355,
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 252)),
            5355,
            0x0abc,
            false,
        );
        let unicast_response =
            DnsTransactionKey::llmnr(address(9), 5355, address(1), 5355, 0x0abc, true);
        assert_eq!(query, unicast_response);

        let self_response = DnsTransactionKey::llmnr(
            address(1),
            5355,
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 252)),
            5355,
            0x0abc,
            true,
        );
        assert_ne!(query, self_response);
    }
}
