//! Server Name Indication extraction for name learning.
//!
//! A TLS ClientHello is not a protocol Packetfin decodes in this slice, but
//! `-N s` learns the server name from one. The parser follows RFC 8446
//! section 4.1.2 and only accepts a complete, unencrypted ClientHello record;
//! a fragmented or malformed hello yields no name.

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let bytes = self.data.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
    }

    fn u24(&mut self) -> Option<usize> {
        let bytes = self.take(3)?;
        Some(
            (usize::from(*bytes.first()?) << 16)
                | (usize::from(*bytes.get(1)?) << 8)
                | usize::from(*bytes.get(2)?),
        )
    }
}

/// Return the server name from a complete TLS ClientHello record at the start
/// of `data`.
pub fn client_hello_sni(data: &[u8]) -> Option<&str> {
    let mut reader = Reader::new(data);
    if reader.u8()? != 22 {
        return None;
    }
    let version = reader.u16()?;
    if version >> 8 != 3 {
        return None;
    }
    let record_length = usize::from(reader.u16()?);
    let record = reader.take(record_length)?;

    let mut handshake = Reader::new(record);
    if handshake.u8()? != 1 {
        return None;
    }
    let hello_length = handshake.u24()?;
    let hello = handshake.take(hello_length)?;

    let mut body = Reader::new(hello);
    body.take(2)?;
    body.take(32)?;
    let session_id_length = usize::from(body.u8()?);
    body.take(session_id_length)?;
    let suites_length = usize::from(body.u16()?);
    body.take(suites_length)?;
    let compression_length = usize::from(body.u8()?);
    body.take(compression_length)?;
    let extensions_length = usize::from(body.u16()?);
    let extensions = body.take(extensions_length)?;

    let mut extensions = Reader::new(extensions);
    while extensions.offset < extensions.data.len() {
        let extension_type = extensions.u16()?;
        let extension_length = usize::from(extensions.u16()?);
        let payload = extensions.take(extension_length)?;
        if extension_type == 0 {
            return parse_server_name(payload);
        }
    }
    None
}

fn parse_server_name(payload: &[u8]) -> Option<&str> {
    let mut reader = Reader::new(payload);
    let list_length = usize::from(reader.u16()?);
    let mut list = Reader::new(reader.take(list_length)?);
    while list.offset < list.data.len() {
        let name_type = list.u8()?;
        let name_length = usize::from(list.u16()?);
        let name = list.take(name_length)?;
        if name_type != 0 {
            continue;
        }
        if name.len() > 255
            || name
                .iter()
                .any(|byte| !byte.is_ascii_graphic() && *byte != b'.')
        {
            return None;
        }
        return std::str::from_utf8(name).ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(server_name: &[u8]) -> Vec<u8> {
        let mut name_entry = Vec::new();
        name_entry.push(0);
        name_entry.extend_from_slice(&u16::try_from(server_name.len()).unwrap_or(0).to_be_bytes());
        name_entry.extend_from_slice(server_name);
        let mut list = Vec::new();
        list.extend_from_slice(&u16::try_from(name_entry.len()).unwrap_or(0).to_be_bytes());
        list.extend_from_slice(&name_entry);
        let mut extension = Vec::new();
        extension.extend_from_slice(&0_u16.to_be_bytes());
        extension.extend_from_slice(&u16::try_from(list.len()).unwrap_or(0).to_be_bytes());
        extension.extend_from_slice(&list);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&2_u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&u16::try_from(extension.len()).unwrap_or(0).to_be_bytes());
        hello.extend_from_slice(&extension);

        let mut handshake = Vec::new();
        handshake.push(1);
        handshake.extend_from_slice(&[
            u8::try_from((hello.len() >> 16) & 0xff).unwrap_or(0),
            u8::try_from((hello.len() >> 8) & 0xff).unwrap_or(0),
            u8::try_from(hello.len() & 0xff).unwrap_or(0),
        ]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap_or(0).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn a_complete_hello_yields_the_server_name() {
        let record = client_hello(b"sni.example");
        assert_eq!(client_hello_sni(&record), Some("sni.example"));
    }

    #[test]
    fn truncated_and_non_hello_records_are_rejected() {
        let record = client_hello(b"sni.example");
        for length in 0..record.len() {
            assert_eq!(client_hello_sni(record.get(..length).unwrap_or(&[])), None);
        }
        assert_eq!(client_hello_sni(&[23, 3, 3, 0, 0]), None);
        assert_eq!(client_hello_sni(&[]), None);
    }
}
