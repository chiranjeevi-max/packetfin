//! Object names and the sink interface for `--export-objects`.
//!
//! Object names follow these rules:
//!
//! * the object name is the request URI's basename: every trailing `/` is
//!   dropped and the text after the last `/` is used; an empty basename
//!   becomes `%2f`. Scheme and authority are not stripped, so
//!   `http://host` becomes `host`, not `%2f`;
//! * a response without a request uses `object<frame>` plus, when a
//!   Content-Type header is present, `.` and the lowercased media type up to
//!   `;` or ASCII whitespace;
//! * bytes that Windows forbids in a file name (`" * : < > ? \ |` plus `/`)
//!   and control bytes are percent-encoded with lowercase hex; existing
//!   `%XX` sequences are kept verbatim, never decoded;
//! * names are at most 255 bytes and the suffix from the last `.` is kept
//!   when it leaves room for at least one stem byte;
//! * a collision appends `(1)`, `(2)`, ... before that suffix, shrinking the
//!   stem so the 255-byte cap still holds.
//!
//! Two security rules apply as well: a literal `.` or `..` name becomes
//! `%2e`/`%2e%2e`, and DEL plus non-ASCII bytes are percent-encoded rather
//! than passed through, so a diagnostic or directory listing cannot carry
//! terminal controls or invalid UTF-8. The result is always exactly one path
//! component.

/// Longest exported object name in bytes, the usual file-system name limit.
pub const MAX_OBJECT_NAME_BYTES: usize = 255;

/// Largest body written for one object.
///
/// Packetfin streams object bodies, but a hostile capture must still not fill
/// the disk without bound; an object over this limit is refused with one
/// diagnostic. A single 64 KiB TCP payload can exceed it through
/// decompression (a 65,250-byte gzip stream expands past 64 MiB), and
/// reassembled bodies reach it directly.
pub const MAX_EXPORT_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Number of collision suffixes probed after the base name before an object
/// is abandoned.
///
/// The base name plus this many `(N)` candidates are tried; the cap bounds
/// the directory probes a hostile capture can force.
pub const MAX_OBJECT_COLLISIONS: u32 = 1000;

/// A sanitized, length-capped object name.
///
/// The name never contains a path separator, a NUL, or a `.`/`..` component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectName {
    base: String,
}

impl ObjectName {
    /// Derive the name from a request URI's basename.
    pub fn from_request_uri(uri: &str) -> Self {
        let path = uri.trim_end_matches('/').as_bytes();
        let basename = match path.iter().rposition(|byte| *byte == b'/') {
            Some(index) => path.get(index.saturating_add(1)..).unwrap_or(&[]),
            None => path,
        };
        let basename = if basename.is_empty() {
            b"%2f".as_slice()
        } else {
            basename
        };
        Self {
            base: capped(component(basename)),
        }
    }

    /// Derive the fallback name for a response with no matching request.
    ///
    /// `content_type` is the header value exactly as parsed; `None` means the
    /// header was absent and no dot is added, while an empty value keeps a
    /// trailing dot (`object20.`).
    pub fn fallback(frame: u64, content_type: Option<&str>) -> Self {
        let mut base = format!("object{frame}");
        if let Some(value) = content_type {
            base.push('.');
            base.push_str(&sanitize_lowercase(media_type(value).as_bytes()));
        }
        Self { base: capped(base) }
    }

    /// The final name, one path component below the export directory.
    pub fn as_str(&self) -> &str {
        &self.base
    }

    /// The candidate name for the `index`-th collision.
    ///
    /// Index zero is the base name. The suffix is inserted before the last
    /// extension and the stem shrinks as needed, keeping the 255-byte cap.
    pub fn with_collision(&self, index: u32) -> String {
        if index == 0 {
            return self.base.clone();
        }
        let suffix = format!("({index})");
        let extension_start = self.base.rfind('.').unwrap_or(self.base.len());
        let stem = self.base.get(..extension_start).unwrap_or(&self.base);
        let extension = self.base.get(extension_start..).unwrap_or("");
        let budget = MAX_OBJECT_NAME_BYTES.saturating_sub(suffix.len());
        let mut name = String::with_capacity(MAX_OBJECT_NAME_BYTES);
        if extension.len() < budget {
            let keep = budget.saturating_sub(extension.len());
            name.push_str(stem.get(..keep).unwrap_or(stem));
            name.push_str(&suffix);
            name.push_str(extension);
        } else {
            // A pathological extension leaves no room; the suffix wins.
            name.push_str(stem.get(..budget).unwrap_or(stem));
            name.push_str(&suffix);
        }
        name
    }
}

/// Receives decoded HTTP message bodies for object export.
///
/// The decoder owns when an object begins and ends; the implementation owns
/// file naming collisions, writing and commit. `begin` returning false skips
/// the writes and the commit.
pub trait ObjectSink {
    /// Begin one object. `expected` is the body length when known.
    fn begin(&mut self, name: &ObjectName, expected: Option<u64>) -> bool;

    /// Write a piece of the body. A failed write makes the later commit a
    /// no-op.
    fn write(&mut self, data: &[u8]);

    /// Finish the object and publish it.
    fn commit(&mut self);

    /// Discard the object without publishing it.
    fn abort(&mut self);

    /// Discard an object the decoder refused before completion.
    ///
    /// The decoder calls this when a known body exceeds
    /// [`MAX_EXPORT_OBJECT_BYTES`] during decompression. The default aborts
    /// silently; a sink that can report why should override it.
    fn refuse(&mut self) {
        self.abort();
    }
}

/// The media type of a Content-Type value: up to `;` or ASCII whitespace.
fn media_type(value: &str) -> &str {
    let without_parameters = value.split(';').next().unwrap_or("");
    let end = without_parameters
        .bytes()
        .position(|byte| byte.is_ascii_whitespace())
        .unwrap_or(without_parameters.len());
    without_parameters.get(..end).unwrap_or("")
}

/// Percent-encode unsafe bytes and map the two directory names.
fn component(bytes: &[u8]) -> String {
    let name = sanitize(bytes);
    match name.as_str() {
        "." => "%2e".to_string(),
        ".." => "%2e%2e".to_string(),
        _ => name,
    }
}

/// Percent-encode every byte outside the safe file-name set.
fn sanitize(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        push_encoded(&mut out, *byte);
    }
    out
}

/// Percent-encode like [`sanitize`], lowercasing ASCII first.
///
/// The fallback media type is lowercased, including existing `%XX`
/// sequences, before it is used in a name.
fn sanitize_lowercase(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        push_encoded(&mut out, byte.to_ascii_lowercase());
    }
    out
}

fn push_encoded(out: &mut String, byte: u8) {
    if is_safe(byte) {
        out.push(char::from(byte));
    } else {
        out.push('%');
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
}

/// Whether `byte` survives verbatim.
///
/// The excluded bytes are the set Windows rejects plus `/`, control
/// characters, DEL and non-ASCII bytes (the last two for diagnostic safety).
fn is_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b';'
                | b'='
                | b'@'
                | b'['
                | b']'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'}'
                | b'~'
        )
}

fn hex_digit(nibble: u8) -> char {
    char::from(if nibble < 10 {
        b'0'.saturating_add(nibble)
    } else {
        b'a'.saturating_add(nibble.saturating_sub(10))
    })
}

/// Apply the 255-byte cap, preserving the last extension when it fits.
///
/// `name` is ASCII by construction, so byte slicing is also character
/// slicing.
fn capped(mut name: String) -> String {
    if name.len() <= MAX_OBJECT_NAME_BYTES {
        return name;
    }
    if let Some(dot) = name.rfind('.')
        && let Some(extension) = name.get(dot..)
        && extension.len() < MAX_OBJECT_NAME_BYTES
    {
        let keep = MAX_OBJECT_NAME_BYTES.saturating_sub(extension.len());
        if let Some(stem) = name.get(..keep) {
            let mut capped = String::with_capacity(MAX_OBJECT_NAME_BYTES);
            capped.push_str(stem);
            capped.push_str(extension);
            return capped;
        }
    }
    name.truncate(MAX_OBJECT_NAME_BYTES);
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_for(uri: &str) -> String {
        ObjectName::from_request_uri(uri).as_str().to_string()
    }

    #[test]
    fn uri_basenames_use_last_path_segment() {
        assert_eq!(name_for("/normal.txt"), "normal.txt");
        assert_eq!(name_for("/dir/"), "dir");
        assert_eq!(name_for("/"), "%2f");
        assert_eq!(name_for("http://other.test/abs.txt"), "abs.txt");
        assert_eq!(name_for("HTTPS://other.test/abs.txt"), "abs.txt");
        assert_eq!(name_for("//double//slash//name.txt"), "name.txt");
        assert_eq!(name_for("http://other.test"), "other.test");
        assert_eq!(name_for("http://host"), "host");
        assert_eq!(name_for("http://host/"), "host");
        assert_eq!(name_for("http://host?a"), "host%3fa");
        assert_eq!(name_for("http://"), "http%3a");
        assert_eq!(name_for("/a//"), "a");
        assert_eq!(name_for("/a///"), "a");
        assert_eq!(name_for("////"), "%2f");
        assert_eq!(name_for("/x?q=1#frag"), "x%3fq=1#frag");
        assert_eq!(name_for("/raw\\back\\slash.txt"), "raw%5cback%5cslash.txt");
        assert_eq!(name_for("/CON"), "CON");
        assert_eq!(name_for("/file."), "file.");
        assert_eq!(name_for("/caf%C3%A9.txt"), "caf%C3%A9.txt");
        assert_eq!(name_for("/new%0aline"), "new%0aline");
        assert_eq!(name_for("/pct%2Fslash"), "pct%2Fslash");
    }

    #[test]
    fn unsafe_bytes_are_percent_encoded() {
        assert_eq!(name_for("/a%22b"), "a%22b");
        assert_eq!(name_for("/a*b"), "a%2ab");
        assert_eq!(name_for("/a:b"), "a%3ab");
        assert_eq!(name_for("/a<b"), "a%3cb");
        assert_eq!(name_for("/a>b"), "a%3eb");
        assert_eq!(name_for("/a?b"), "a%3fb");
        assert_eq!(name_for("/a\\b"), "a%5cb");
        assert_eq!(name_for("/a|b"), "a%7cb");
        assert_eq!(name_for("/a\tb"), "a%09b");
        assert_eq!(name_for("/caf\u{e9}.txt"), "caf%c3%a9.txt");
    }

    #[test]
    fn safe_bytes_survive() {
        let safe = "a!#$%&'()+,-.;=@[]^_`{}~Z09b";
        assert_eq!(name_for(&format!("/{safe}")), safe);
    }

    #[test]
    fn dot_names_are_never_directory_components() {
        assert_eq!(name_for("/."), "%2e");
        assert_eq!(name_for("/.."), "%2e%2e");
        assert_eq!(name_for("/../../etc/passwd"), "passwd");
        assert_eq!(name_for("/a/..%2f..%2fetc"), "..%2f..%2fetc");
    }

    #[test]
    fn fallback_names_use_frame_and_media_type() {
        assert_eq!(ObjectName::fallback(12, None).as_str(), "object12");
        assert_eq!(
            ObjectName::fallback(2, Some("text/html")).as_str(),
            "object2.text%2fhtml"
        );
        assert_eq!(
            ObjectName::fallback(3, Some("text/html; charset=UTF-8")).as_str(),
            "object3.text%2fhtml"
        );
        assert_eq!(ObjectName::fallback(4, Some("")).as_str(), "object4.");
        assert_eq!(ObjectName::fallback(5, Some(";x")).as_str(), "object5.");
        assert_eq!(
            ObjectName::fallback(6, Some("a b/c d")).as_str(),
            "object6.a"
        );
        assert_eq!(
            ObjectName::fallback(7, Some("application/octet-stream")).as_str(),
            "object7.application%2foctet-stream"
        );
        assert_eq!(
            ObjectName::fallback(8, Some("../..%2fetc")).as_str(),
            "object8...%2f..%2fetc"
        );
        assert_eq!(
            ObjectName::fallback(9, Some("tex\ttab")).as_str(),
            "object9.tex"
        );
        assert_eq!(
            ObjectName::fallback(10, Some("a:b*c?d\"e<f>g|h\\i/j")).as_str(),
            "object10.a%3ab%2ac%3fd%22e%3cf%3eg%7ch%5ci%2fj"
        );
        assert_eq!(
            ObjectName::fallback(11, Some("TEXT/HTML")).as_str(),
            "object11.text%2fhtml"
        );
        assert_eq!(
            ObjectName::fallback(12, Some("TeXt/PlAiN; A=B")).as_str(),
            "object12.text%2fplain"
        );
        assert_eq!(
            ObjectName::fallback(13, Some("A%2FB")).as_str(),
            "object13.a%2fb"
        );
    }

    #[test]
    fn name_cap_preserves_the_last_extension() {
        let long = format!("{}.txt", "L".repeat(400));
        let capped = name_for(&format!("/{long}"));
        assert_eq!(capped.len(), MAX_OBJECT_NAME_BYTES);
        assert_eq!(capped, format!("{}.txt", "L".repeat(251)));

        let archives = format!("{}.tar.gz", "e".repeat(300));
        let capped = name_for(&format!("/{archives}"));
        assert_eq!(capped.len(), MAX_OBJECT_NAME_BYTES);
        assert_eq!(capped, format!("{}.gz", "e".repeat(252)));

        let extensionless = "n".repeat(400);
        assert_eq!(name_for(&format!("/{extensionless}")), "n".repeat(255));

        // An extension that cannot leave a stem is not preserved.
        let pathological = format!("a.{}", "b".repeat(300));
        let capped = name_for(&format!("/{pathological}"));
        assert_eq!(capped.len(), MAX_OBJECT_NAME_BYTES);
        assert_eq!(capped, pathological.get(..255).unwrap_or(""));
    }

    #[test]
    fn collision_suffixes_keep_the_cap() {
        let long = ObjectName::from_request_uri(&format!("/{}.txt", "a".repeat(250)));
        let first = long.with_collision(1);
        assert_eq!(first.len(), MAX_OBJECT_NAME_BYTES);
        assert_eq!(first, format!("{}(1).txt", "a".repeat(248)));

        let extensionless = ObjectName::from_request_uri(&format!("/{}", "n".repeat(255)));
        let first = extensionless.with_collision(1);
        assert_eq!(first.len(), MAX_OBJECT_NAME_BYTES);
        assert_eq!(first, format!("{}(1)", "n".repeat(252)));

        let dotted = ObjectName::from_request_uri("/dup.txt");
        assert_eq!(dotted.with_collision(0), "dup.txt");
        assert_eq!(dotted.with_collision(1), "dup(1).txt");
        assert_eq!(dotted.with_collision(22), "dup(22).txt");

        // A leading dot is an extension with an empty stem.
        let hidden = ObjectName::from_request_uri("/.txt");
        assert_eq!(hidden.as_str(), ".txt");
        assert_eq!(hidden.with_collision(1), "(1).txt");
    }

    #[test]
    fn names_are_always_one_safe_component() {
        let hostile = [
            "",
            ".",
            "..",
            "/",
            "//",
            "/../../../../etc/passwd",
            "/a\\b",
            "/a/b",
            "/\u{0}\u{1}\u{1b}[31m",
            "/caf\u{e9}.txt",
            "/CON",
            "http://x/..",
            "http://x",
        ];
        for uri in hostile {
            let name = ObjectName::from_request_uri(uri);
            let text = name.as_str();
            assert!(!text.is_empty(), "URI {uri:?}");
            assert!(text.len() <= MAX_OBJECT_NAME_BYTES, "URI {uri:?}");
            assert!(!text.contains('/'), "URI {uri:?}: {text}");
            assert!(!text.contains('\\'), "URI {uri:?}: {text}");
            assert!(!text.contains('\0'), "URI {uri:?}: {text}");
            assert!(
                text.bytes().all(|byte| byte.is_ascii()),
                "URI {uri:?}: {text}"
            );
            assert_ne!(text, ".", "URI {uri:?}");
            assert_ne!(text, "..", "URI {uri:?}");
            for index in [0, 1, 999] {
                let candidate = name.with_collision(index);
                assert!(candidate.len() <= MAX_OBJECT_NAME_BYTES, "URI {uri:?}");
                assert!(!candidate.contains('/'), "URI {uri:?}: {candidate}");
                assert!(!candidate.contains('\\'), "URI {uri:?}: {candidate}");
            }
        }
    }
}
