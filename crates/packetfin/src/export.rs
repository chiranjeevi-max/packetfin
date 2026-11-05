//! `--export-objects` destination handling.
//!
//! The decoder hands bodies to [`ObjectWriter`] as they are parsed; this
//! module owns the filesystem side. Each object streams to a unique temporary
//! file in the destination directory and is published with `hard_link`, which
//! fails instead of overwriting and never follows a symlink at the final
//! path. A filesystem without hard links falls back to `create_new` plus a
//! copy. Rules:
//!
//! * Nothing is overwritten: an existing file, directory or symlink makes the
//!   writer try `name(1).ext`, `name(2).ext`, and so on.
//! * The destination is created recursively with mode 0755 and objects are
//!   written with mode 0644; failure to create it prints one diagnostic and
//!   the run still exits 0.
//! * A body that cannot be completed produces no file, so a temporary file is
//!   removed on abort.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use packetfin_core::export::{
    MAX_EXPORT_OBJECT_BYTES, MAX_OBJECT_COLLISIONS, ObjectName, ObjectSink,
};

/// Creates the export directory and writes HTTP objects into it.
pub struct ObjectWriter {
    directory: Option<PathBuf>,
    sequence: u64,
    active: Option<ActiveObject>,
}

struct ActiveObject {
    temporary: PathBuf,
    file: File,
    name: ObjectName,
    written: u64,
}

impl ObjectWriter {
    /// Create `directory` recursively, or return a disabled writer.
    ///
    /// The directory is created before reading frames but after opening
    /// the capture, and a failure to create it is not an exit status.
    pub fn setup(directory: &Path) -> Self {
        match create_directory(directory) {
            Ok(()) => Self {
                directory: Some(directory.to_path_buf()),
                sequence: 0,
                active: None,
            },
            Err(error) => {
                crate::diagnostic(&format!(
                    "cannot create export objects directory \"{}\": {error}",
                    directory.display()
                ));
                Self {
                    directory: None,
                    sequence: 0,
                    active: None,
                }
            }
        }
    }

    /// Announce a failed write and remove the partial object.
    fn discard(&mut self, active: ActiveObject, message: &str) {
        let _ = fs::remove_file(&active.temporary);
        crate::diagnostic(message);
    }
}

/// Create one unique temporary file in `directory`.
fn create_temporary(directory: &Path, sequence: &mut u64) -> Option<(PathBuf, File)> {
    for _ in 0..MAX_OBJECT_COLLISIONS {
        *sequence = sequence.wrapping_add(1);
        let name = format!(".packetfin-{}-{}.part", std::process::id(), sequence);
        let path = directory.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        match options.open(&path) {
            Ok(file) => return Some((path, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                crate::diagnostic(&format!(
                    "cannot create a temporary object file in \"{}\": {error}",
                    directory.display()
                ));
                return None;
            }
        }
    }
    crate::diagnostic(&format!(
        "cannot create a temporary object file in \"{}\": no free name",
        directory.display()
    ));
    None
}

impl ObjectSink for ObjectWriter {
    fn begin(&mut self, name: &ObjectName, expected: Option<u64>) -> bool {
        if self.directory.is_none() {
            return false;
        }
        // The decoder commits or aborts every object before the next one; a
        // leftover can only come from a future caller bug, so drop it rather
        // than leak the temporary file.
        self.abort();
        if let Some(expected) = expected
            && expected > MAX_EXPORT_OBJECT_BYTES
        {
            crate::diagnostic(&format!(
                "object \"{}\" is larger than the {MAX_EXPORT_OBJECT_BYTES}-byte export limit",
                name.as_str()
            ));
            return false;
        }
        let Some(directory) = self.directory.as_deref() else {
            return false;
        };
        let Some((temporary, file)) = create_temporary(directory, &mut self.sequence) else {
            return false;
        };
        self.active = Some(ActiveObject {
            temporary,
            file,
            name: name.clone(),
            written: 0,
        });
        true
    }

    fn write(&mut self, data: &[u8]) {
        let Some(mut active) = self.active.take() else {
            return;
        };
        let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let Some(written) = active.written.checked_add(length) else {
            let message = format!(
                "object \"{}\" exceeded the {MAX_EXPORT_OBJECT_BYTES}-byte export limit",
                active.name.as_str()
            );
            self.discard(active, &message);
            return;
        };
        if written > MAX_EXPORT_OBJECT_BYTES {
            let message = format!(
                "object \"{}\" exceeded the {MAX_EXPORT_OBJECT_BYTES}-byte export limit",
                active.name.as_str()
            );
            self.discard(active, &message);
            return;
        }
        match active.file.write_all(data) {
            Ok(()) => {
                active.written = written;
                self.active = Some(active);
            }
            Err(error) => {
                let message = format!("cannot write object \"{}\": {error}", active.name.as_str());
                self.discard(active, &message);
            }
        }
    }

    fn commit(&mut self) {
        let Some(active) = self.active.take() else {
            return;
        };
        let ActiveObject {
            temporary,
            file,
            name,
            ..
        } = active;
        // Closing before publishing keeps Windows hard links from failing on
        // an open source handle.
        drop(file);
        let Some(directory) = self.directory.as_deref() else {
            let _ = fs::remove_file(&temporary);
            return;
        };
        let mut last_error = None;
        for index in 0..=MAX_OBJECT_COLLISIONS {
            let candidate = name.with_collision(index);
            if !is_single_component(&candidate) {
                continue;
            }
            let destination = directory.join(&candidate);
            match fs::hard_link(&temporary, &destination) {
                Ok(()) => {
                    if let Err(error) = fs::remove_file(&temporary) {
                        crate::diagnostic(&format!(
                            "cannot remove temporary object file \"{}\": {error}",
                            temporary.display()
                        ));
                    }
                    return;
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => match publish_by_copy(&temporary, &destination) {
                    Ok(true) => {
                        let _ = fs::remove_file(&temporary);
                        return;
                    }
                    Ok(false) => continue,
                    Err(copy_error) => {
                        last_error = Some(format!(
                            "cannot create object \"{candidate}\": {error}; copy failed: {copy_error}"
                        ));
                        break;
                    }
                },
            }
        }
        let _ = fs::remove_file(&temporary);
        match last_error {
            Some(message) => crate::diagnostic(&message),
            None => crate::diagnostic(&format!(
                "cannot create object \"{}\": no free collision suffix",
                name.as_str()
            )),
        }
    }

    fn abort(&mut self) {
        if let Some(active) = self.active.take() {
            let _ = fs::remove_file(&active.temporary);
        }
    }

    fn refuse(&mut self) {
        let Some(active) = self.active.take() else {
            return;
        };
        let message = format!(
            "object \"{}\" exceeded the {MAX_EXPORT_OBJECT_BYTES}-byte export limit",
            active.name.as_str()
        );
        self.discard(active, &message);
    }
}

impl Drop for ObjectWriter {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Create the destination recursively with mode 0755.
fn create_directory(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "invalid argument"));
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o755);
    }
    builder.create(path)
}

/// Publish by copying into a fresh final file.
///
/// Used only when the filesystem rejects hard links (FAT, some network
/// mounts). Returns `Ok(false)` when the candidate already exists.
fn publish_by_copy(temporary: &Path, destination: &Path) -> io::Result<bool> {
    let mut input = File::open(temporary)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut output = match options.open(destination) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error),
    };
    // On Windows a reserved device name such as CON can open a device even
    // under a directory path; never copy capture bytes to it and never pass
    // it to remove_file. The hard-link path never opens the destination.
    if !output.metadata()?.is_file() {
        drop(output);
        return Err(io::Error::other("destination is not a regular file"));
    }
    if let Err(error) = io::copy(&mut input, &mut output) {
        drop(output);
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    Ok(true)
}

/// Whether `name` is exactly one path component.
///
/// [`ObjectName`] already guarantees this; checking again keeps a future
/// naming change from reaching the filesystem as a path.
fn is_single_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && Path::new(name).components().count() == 1
}
