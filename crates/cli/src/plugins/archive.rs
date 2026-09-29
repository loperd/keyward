//! Checking an archive before anything out of it appears on disk.
//!
//! A package is somebody else's archive, and an unpacker is a program that does
//! what the archive says. So there are three passes here, all before
//! installation:
//!
//! 1. **How much.** The compressed file no larger than 64 MiB, the unpacked
//!    contents no larger than 256 MiB, no more than ten thousand entries. The
//!    unpacked size is counted over a stream rather than on disk: a zip bomb has
//!    to run into a limit before it runs into free space.
//! 2. **Where to.** No absolute paths, no `..`, no entries outside a single top
//!    directory. Unpackers dislike this themselves, but relying on their mood
//!    about where files land is not allowed.
//! 3. **What.** After unpacking, a walk: symbolic and hard links, devices,
//!    sockets, the setuid and setgid bits. A breach refuses the lot: a package
//!    that reaches outside its own directory has nothing worth mending.

use std::path::{Component, Path};
use std::process::{Command, Stdio};

use anyhow::{bail, Context as _};

/// The ceiling on a compressed file.
pub const PACKED_MAX: u64 = 64 * 1024 * 1024;

/// The ceiling on what is unpacked.
pub const UNPACKED_MAX: u64 = 256 * 1024 * 1024;

/// The ceiling on the number of entries.
pub const ENTRIES_MAX: usize = 10_000;

/// The format, from the file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    TarGz,
    Zip,
}

pub fn kind_of(path: &Path) -> anyhow::Result<Kind> {
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Ok(Kind::TarGz)
    } else if name.ends_with(".zip") {
        Ok(Kind::Zip)
    } else {
        bail!("{} is neither a directory nor a .zip or .tar.gz archive", path.display())
    }
}

/// An archive entry's name will do only if it points inside the package.
fn safe_name(name: &str) -> anyhow::Result<()> {
    if name.starts_with('/') || name.starts_with("~/") {
        bail!("the archive has an absolute path \"{name}\"");
    }
    if name.contains('\\') {
        bail!("the archive has an entry with a Windows path separator: \"{name}\"");
    }
    for part in Path::new(name).components() {
        match part {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("the archive entry \"{name}\" leads outside the package"),
            Component::RootDir | Component::Prefix(_) => bail!("the archive has an absolute path \"{name}\""),
        }
    }
    Ok(())
}

/// An entry's top directory: `hello/bin/run` gives `hello`.
fn top(name: &str) -> Option<String> {
    name.trim_start_matches("./")
        .split('/')
        .find(|p| !p.is_empty() && *p != ".")
        .map(str::to_string)
}

/// Checking the list of entries: how many there are and where they will land.
pub fn check_names(names: &[String]) -> anyhow::Result<()> {
    if names.is_empty() {
        bail!("the archive is empty");
    }
    if names.len() > ENTRIES_MAX {
        bail!("the archive has {} entries, over the limit of {ENTRIES_MAX}", names.len());
    }
    let mut tops = std::collections::BTreeSet::new();
    for name in names {
        // `__MACOSX` is put alongside by the system archiver: it is no part of
        // the package and does not count as a top directory.
        if name.starts_with("__MACOSX/") || name == "__MACOSX" {
            continue;
        }
        safe_name(name)?;
        if let Some(t) = top(name) {
            tops.insert(t);
        }
    }
    let tops: Vec<String> = tops.into_iter().filter(|t| t != "__MACOSX").collect();
    match tops.len() {
        1 => Ok(()),
        0 => bail!("the archive has nothing to install"),
        _ => bail!("the archive has {} top directories at once; a package has to be one", tops.len()),
    }
}

fn run(mut cmd: Command, what: &str) -> anyhow::Result<String> {
    let out = cmd.stderr(Stdio::piped()).output().with_context(|| format!("{what} would not start"))?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        bail!("{what}: {}", why.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The list of names inside an archive, without unpacking it.
pub fn names(archive: &Path, kind: Kind) -> anyhow::Result<Vec<String>> {
    let raw = match kind {
        Kind::TarGz => {
            let mut c = Command::new("/usr/bin/tar");
            c.arg("-tzf").arg(archive);
            run(c, "reading the archive")?
        }
        Kind::Zip => {
            let mut c = Command::new("/usr/bin/unzip");
            c.args(["-Z", "-1"]).arg(archive);
            run(c, "reading the archive")?
        }
    };
    Ok(raw.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect())
}

/// How much there will be after unpacking. Counted over a stream: not a byte
/// reaches the disk while the check runs.
pub fn unpacked_size(archive: &Path, kind: Kind) -> anyhow::Result<u64> {
    match kind {
        Kind::TarGz => {
            // `gzip -dc | head -c N+1 | wc -c`: head closes the pipe as soon
            // as the limit is reached, and gzip dies of its own accord.
            let script = format!(
                "/usr/bin/gzip -dc \"$1\" 2>/dev/null | /usr/bin/head -c {} | /usr/bin/wc -c",
                UNPACKED_MAX + 1
            );
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(script).arg("sh").arg(archive);
            let out = run(c, "checking the archive's size")?;
            out.trim().parse().context("the archive's size was not counted")
        }
        Kind::Zip => {
            let mut c = Command::new("/usr/bin/unzip");
            c.args(["-Z", "-t"]).arg(archive);
            let out = run(c, "checking the archive's size")?;
            // «3 files, 1234 bytes uncompressed, …»
            let n = out
                .split(',')
                .find(|p| p.contains("uncompressed"))
                .and_then(|p| p.split_whitespace().next())
                .and_then(|n| n.replace(['.', ' '], "").parse::<u64>().ok())
                .context("the archive's size was not counted")?;
            Ok(n)
        }
    }
}

/// The numeric ceilings. A function of its own so that a test checks them
/// rather than trust: reaching a limit for real takes building a zip bomb, and
/// that costs more than checking the arithmetic.
pub fn check_limits(packed: u64, unpacked: u64, entries: usize) -> anyhow::Result<()> {
    if packed > PACKED_MAX {
        bail!("the package is {packed} bytes, over the limit of {PACKED_MAX}");
    }
    if unpacked > UNPACKED_MAX {
        bail!("unpacked it would be over {UNPACKED_MAX} bytes; a package like that is not installed");
    }
    if entries > ENTRIES_MAX {
        bail!("the archive has {entries} entries, over the limit of {ENTRIES_MAX}");
    }
    Ok(())
}

/// Everything that can be learnt about an archive without unpacking it.
pub fn check_before_unpacking(archive: &Path) -> anyhow::Result<Kind> {
    let kind = kind_of(archive)?;
    let packed = std::fs::metadata(archive)
        .with_context(|| format!("cannot read {}", archive.display()))?
        .len();
    let names = names(archive, kind)?;
    check_limits(packed, unpacked_size(archive, kind)?, names.len())?;
    check_names(&names)?;
    Ok(kind)
}

/// A walk over what was unpacked: what is really on the disk.
///
/// The unpacker may have created a link, a socket or a file with setuid, and
/// the list of names did not show that. Here is the last chance to say no
/// before the package moves into `~/.keyward/plugins`.
pub fn check_tree(root: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let mut count = 0usize;
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).with_context(|| format!("cannot read {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            count += 1;
            if count > ENTRIES_MAX {
                bail!("the package has more than {ENTRIES_MAX} files");
            }
            let meta = std::fs::symlink_metadata(&path)?;
            let kind = meta.file_type();
            if kind.is_symlink() {
                bail!("the package has a symbolic link \"{name}\"; we do not install those");
            }
            if kind.is_dir() {
                stack.push(path);
                continue;
            }
            if !kind.is_file() {
                bail!("\"{name}\" in the package is neither a file nor a directory");
            }
            // A hard link is the same file under two names, and one of them
            // may lie outside the package.
            if meta.nlink() > 1 {
                bail!("the package has a hard link \"{name}\"; we do not install those");
            }
            if meta.permissions().mode() & 0o6000 != 0 {
                bail!("the package has a file \"{name}\" with a setuid or setgid bit");
            }
            total += meta.len();
            if total > UNPACKED_MAX {
                bail!("the unpacked package is over {UNPACKED_MAX} bytes");
            }
        }
    }
    Ok(())
}

/// Permissions set here: directories 0700, ordinary files 0644, the program
/// 0755.
///
/// The mode is set by us rather than taken from the archive: a package's
/// author does not decide what will be executable on somebody's disk.
pub fn set_modes(root: &Path, exec: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut stack = vec![root.to_path_buf()];
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                stack.push(path);
            } else if meta.is_file() {
                let mode = if path == exec { 0o755 } else { 0o644 };
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            }
        }
    }
    Ok(())
}

/// Unpacking an archive that has been checked. Both tools come from the
/// system; both refuse to write outside the destination directory of their own
/// accord, but what we rely on is the checks before and after, not them.
pub fn unpack_into(archive: &Path, kind: Kind, dest: &Path) -> anyhow::Result<()> {
    let out = match kind {
        Kind::Zip => Command::new("/usr/bin/unzip")
            .arg("-q")
            .arg(archive)
            .arg("-d")
            .arg(dest)
            .output(),
        Kind::TarGz => Command::new("/usr/bin/tar")
            .arg("-xzf")
            .arg(archive)
            .arg("-C")
            .arg(dest)
            .output(),
    };
    let out = out.context("the unpacker would not start")?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        bail!("the archive did not unpack: {}", why.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kw-arc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn names_that_leave_the_package_are_refused() {
        assert!(check_names(&["hello/plugin.json".into(), "hello/run.py".into()]).is_ok());
        assert!(check_names(&["/etc/passwd".into()]).is_err());
        assert!(check_names(&["hello/../../etc/passwd".into()]).is_err());
        assert!(check_names(&["~/evil".into()]).is_err());
        assert!(check_names(&[]).is_err());
        // Two packages at once is not a package.
        assert!(check_names(&["hello/plugin.json".into(), "evil/plugin.json".into()]).is_err());
        // The system archiver's litter does not count as a top directory.
        assert!(check_names(&["hello/plugin.json".into(), "__MACOSX/._hello".into()]).is_ok());
        assert!(check_names(&(0..ENTRIES_MAX + 1).map(|i| format!("hello/f{i}")).collect::<Vec<_>>()).is_err());
    }

    #[test]
    fn the_limits_are_limits() {
        check_limits(1024, 4096, 3).unwrap();
        let e = check_limits(PACKED_MAX + 1, 10, 1).unwrap_err().to_string();
        assert!(e.contains("over the limit"), "got: {e}");
        // A zip bomb: little compressed, gigabytes unpacked.
        let e = check_limits(1024, UNPACKED_MAX + 1, 1).unwrap_err().to_string();
        assert!(e.contains("unpacked it would be"), "got: {e}");
        assert!(check_limits(1024, 4096, ENTRIES_MAX + 1).is_err());
    }

    #[test]
    fn a_symlink_in_the_package_is_a_refusal() {
        let dir = temp("symlink");
        let pkg = dir.join("hello");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("plugin.json"), "{}").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", pkg.join("secrets")).unwrap();
        let e = check_tree(&dir).unwrap_err().to_string();
        assert!(e.contains("symbolic link"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_hard_link_and_a_setuid_bit_are_refusals_too() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp("links");
        let pkg = dir.join("hello");
        std::fs::create_dir_all(&pkg).unwrap();
        let file = pkg.join("run.py");
        std::fs::write(&file, "#!/usr/bin/env python3\n").unwrap();
        std::fs::hard_link(&file, pkg.join("run2.py")).unwrap();
        assert!(check_tree(&dir).unwrap_err().to_string().contains("hard link"));
        std::fs::remove_file(pkg.join("run2.py")).unwrap();
        check_tree(&dir).unwrap();

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o4755)).unwrap();
        assert!(check_tree(&dir).unwrap_err().to_string().contains("setuid"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_real_archive_passes_and_a_traversing_one_does_not() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp("real");
        let pkg = dir.join("hello");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("plugin.json"), "{}").unwrap();
        let exe = pkg.join("run.py");
        std::fs::write(&exe, "#!/usr/bin/env python3\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let good = dir.join("hello.tar.gz");
        assert!(std::process::Command::new("/usr/bin/tar")
            .current_dir(&dir)
            .args(["-czf", "hello.tar.gz", "hello"])
            .status()
            .unwrap()
            .success());
        assert_eq!(check_before_unpacking(&good).unwrap(), Kind::TarGz);
        assert!(unpacked_size(&good, Kind::TarGz).unwrap() > 0);

        // An archive aiming outside the destination directory.
        let evil = dir.join("evil.tar.gz");
        assert!(std::process::Command::new("/bin/sh")
            .current_dir(&dir)
            .arg("-c")
            .arg("/usr/bin/tar -czf evil.tar.gz -s ',^hello,../hello,' hello 2>/dev/null || /usr/bin/tar -czf evil.tar.gz --transform 's,^hello,../hello,' hello")
            .status()
            .unwrap()
            .success());
        let e = check_before_unpacking(&evil).unwrap_err().to_string();
        assert!(e.contains("outside the package") || e.contains("top directories"), "got: {e}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn modes_are_ours_not_the_authors() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp("modes");
        let pkg = dir.join("hello");
        std::fs::create_dir_all(pkg.join("bin")).unwrap();
        let exe = pkg.join("bin/run");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        let plain = pkg.join("plugin.json");
        // The package's author left the manifest executable and open to all.
        std::fs::write(&plain, "{}").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o777)).unwrap();

        set_modes(&pkg, &exe).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&pkg), 0o700);
        assert_eq!(mode(&exe), 0o755);
        assert_eq!(mode(&plain), 0o644);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
