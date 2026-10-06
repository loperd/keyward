//! An external plugin's package: a directory with a `plugin.json` and a
//! program inside.
//!
//! Checking the manifest is no formality but the one place where the core
//! decides whether to let somebody else's code in at all. So the default here
//! is a refusal: an identifier that cannot be understood, an `exec` with `..`,
//! a file with no execute bit — all of that is "no" rather than "let us try and
//! see".

use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;
use keyward_plugin::{Manifest, Origin};
use serde::{Deserialize, Serialize};

/// The manifest's name inside a package.
pub const MANIFEST: &str = "plugin.json";

/// The register of what is on lies in a file next to the packages, so the
/// name is taken.
pub const REGISTRY_FILE: &str = "registry.json";

/// The ceiling on an identifier's length. It is also a directory name and a
/// settings file's name; 32 bytes is enough for any honest plugin and keeps the
/// path length limit out of the way.
const ID_MAX: usize = 32;

/// An external package's manifest: the plugin's card plus what a built-in one
/// does not have — what to run it with.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Package {
    #[serde(flatten)]
    pub manifest: Manifest,
    /// The path to the program, relative to the package's directory.
    pub exec: String,
    /// The version of the plugin protocol the program speaks. Absent means
    /// the first, unencrypted one, which the daemon no longer speaks.
    #[serde(default)]
    pub protocol: u32,
}

/// The plugin protocol this daemon speaks: every message sealed with Noise.
pub const PROTOCOL: u32 = 2;

impl Package {
    /// A package that speaks another protocol is refused plainly, rather than
    /// started and left to hang or, worse, talked to in the clear.
    pub fn check_protocol(&self) -> anyhow::Result<()> {
        if self.protocol == PROTOCOL {
            Ok(())
        } else {
            Err(keyward_core::fault!("err.pluginProtocolOld", "plugin" => &self.manifest.id))
        }
    }
}

impl Package {
    /// The full path to the program. Only the register knows a package's
    /// directory, so the joining happens here rather than in the manifest.
    pub fn exec_path(&self, dir: &Path) -> PathBuf {
        dir.join(&self.exec)
    }
}

/// An identifier: lower-case latin letters, digits, a hyphen.
///
/// Upper case is forbidden on purpose. An identifier is a directory name, and
/// APFS ignores case by default: `Ssh` and `ssh` would be one directory, and
/// "install a plugin" would turn into "overwrite somebody else's".
pub fn validate_id(id: &str) -> anyhow::Result<()> {
    if id.is_empty() {
        return Err(keyward_core::fault!("err.pluginNoId"));
    }
    if id.len() > ID_MAX {
        return Err(keyward_core::fault!("err.pluginIdTooLong", "max" => ID_MAX, "id" => id));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        return Err(keyward_core::fault!("err.pluginIdCharset", "id" => id));
    }
    // A leading or trailing hyphen makes a name nobody reads, and a directory
    // called `-` is confused with a command-line switch on top of that.
    if id.starts_with('-') || id.ends_with('-') {
        return Err(keyward_core::fault!("err.pluginIdHyphen", "id" => id));
    }
    // A plugin's settings lie in `~/.keyward/plugins/<id>.json` next to the
    // package directories, and three names there are already taken by our own:
    // the register of what is on, the list of showcase sources, and its
    // cache.
    if matches!(id, "registry" | "sources" | "catalog" | "publishers") {
        return Err(keyward_core::fault!("err.pluginIdReserved", "id" => id));
    }
    Ok(())
}

/// The path to run: inside the package only, and relative only.
///
/// An absolute path would mean "run something in the system" and a `..` "run
/// something next door": either makes checking the manifest pointless, because
/// what runs is then not part of the package.
pub fn validate_exec(exec: &str) -> anyhow::Result<()> {
    if exec.trim().is_empty() {
        return Err(keyward_core::fault!("err.pluginNoExec"));
    }
    let path = Path::new(exec);
    if path.is_absolute() {
        return Err(keyward_core::fault!("err.pluginExecAbsolute", "exec" => exec));
    }
    for part in path.components() {
        match part {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => return Err(keyward_core::fault!("err.pluginExecOutside", "exec" => exec)),
            Component::RootDir | Component::Prefix(_) => {
                return Err(keyward_core::fault!("err.pluginExecAbsolute", "exec" => exec))
            }
        }
    }
    Ok(())
}

/// A version is three numbers with dots between them. Not decoration: the
/// showcase decides what is newer by versions, and there is nothing to compare
/// "1.0-beta" against.
pub fn validate_version(v: &str) -> anyhow::Result<()> {
    let parts: Vec<&str> = v.split('.').collect();
    let ok = parts.len() == 3
        && parts.iter().all(|p| !p.is_empty() && p.len() <= 6 && p.chars().all(|c| c.is_ascii_digit()));
    if !ok {
        return Err(keyward_core::fault!("err.pluginVersionFormat", "version" => v));
    }
    Ok(())
}

/// An icon's name: latin letters, digits, a hyphen. The interface draws the
/// icon, and the string from here goes into a resource name.
fn validate_icon(icon: &str) -> anyhow::Result<()> {
    if icon.is_empty() {
        return Ok(());
    }
    let mut chars = icon.chars();
    let head = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    let tail = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !head || !tail || icon.len() > 32 {
        return Err(keyward_core::fault!("err.pluginIconCharset", "icon" => icon));
    }
    Ok(())
}

/// The manifest's rules in full: the one place where it is decided whether
/// somebody else's package goes any further. The default is a refusal — a field
/// that cannot be understood is better explained to a person now than puzzled
/// over later when the plugin behaves strangely.
pub fn validate_manifest(pkg: &mut Package) -> anyhow::Result<()> {
    validate_id(&pkg.manifest.id)?;
    validate_version(&pkg.manifest.version)?;
    validate_exec(&pkg.exec)?;
    validate_icon(&pkg.manifest.icon)?;
    if pkg.manifest.title.chars().count() > 64 {
        return Err(keyward_core::fault!("err.pluginTitleTooLong"));
    }
    if pkg.manifest.description.chars().count() > 200 {
        return Err(keyward_core::fault!("err.pluginDescriptionTooLong"));
    }
    // Duplicates are folded: "asks for entries twice" is the same entries, and
    // in the consent dialogue it has to be one line.
    pkg.manifest.permissions.sort();
    pkg.manifest.permissions.dedup();
    Ok(())
}

/// Read and check a directory's manifest. Everything the daemon sees beyond
/// this point came through here.
pub fn read(dir: &Path) -> anyhow::Result<Package> {
    let file = dir.join(MANIFEST);
    let raw = std::fs::read_to_string(&file)
        .with_context(|| format!("cannot read {}", file.display()))?;
    let mut pkg: Package = serde_json::from_str(&raw)
        .with_context(|| format!("the manifest {} would not parse", file.display()))?;

    validate_manifest(&mut pkg)?;

    let exe = pkg.exec_path(dir);
    let meta = std::fs::symlink_metadata(&exe)
        .with_context(|| format!("the package has no file {}", pkg.exec))?;
    if !meta.is_file() {
        return Err(keyward_core::fault!("err.pluginExecNotAFile", "exec" => &pkg.exec));
    }
    // The execute bit is neither asked of the package's author nor taken from
    // the archive: `archive::set_modes` sets the mode in place. A package's
    // author does not decide what is executable on somebody's disk.

    // The daemon decides the origin and whether a plugin is on, not the
    // package's author: otherwise a plugin would install already switched on
    // and under somebody else's signature.
    pkg.manifest.origin = Origin::External;
    pkg.manifest.enabled = false;
    if pkg.manifest.title.trim().is_empty() {
        pkg.manifest.title = pkg.manifest.id.clone();
    }
    Ok(pkg)
}

/// The directory of packages: `~/.keyward/plugins`.
pub fn root() -> PathBuf {
    keyward_core::paths::base_dir().join("plugins")
}

/// Install a package from a directory or an archive. Returns the card the
/// interface asks for consent to the permissions by.
pub fn install(src: &Path, taken: &dyn Fn(&str) -> bool) -> anyhow::Result<Placed> {
    place(src, Mode::Fresh(taken), None)
}

/// Install or update: the identifier is known only after the manifest is
/// parsed, so the decision of "a new installation or an update" is taken here
/// rather than outside. The old directory steps aside and comes back if the new
/// one does not stand up: nobody signed up to be left without a plugin because
/// an update went wrong.
pub fn install_or_update(
    src: &Path,
    is_builtin: &dyn Fn(&str) -> bool,
    is_installed: &dyn Fn(&str) -> bool,
    promised: Option<&Promise>,
) -> anyhow::Result<Placed> {
    place(src, Mode::Auto { is_builtin, is_installed }, promised)
}

/// What the showcase promised about this package. Checked before anything
/// reaches the disk: if the archive holds another version, or asks for more
/// rights than the showcase listed, that is not what a person agreed to.
#[derive(Debug, Clone)]
pub struct Promise {
    pub version: String,
    pub permissions: Vec<String>,
}

fn check_promise(pkg: &Package, promised: &Promise) -> anyhow::Result<()> {
    if !promised.version.is_empty() && promised.version != pkg.manifest.version {
        return Err(keyward_core::fault!(
            "err.packageVersionMismatch",
            "promised" => &promised.version,
            "found" => &pkg.manifest.version,
        ));
    }
    if promised.permissions.is_empty() {
        return Ok(());
    }
    let asks: Vec<String> = pkg
        .manifest
        .permissions
        .iter()
        .filter_map(|p| serde_json::to_value(p).ok())
        .filter_map(|v| v.as_str().map(str::to_string))
        .filter(|name| !promised.permissions.contains(name))
        .collect();
    if !asks.is_empty() {
        return Err(keyward_core::fault!(
            "err.packageExtraPermissions",
            "permissions" => asks.join(", "),
        ));
    }
    Ok(())
}

/// What the register remembers about an installed package.
#[derive(Debug, Clone)]
pub struct Placed {
    pub pkg: Package,
    /// Installed over one that was already there.
    pub updated: bool,
    /// The sha256 of the manifest and the program at the moment of
    /// installation: the daemon learns from them before every start whether the
    /// package on disk was swapped.
    pub manifest_sha: String,
    pub exec_sha: String,
}

enum Mode<'a> {
    /// A new installation: the identifier has to be free.
    Fresh(&'a dyn Fn(&str) -> bool),
    /// Whichever fits: free means install, taken by an external one means
    /// update, taken by a built-in one means a refusal.
    Auto { is_builtin: &'a dyn Fn(&str) -> bool, is_installed: &'a dyn Fn(&str) -> bool },
}

fn place(src: &Path, mode: Mode<'_>, promised: Option<&Promise>) -> anyhow::Result<Placed> {
    if !src.exists() {
        return Err(keyward_core::fault!("err.pathMissing", "path" => src.display()));
    }

    // An archive is unpacked into a temporary directory of our own next to the
    // packages: it is on the same file system, so moving afterwards is cheap,
    // and the mode on it is ours — 0700. The archive's checks come before
    // anything out of it appears on disk.
    let unpacked = if src.is_dir() {
        None
    } else {
        let kind = super::archive::check_before_unpacking(src)?;
        let tmp = scratch(&root(), "unpack")?;
        super::archive::unpack_into(src, kind, tmp.path())?;
        super::archive::check_tree(tmp.path())?;
        Some(tmp)
    };

    let dir = match &unpacked {
        Some(tmp) => package_root(tmp.path())?,
        None => src.to_path_buf(),
    };
    let pkg = read(&dir)?;
    // A package of the old, unencrypted protocol is refused here and now,
    // not installed to fail at its first call.
    pkg.check_protocol()?;
    if let Some(promised) = promised {
        check_promise(&pkg, promised)?;
    }
    let id = pkg.manifest.id.clone();
    let updating = match mode {
        Mode::Fresh(taken) => {
            if taken(&id) {
                return Err(keyward_core::fault!("err.pluginAlreadyInstalled", "id" => id));
            }
            false
        }
        Mode::Auto { is_builtin, is_installed } => {
            if is_builtin(&id) {
                return Err(keyward_core::fault!("err.pluginIdBuiltin", "id" => id));
            }
            is_installed(&id)
        }
    };

    let dest = root().join(&id);
    std::fs::create_dir_all(root())?;
    crate::daemon::restrict(&root())?;

    // The old one steps aside rather than being deleted: if the new package
    // does not stand up, what worked comes back.
    let backup = if dest.exists() {
        if !updating {
            return Err(keyward_core::fault!("err.directoryTaken", "path" => dest.display()));
        }
        let aside = root().join(format!(".old-{id}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&aside);
        std::fs::rename(&dest, &aside).with_context(|| format!("cannot move {} aside", dest.display()))?;
        Some(aside)
    } else {
        None
    };

    let result = (|| -> anyhow::Result<Placed> {
        copy_tree(&dir, &dest)?;
        let exe = pkg.exec_path(&dest);
        super::archive::set_modes(&dest, &exe)?;
        // Once more in place: what runs has to be checked where it lies, not
        // where it lay.
        let pkg = read(&dest)?;
        super::archive::check_tree(&dest)?;
        Ok(Placed {
            manifest_sha: file_sha(&dest.join(MANIFEST))?,
            exec_sha: file_sha(&pkg.exec_path(&dest))?,
            updated: updating,
            pkg,
        })
    })();

    match (result, backup) {
        (Ok(placed), backup) => {
            if let Some(aside) = backup {
                let _ = std::fs::remove_dir_all(aside);
            }
            Ok(placed)
        }
        (Err(e), Some(aside)) => {
            let _ = std::fs::remove_dir_all(&dest);
            let _ = std::fs::rename(&aside, &dest);
            Err(e)
        }
        (Err(e), None) => {
            let _ = std::fs::remove_dir_all(&dest);
            Err(e)
        }
    }
}

/// A file's sha256 in hexadecimal.
pub fn file_sha(path: &Path) -> anyhow::Result<String> {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// Do a package's files match what was remembered at installation?
///
/// The signature and the fingerprint are checked at installation, and there
/// their work ends: a file on disk can be swapped afterwards. So there is a
/// recount before every start of the process.
pub fn unchanged(dir: &Path, exec: &str, manifest_sha: &str, exec_sha: &str) -> anyhow::Result<()> {
    let got_manifest = file_sha(&dir.join(MANIFEST))?;
    if got_manifest != manifest_sha {
        return Err(keyward_core::fault!("err.packageFileChanged", "file" => MANIFEST));
    }
    let got_exec = file_sha(&dir.join(exec))?;
    if got_exec != exec_sha {
        return Err(keyward_core::fault!("err.packageFileChanged", "file" => exec));
    }
    Ok(())
}

/// Remove a package: its directory, its settings and its state. Nothing of
/// the plugin is left anywhere.
pub fn remove(id: &str) -> anyhow::Result<()> {
    validate_id(id)?;
    let dir = root().join(id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("cannot remove {}", dir.display()))?;
    }
    // The settings lie in a file next to the directory: they are part of the
    // plugin, not of the person, and leaving them would mean handing somebody
    // else's data to the next installation.
    let settings = keyward_core::paths::plugin_settings(id);
    if settings.exists() {
        std::fs::remove_file(&settings)
            .with_context(|| format!("cannot remove {}", settings.display()))?;
    }
    Ok(())
}

/// A temporary directory that clears up after itself.
#[derive(Debug)]
pub struct Temp(PathBuf);

impl Temp {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A temporary directory next to the packages: the same volume as the
/// destination, and mode 0700 — a downloaded package is shown to nobody on the
/// way.
///
/// The register's walk skips directories with no `plugin.json`, so such a
/// directory, having outlived a crash of the daemon, turns into nothing.
pub fn scratch(parent: &Path, tag: &str) -> anyhow::Result<Temp> {
    let dir = parent.join(format!(".{tag}-{}-{}", std::process::id(), now_ms()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    crate::daemon::restrict(&dir)?;
    Ok(Temp(dir))
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

/// Where the package itself lies inside what was unpacked: alongside, or in a
/// single directory within. Archives are built both ways, and the difference is
/// of no interest to a person.
fn package_root(dir: &Path) -> anyhow::Result<PathBuf> {
    if dir.join(MANIFEST).exists() {
        return Ok(dir.to_path_buf());
    }
    let mut inner: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // `__MACOSX` is put alongside by the system archiver; dotfiles are
        // litter such as `.DS_Store`.
        if name.starts_with('.') || name == "__MACOSX" {
            continue;
        }
        if entry.path().join(MANIFEST).exists() {
            inner.push(entry.path());
        }
    }
    match inner.len() {
        1 => Ok(inner.remove(0)),
        0 => return Err(keyward_core::fault!("err.archiveNoManifest", "manifest" => MANIFEST)),
        n => return Err(keyward_core::fault!("err.archiveManyPackages", "count" => n)),
    }
}

/// Copying a package with its modes kept: the execute bit is part of the
/// package.
///
/// Symbolic links are not copied: they have no business inside a package, and
/// a link outwards turns "a directory with a program" into anything at all and
/// can loop the walk into the bargain.
fn copy_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = to.join(entry.file_name());
        if kind.is_symlink() {
            tracing::warn!(path = %entry.path().display(), "a link in a plugin package was skipped");
            continue;
        }
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target)
                .with_context(|| format!("cannot copy {}", entry.path().display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kw-pkg-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_package(dir: &Path, manifest: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(dir.join(MANIFEST), manifest).unwrap();
        let exe = dir.join("run.py");
        std::fs::write(&exe, "#!/usr/bin/env python3\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    const GOOD: &str = r#"{"id":"hello","title":"Hello","icon":"note","section":true,
        "needs_unlocked":false,"version":"1.0.0","exec":"run.py","protocol":2,"permissions":["entries","notices"]}"#;

    #[test]
    fn a_package_of_the_old_protocol_is_refused_at_install() {
        let dir = std::env::temp_dir().join(format!("kw-old-proto-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("run.py"), "#!/bin/sh\n").unwrap();
        std::fs::write(
            dir.join(MANIFEST),
            r#"{"id":"oldie","title":"Old","icon":"note","section":false,"needs_unlocked":false,"version":"1.0.0","exec":"run.py"}"#,
        )
        .unwrap();
        let pkg = read(&dir).unwrap();
        let e = pkg.check_protocol().unwrap_err();
        assert!(e.to_string().starts_with("err.pluginProtocolOld"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn good_package_reads() {
        let dir = temp("good");
        write_package(&dir, GOOD, 0o755);
        let pkg = read(&dir).unwrap();
        assert_eq!(pkg.manifest.id, "hello");
        assert_eq!(pkg.exec, "run.py");
        assert_eq!(pkg.manifest.permissions.len(), 2);
        // A package's author does not set the origin or whether it is on.
        assert_eq!(pkg.manifest.origin, Origin::External);
        assert!(!pkg.manifest.enabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_cannot_claim_to_be_builtin() {
        let dir = temp("liar");
        write_package(
            &dir,
            r#"{"id":"hello","title":"Hello","icon":"note","section":true,"needs_unlocked":false,
                "version":"1.0.0","exec":"run.py","origin":"builtin","enabled":true}"#,
            0o755,
        );
        let pkg = read(&dir).unwrap();
        assert_eq!(pkg.manifest.origin, Origin::External);
        assert!(!pkg.manifest.enabled, "a package is not entitled to install switched on");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_run_bit_is_ours_to_set_not_the_authors() {
        // A package with no execute bit is no trouble: `set_modes` sets the
        // mode in place. We do not take modes from somebody else's archive at
        // all.
        let dir = temp("noexec");
        write_package(&dir, GOOD, 0o644);
        read(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_manifest_rules_are_not_suggestions() {
        use std::os::unix::fs::PermissionsExt as _;
        // The version, the length of the title and the description, the
        // icon's name — all of these are rules rather than wishes: a package's
        // author writes the manifest, and we are not entitled to read it as
        // well-meaning.
        let cases = [
            (r#""version":"1.0","icon":"note","title":"Hello""#, "err.pluginVersionFormat"),
            (
                &format!(r#""version":"1.0.0","icon":"note","title":"{}""#, "a".repeat(65)) as &str,
                "err.pluginTitleTooLong",
            ),
            (
                &format!(r#""version":"1.0.0","icon":"note","title":"Hello","description":"{}""#, "b".repeat(201)) as &str,
                "err.pluginDescriptionTooLong",
            ),
            (r#""version":"1.0.0","icon":"Icon!","title":"Hello""#, "err.pluginIconCharset"),
        ];
        for (n, (fields, why)) in cases.iter().enumerate() {
            let dir = temp(&format!("rules-{n}"));
            let manifest =
                format!(r#"{{"id":"hello","section":false,"needs_unlocked":false,"exec":"run.py",{fields}}}"#);
            std::fs::write(dir.join(MANIFEST), &manifest).unwrap();
            let exe = dir.join("run.py");
            std::fs::write(&exe, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
            let e = read(&dir).unwrap_err().to_string();
            assert!(e.contains(why), "expected a refusal about {why}, got: {e}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_repeated_permission_is_one_permission() {
        let dir = temp("dedup");
        write_package(
            &dir,
            r#"{"id":"hello","title":"Hello","icon":"note","section":false,"needs_unlocked":false,
                "version":"1.0.0","exec":"run.py","permissions":["entries","notices","entries"]}"#,
            0o755,
        );
        let pkg = read(&dir).unwrap();
        assert_eq!(pkg.manifest.permissions.len(), 2, "a duplicate permission stayed: {:?}", pkg.manifest.permissions);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_exec_file_is_refused() {
        let dir = temp("noprog");
        std::fs::write(dir.join(MANIFEST), GOOD).unwrap();
        assert!(read(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ids_are_lowercase_latin_digits_and_hyphen() {
        for good in ["hello", "hello-world", "h", "vault2", "a-b-c"] {
            validate_id(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in ["", "Hello", "hello world", "hello/../etc", "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}", "hello.", "-x", "x-", &"a".repeat(64)] {
            assert!(validate_id(bad).is_err(), "something unusable got through: {bad:?}");
        }
        // Our own names are taken: a plugin's settings file lies next to the
        // directories as `<id>.json` and would write over the register or the
        // showcase.
        for busy in ["registry", "sources", "catalog", "publishers"] {
            assert!(validate_id(busy).is_err(), "the name {busy} has to be taken");
        }
    }

    #[test]
    fn exec_cannot_leave_the_package() {
        for bad in ["", "  ", "/bin/sh", "../../bin/sh", "sub/../../out.py", "/usr/bin/env"] {
            assert!(validate_exec(bad).is_err(), "something unusable got through: {bad:?}");
        }
        for good in ["run.py", "./run.py", "bin/run", "a/b/c.sh"] {
            validate_exec(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
    }

    #[test]
    fn traversal_in_exec_is_caught_by_read_too() {
        let dir = temp("traversal");
        write_package(
            &dir,
            r#"{"id":"hello","title":"Hello","icon":"note","section":true,"needs_unlocked":false,
                "version":"1.0.0","exec":"../../../../bin/sh"}"#,
            0o755,
        );
        let e = read(&dir).unwrap_err().to_string();
        assert!(e.contains("err.pluginExecOutside"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_permission_is_not_silently_dropped() {
        let dir = temp("perm");
        write_package(
            &dir,
            r#"{"id":"hello","title":"Hello","icon":"note","section":true,"needs_unlocked":false,
                "version":"1.0.0","exec":"run.py","permissions":["entries","everything"]}"#,
            0o755,
        );
        assert!(read(&dir).is_err(), "an unfamiliar permission has to be a refusal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_refuses_an_id_that_is_already_taken() {
        let dir = temp("taken");
        write_package(&dir, GOOD, 0o755);
        let e = install(&dir, &|_| true).unwrap_err().to_string();
        assert!(e.contains("err.pluginAlreadyInstalled"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn package_root_finds_the_single_nested_directory() {
        let dir = temp("nested");
        let inner = dir.join("hello-1.0.0");
        std::fs::create_dir_all(&inner).unwrap();
        write_package(&inner, GOOD, 0o755);
        std::fs::create_dir_all(dir.join("__MACOSX")).unwrap();
        assert_eq!(package_root(&dir).unwrap(), inner);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn package_root_says_no_when_there_is_nothing_to_take() {
        let dir = temp("empty");
        let e = package_root(&dir).unwrap_err().to_string();
        assert!(e.contains("err.archiveNoManifest"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn archive_of(dir: &Path, kind: &str) -> PathBuf {
        let inner = dir.join("hello");
        std::fs::create_dir_all(&inner).unwrap();
        write_package(&inner, GOOD, 0o755);
        let archive = dir.join(format!("hello.{kind}"));
        let out = if kind == "zip" {
            std::process::Command::new("/usr/bin/zip")
                .current_dir(dir)
                .args(["-q", "-r", "-X", "hello.zip", "hello"])
                .output()
        } else {
            std::process::Command::new("/usr/bin/tar")
                .current_dir(dir)
                .args(["-czf", "hello.tar.gz", "hello"])
                .output()
        };
        assert!(out.unwrap().status.success(), "the archive would not build");
        archive
    }

    #[test]
    fn archives_of_both_kinds_unpack_into_a_package() {
        for kind in ["zip", "tar.gz"] {
            let dir = temp(&kind.replace('.', ""));
            let archive = archive_of(&dir, kind);
            let format = super::super::archive::check_before_unpacking(&archive).unwrap();
            let tmp = scratch(&dir, "t").unwrap();
            super::super::archive::unpack_into(&archive, format, tmp.path()).unwrap();
            super::super::archive::check_tree(tmp.path()).unwrap();
            let pkg = read(&package_root(tmp.path()).unwrap()).unwrap();
            assert_eq!(pkg.manifest.id, "hello", "format {kind}");
            let path = tmp.path().to_path_buf();
            drop(tmp);
            assert!(!path.exists(), "the temporary directory stayed after unpacking");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_file_that_is_neither_directory_nor_archive_is_refused() {
        let dir = temp("plain");
        let file = dir.join("hello.txt");
        std::fs::write(&file, "not an archive").unwrap();
        let e = install(&file, &|_| false).unwrap_err().to_string();
        assert!(e.contains("neither a directory nor a"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
