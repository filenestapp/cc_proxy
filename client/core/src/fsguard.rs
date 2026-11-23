//! Link-safe file access and ownership checks for the privileged supervisor (issue #1, follow-up to CC-01).
//!
//! * [`read_regular_file`] opens a file without following a link or reparse point at its last component. It
//!   then checks type, size and link count on that same open handle before reading from it, so the file
//!   that is checked is the file that is read.
//! * [`prepare_dir`] and [`verify_dir`] make sure a directory the supervisor writes to can be written only by
//!   root (Unix) or SYSTEM / Administrators (Windows). They check its owner, its mode bits and ACL entries, and
//!   those of every directory above it, so nobody else can write to it, rename it or replace it.
//!   [`prepare_dir`] moves a pre-existing directory that fails the check aside and creates a fresh one. It never
//!   repairs one in place: anything another account could put there earlier (links, hard links, junctions) is
//!   untrusted.
//!
//! The decision rules are plain functions in [`policy`], so they can be tested on every platform.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

/// Who must own a protected directory and the directories above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Production: root (Unix) or SYSTEM / Administrators (Windows).
    Privileged,
    /// Tests on Unix: root or this uid. Treated like [`Trust::Privileged`] on Windows.
    Uid(u32),
    /// Tests only: no ownership or permission checks. The directory must still be a real directory, not a link.
    Unchecked,
}

// ---- reading a file through one handle --------------------------------------------------------------------

/// Open `path` for reading without following a symlink (Unix) or reparse point (Windows) at its last component.
/// On Unix the open does not block on a FIFO; the type check that follows refuses it.
pub fn open_no_follow(path: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    o.open(path).with_context(|| format!("opening {} (links are not followed)", path.display()))
}

/// Read a regular file of at most `max` bytes that has exactly one link. Every check runs on the handle that is
/// read from.
pub fn read_regular_file(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = open_no_follow(path)?;
    let meta = file.metadata().with_context(|| format!("inspecting {}", path.display()))?;
    if !meta.file_type().is_file() || is_reparse_point(&meta) {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > max {
        bail!("{} is larger than {max} bytes", path.display());
    }
    if link_count(&file, &meta)? != 1 {
        bail!("{} has more than one hard link", path.display());
    }
    let mut data = Vec::new();
    (&file).take(max + 1).read_to_end(&mut data).with_context(|| format!("reading {}", path.display()))?;
    if data.len() as u64 > max {
        bail!("{} grew beyond {max} bytes while being read", path.display());
    }
    Ok(data)
}

#[cfg(unix)]
fn is_reparse_point(_: &std::fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(unix)]
fn link_count(_: &File, meta: &std::fs::Metadata) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(meta.nlink())
}

#[cfg(windows)]
fn link_count(file: &File, _: &std::fs::Metadata) -> Result<u64> {
    use std::os::windows::io::AsRawHandle;
    Ok(u64::from(win::file_info(file.as_raw_handle())?.nNumberOfLinks))
}

// ---- protected directories --------------------------------------------------------------------------------

/// Create `dir` if needed and make sure only the trusted accounts can write to it or replace it. A pre-existing
/// directory (or link, junction or file) in its place that fails the check is renamed to
/// `<name>.untrusted-<time>-<pid>` and a fresh directory is created. With [`Trust::Unchecked`] a failing entry
/// is an error instead.
pub fn prepare_dir(dir: &Path, trust: Trust) -> Result<()> {
    imp::walk(dir, trust, true)
}

/// Check `dir` as [`prepare_dir`] does, without creating, moving or changing anything. Run before every write.
pub fn verify_dir(dir: &Path, trust: Trust) -> Result<()> {
    imp::walk(dir, trust, false)
}

fn quarantine_name(name: &std::ffi::OsStr) -> std::ffi::OsString {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut n = name.to_os_string();
    n.push(format!(".untrusted-{secs}-{}", std::process::id()));
    n
}

#[cfg(unix)]
use unix as imp;
#[cfg(windows)]
use win as imp;

#[cfg(unix)]
mod unix {
    use super::{policy, quarantine_name, Trust};
    use anyhow::{bail, Context, Result};
    use std::ffi::{CString, OsStr};
    use std::fs::{File, Permissions};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Component, Path, PathBuf};

    fn c_name(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }

    /// Open a directory relative to `parent` (or by path when `parent` is None). `follow`: allow a symlink as the
    /// last component.
    fn open_dir(parent: Option<&File>, name: &OsStr, follow: bool) -> io::Result<File> {
        let c = c_name(name)?;
        let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        if !follow {
            flags |= libc::O_NOFOLLOW;
        }
        let fd = unsafe {
            match parent {
                Some(p) => libc::openat(p.as_raw_fd(), c.as_ptr(), flags),
                None => libc::open(c.as_ptr(), flags),
            }
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn mkdir_at(parent: &File, name: &OsStr) -> io::Result<()> {
        let c = c_name(name)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn rename_at(parent: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let (f, t) = (c_name(from)?, c_name(to)?);
        if unsafe { libc::renameat(parent.as_raw_fd(), f.as_ptr(), parent.as_raw_fd(), t.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Everything wrong with one open directory under `trust` (never [`Trust::Unchecked`]).
    fn problems(dir: &File, trust: Trust) -> Result<Vec<String>> {
        let extra = match trust {
            Trust::Uid(uid) => Some(uid),
            _ => None,
        };
        let m = dir.metadata()?;
        let mut p = policy::unix_dir_problems(m.uid(), m.mode(), extra);
        if acl::grants_write(dir)? {
            p.push("an ACL entry lets another account write to it".into());
        }
        Ok(p)
    }

    fn refuse(path: &Path, problems: &[String]) -> anyhow::Error {
        anyhow::anyhow!("{} is not protected: {}", path.display(), problems.join("; "))
    }

    fn is_replaceable(e: &io::Error) -> bool {
        matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR))
    }

    pub fn walk(dir: &Path, trust: Trust, create: bool) -> Result<()> {
        let name = dir.file_name().with_context(|| format!("{} has no final component", dir.display()))?;
        let parent_path = match dir.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };

        // The parent: in tests opened by path; in production walked from "/" one component at a time without
        // following links, each directory checked on the handle that the next step opens from.
        let parent = if trust == Trust::Unchecked {
            open_dir(None, parent_path.as_os_str(), true).with_context(|| format!("opening {}", parent_path.display()))?
        } else {
            if !dir.is_absolute() {
                bail!("{} must be an absolute path", dir.display());
            }
            let mut shown = PathBuf::from("/");
            let mut cur = open_dir(None, OsStr::new("/"), true).context("opening /")?;
            let p = problems(&cur, trust)?;
            if !p.is_empty() {
                return Err(refuse(&shown, &p));
            }
            for c in parent_path.components() {
                match c {
                    Component::RootDir => {}
                    Component::Normal(n) => {
                        shown.push(n);
                        cur = open_dir(Some(&cur), n, false)
                            .with_context(|| format!("{} must be a real directory, not a link", shown.display()))?;
                        let p = problems(&cur, trust)?;
                        if !p.is_empty() {
                            return Err(refuse(&shown, &p));
                        }
                    }
                    _ => bail!("{} must be a plain absolute path", dir.display()),
                }
            }
            cur
        };

        match open_dir(Some(&parent), name, false) {
            Ok(existing) => {
                if trust == Trust::Unchecked {
                    if create {
                        existing.set_permissions(Permissions::from_mode(0o755))?;
                    }
                    return Ok(());
                }
                let p = problems(&existing, trust)?;
                if p.is_empty() {
                    return Ok(());
                }
                if !create {
                    return Err(refuse(dir, &p));
                }
                drop(existing);
                rename_at(&parent, name, &quarantine_name(name))
                    .with_context(|| format!("moving aside unprotected {}", dir.display()))?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {}
            Err(e) if is_replaceable(&e) && create && trust != Trust::Unchecked => {
                rename_at(&parent, name, &quarantine_name(name))
                    .with_context(|| format!("moving aside {} (a link or file)", dir.display()))?;
            }
            Err(e) if is_replaceable(&e) => bail!("{} must be a directory, not a link", dir.display()),
            Err(e) => return Err(e).with_context(|| format!("opening {}", dir.display())),
        }

        mkdir_at(&parent, name).with_context(|| format!("creating {}", dir.display()))?;
        let fresh = open_dir(Some(&parent), name, false).with_context(|| format!("opening {}", dir.display()))?;
        fresh.set_permissions(Permissions::from_mode(0o755))?;
        if trust != Trust::Unchecked {
            let p = problems(&fresh, trust)?;
            if !p.is_empty() {
                return Err(refuse(dir, &p));
            }
        }
        Ok(())
    }

    /// Extended ACLs (macOS) or POSIX ACLs (Linux) that let anyone write to the directory or to what is created in
    /// it. Mode bits are checked separately.
    #[cfg(target_os = "macos")]
    mod acl {
        use crate::fsguard::policy;
        use anyhow::{Context, Result};
        use std::fs::File;
        use std::io;
        use std::os::fd::AsRawFd;
        use std::os::raw::{c_int, c_void};
        use std::ptr::null_mut;

        const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
        const ACL_FIRST_ENTRY: c_int = 0;
        const ACL_NEXT_ENTRY: c_int = -1;

        extern "C" {
            fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
            fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
            fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
            fn acl_get_permset(entry: *mut c_void, permset: *mut *mut c_void) -> c_int;
            fn acl_get_perm_np(permset: *mut c_void, perm: c_int) -> c_int;
            fn acl_free(obj: *mut c_void) -> c_int;
        }

        pub fn grants_write(dir: &File) -> Result<bool> {
            let acl = unsafe { acl_get_fd_np(dir.as_raw_fd(), ACL_TYPE_EXTENDED) };
            if acl.is_null() {
                let e = io::Error::last_os_error();
                return if e.raw_os_error() == Some(libc::ENOENT) { Ok(false) } else { Err(e).context("reading ACL") };
            }
            let mut found = false;
            let mut id = ACL_FIRST_ENTRY;
            let mut entry = null_mut();
            while unsafe { acl_get_entry(acl, id, &mut entry) } == 0 {
                id = ACL_NEXT_ENTRY;
                let mut tag: c_int = 0;
                let mut permset = null_mut();
                if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || unsafe { acl_get_permset(entry, &mut permset) } != 0
                {
                    // An entry we cannot read is treated as granting write.
                    found = true;
                    break;
                }
                let mut perms = 0u32;
                for p in policy::MACOS_ACL_WRITE_PERMS {
                    if unsafe { acl_get_perm_np(permset, p as c_int) } == 1 {
                        perms |= p;
                    }
                }
                if policy::macos_acl_entry_grants_write(tag, perms) {
                    found = true;
                    break;
                }
            }
            unsafe { acl_free(acl) };
            Ok(found)
        }
    }

    #[cfg(target_os = "linux")]
    mod acl {
        use crate::fsguard::policy;
        use anyhow::{anyhow, Context, Result};
        use std::fs::File;
        use std::io;
        use std::os::fd::AsRawFd;

        pub fn grants_write(dir: &File) -> Result<bool> {
            for name in [&b"system.posix_acl_access\0"[..], &b"system.posix_acl_default\0"[..]] {
                let mut buf = vec![0u8; 64 * 1024];
                let n = unsafe {
                    libc::fgetxattr(dir.as_raw_fd(), name.as_ptr().cast(), buf.as_mut_ptr().cast(), buf.len())
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    match e.raw_os_error() {
                        Some(libc::ENODATA) | Some(libc::EOPNOTSUPP) => continue,
                        _ => return Err(e).context("reading POSIX ACL"),
                    }
                }
                if policy::posix_acl_grants_write(&buf[..n as usize]).map_err(|e| anyhow!(e))? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    mod acl {
        pub fn grants_write(_: &std::fs::File) -> anyhow::Result<bool> {
            Ok(false)
        }
    }
}

#[cfg(windows)]
mod win {
    use super::{policy, quarantine_name, Trust};
    use anyhow::{bail, Context, Result};
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::Path;
    use std::ptr::{addr_of, null, null_mut};
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, MoveFileExW, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    const READ_CONTROL: u32 = 0x0002_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    /// SYSTEM and Administrators: full control; Users: read and traverse. Protected: nothing inherited from above.
    const PROTECTED_SDDL: &str = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    pub fn file_info(h: RawHandle) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(h as _, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    /// Open a directory (or whatever is at `path`) for reading its attributes and security, without following a
    /// reparse point.
    fn open_entry(path: &Path) -> io::Result<OwnedHandle> {
        let w = wide(path.as_os_str());
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) })
    }

    fn sid_string(sid: *mut c_void) -> Result<String> {
        let mut s: *mut u16 = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
            return Err(io::Error::last_os_error()).context("converting a SID");
        }
        let mut len = 0;
        while unsafe { *s.add(len) } != 0 {
            len += 1;
        }
        let out = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) });
        unsafe { LocalFree(s as _) };
        Ok(out)
    }

    /// Owner SID and DACL (None: a NULL DACL, which grants everyone everything), read from the open handle.
    fn security(h: &OwnedHandle) -> Result<(String, Option<Vec<policy::WinAce>>)> {
        let mut owner: *mut c_void = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut sd: *mut c_void = null_mut();
        let rc = unsafe {
            GetSecurityInfo(
                h.as_raw_handle() as _,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner as *mut _ as _,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd as *mut _ as _,
            )
        };
        if rc != 0 {
            bail!("reading the security descriptor failed (error {rc})");
        }
        let read = || -> Result<(String, Option<Vec<policy::WinAce>>)> {
            let owner = sid_string(owner)?;
            if dacl.is_null() {
                return Ok((owner, None));
            }
            let count = unsafe { (*dacl).AceCount };
            let mut aces = Vec::with_capacity(count as usize);
            for i in 0..u32::from(count) {
                let mut ace: *mut c_void = null_mut();
                if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
                    return Err(io::Error::last_os_error()).context("reading an ACE");
                }
                let header = unsafe { &*(ace as *const ACE_HEADER) };
                // Allowed (0) and denied (1) ACEs share the ACCESS_ALLOWED_ACE layout. Other types are judged by
                // type alone in the policy.
                let (mask, sid) = if header.AceType <= 1 {
                    let a = ace as *const ACCESS_ALLOWED_ACE;
                    let sid = unsafe { addr_of!((*a).SidStart) } as *mut c_void;
                    (unsafe { (*a).Mask }, sid_string(sid)?)
                } else {
                    (0, String::new())
                };
                aces.push(policy::WinAce { ace_type: header.AceType, flags: header.AceFlags, mask, sid });
            }
            Ok((owner, Some(aces)))
        };
        let result = read();
        unsafe { LocalFree(sd as _) };
        result
    }

    /// None: nothing at `path`. Otherwise everything wrong with it in `role`.
    fn inspect(path: &Path, role: policy::WinRole, check_security: bool) -> Result<Option<Vec<String>>> {
        let h = match open_entry(path) {
            Ok(h) => h,
            Err(e) if matches!(e.raw_os_error(), Some(c) if c == ERROR_FILE_NOT_FOUND as i32 || c == ERROR_PATH_NOT_FOUND as i32) => {
                return Ok(None)
            }
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        };
        let attrs = file_info(h.as_raw_handle())?.dwFileAttributes;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(Some(vec!["it is a junction, symlink or other reparse point".into()]));
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Ok(Some(vec!["it is not a directory".into()]));
        }
        if !check_security {
            return Ok(Some(Vec::new()));
        }
        let (owner, dacl) = security(&h)?;
        Ok(Some(policy::windows_dir_problems(&owner, dacl.as_deref(), role)))
    }

    fn create_protected(dir: &Path) -> Result<()> {
        let sddl = wide(std::ffi::OsStr::new(PROTECTED_SDDL));
        let mut sd: *mut c_void = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd as *mut _ as _, null_mut())
        } == 0
        {
            return Err(io::Error::last_os_error()).context("building the runtime directory's security descriptor");
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd as _,
            bInheritHandle: 0,
        };
        let w = wide(dir.as_os_str());
        let ok = unsafe { CreateDirectoryW(w.as_ptr(), &sa) };
        let err = io::Error::last_os_error();
        unsafe { LocalFree(sd as _) };
        if ok == 0 {
            return Err(err).with_context(|| format!("creating {}", dir.display()));
        }
        Ok(())
    }

    fn refuse(path: &Path, problems: &[String]) -> anyhow::Error {
        anyhow::anyhow!("{} is not protected: {}", path.display(), problems.join("; "))
    }

    pub fn walk(dir: &Path, trust: Trust, create: bool) -> Result<()> {
        let checked = trust != Trust::Unchecked;
        if checked {
            if !dir.is_absolute() {
                bail!("{} must be an absolute path", dir.display());
            }
            // Nobody else may rename or re-permission a directory above it (which would let them swap it).
            for a in dir.ancestors().skip(1) {
                match inspect(a, policy::WinRole::Ancestor, true)? {
                    Some(p) if p.is_empty() => {}
                    Some(p) => return Err(refuse(a, &p)),
                    None => bail!("{} does not exist", a.display()),
                }
            }
        }
        match inspect(dir, policy::WinRole::Target, checked)? {
            Some(p) if p.is_empty() => return Ok(()),
            Some(p) if !create || !checked => return Err(refuse(dir, &p)),
            Some(_) => {
                let name = dir.file_name().context("runtime directory has no name")?;
                let aside = dir.with_file_name(quarantine_name(name));
                let (from, to) = (wide(dir.as_os_str()), wide(aside.as_os_str()));
                if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } == 0 {
                    return Err(io::Error::last_os_error())
                        .with_context(|| format!("moving aside unprotected {}", dir.display()));
                }
            }
            None if !create => bail!("{} does not exist", dir.display()),
            None => {}
        }
        if checked {
            create_protected(dir)?;
        } else {
            std::fs::create_dir(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        match inspect(dir, policy::WinRole::Target, checked)? {
            Some(p) if p.is_empty() => Ok(()),
            Some(p) => Err(refuse(dir, &p)),
            None => bail!("{} disappeared after it was created", dir.display()),
        }
    }
}

/// The rules, separated from the platform calls so they can be tested anywhere.
pub mod policy {
    // ---- Unix mode bits ----

    const S_IFMT: u32 = 0o170000;
    const S_IFDIR: u32 = 0o040000;

    /// Problems with a directory's owner and mode. The owner must be root, or `extra_trusted_uid` (tests). Group
    /// and others must not have write access (a sticky bit does not make a world-writable directory acceptable).
    pub fn unix_dir_problems(uid: u32, mode: u32, extra_trusted_uid: Option<u32>) -> Vec<String> {
        let mut p = Vec::new();
        if mode & S_IFMT != S_IFDIR {
            p.push("it is not a directory".into());
        }
        if uid != 0 && Some(uid) != extra_trusted_uid {
            p.push(format!("it is owned by uid {uid}, not root"));
        }
        if mode & 0o022 != 0 {
            p.push(format!("its mode {:o} lets group or others write", mode & 0o7777));
        }
        p
    }

    // ---- macOS extended ACLs (sys/acl.h) ----

    pub const MACOS_ACL_EXTENDED_ALLOW: i32 = 1;
    /// ACL_WRITE_DATA (= ADD_FILE), ACL_DELETE, ACL_APPEND_DATA (= ADD_SUBDIRECTORY), ACL_DELETE_CHILD,
    /// ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER.
    pub const MACOS_ACL_WRITE_PERMS: [u32; 8] = [1 << 2, 1 << 4, 1 << 5, 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 13];

    /// An allow entry with any write-type permission. Entries can only name users and groups by UUID, so any such
    /// entry is refused; root and the owner already have access through the mode bits.
    pub fn macos_acl_entry_grants_write(tag: i32, perms: u32) -> bool {
        let write = MACOS_ACL_WRITE_PERMS.iter().fold(0, |a, b| a | b);
        tag == MACOS_ACL_EXTENDED_ALLOW && perms & write != 0
    }

    // ---- Linux POSIX ACLs (system.posix_acl_access / system.posix_acl_default xattrs) ----

    const ACL_USER_OBJ: u16 = 0x01;
    const ACL_MASK: u16 = 0x10;
    const ACL_OTHER: u16 = 0x20;
    const ACL_WRITE: u16 = 0x02;

    /// Whether an ACL xattr gives anyone but the owning user write access, after the mask. For a default ACL this
    /// is what new files and directories created inside would grant.
    pub fn posix_acl_grants_write(xattr: &[u8]) -> Result<bool, String> {
        if xattr.len() < 4 || !(xattr.len() - 4).is_multiple_of(8) {
            return Err("malformed POSIX ACL".into());
        }
        if u32::from_le_bytes([xattr[0], xattr[1], xattr[2], xattr[3]]) != 2 {
            return Err("unsupported POSIX ACL version".into());
        }
        let entries: Vec<(u16, u16)> = xattr[4..]
            .chunks_exact(8)
            .map(|e| (u16::from_le_bytes([e[0], e[1]]), u16::from_le_bytes([e[2], e[3]])))
            .collect();
        let mask = entries.iter().find(|(tag, _)| *tag == ACL_MASK).map(|(_, perm)| *perm);
        Ok(entries.iter().any(|&(tag, perm)| {
            let effective = match (tag, mask) {
                (ACL_USER_OBJ | ACL_MASK, _) => 0,
                (ACL_OTHER, _) | (_, None) => perm,
                (_, Some(m)) => perm & m,
            };
            effective & ACL_WRITE != 0
        }))
    }

    // ---- Windows owner and DACL ----

    pub const SID_SYSTEM: &str = "S-1-5-18";
    pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
    pub const SID_TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    /// One ACE as read from a DACL. `sid` and `mask` are filled only for access-allowed (0) and access-denied (1)
    /// ACEs.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct WinAce {
        pub ace_type: u8,
        pub flags: u8,
        pub mask: u32,
        pub sid: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WinRole {
        /// The runtime directory itself: nobody else may write anything into it or change it.
        Target,
        /// A directory above it: nobody else may delete, rename or re-permission entries in it or the directory
        /// itself. Adding new entries (as Users may in ProgramData) is fine.
        Ancestor,
    }

    const INHERIT_ONLY_ACE: u8 = 0x08;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_DELETE_CHILD: u32 = 0x0040;
    /// FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES plus the above.
    const TARGET_WRITE: u32 =
        0x0002 | 0x0004 | 0x0010 | 0x0100 | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;
    const ANCESTOR_WRITE: u32 = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

    /// Problems with a directory's owner and DACL (`None`: a NULL DACL). Pre-existing grants count: every
    /// allow ACE is judged, explicit or inherited. On the target, inherit-only ACEs count too, since they decide
    /// what files created inside will allow.
    pub fn windows_dir_problems(owner: &str, dacl: Option<&[WinAce]>, role: WinRole) -> Vec<String> {
        let mut p = Vec::new();
        let owner_ok = match role {
            WinRole::Target => [SID_SYSTEM, SID_ADMINISTRATORS].contains(&owner),
            WinRole::Ancestor => [SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER].contains(&owner),
        };
        if !owner_ok {
            p.push(format!("it is owned by {owner}, not SYSTEM or Administrators"));
        }
        let Some(aces) = dacl else {
            p.push("it has a NULL DACL, which grants everyone full access".into());
            return p;
        };
        let (write, trusted): (u32, &[&str]) = match role {
            WinRole::Target => (TARGET_WRITE, &[SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER]),
            WinRole::Ancestor => (ANCESTOR_WRITE, &[SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER]),
        };
        for ace in aces {
            if role == WinRole::Ancestor && ace.flags & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            match ace.ace_type {
                // Access allowed.
                0 => {
                    if ace.mask & write != 0 && !trusted.contains(&ace.sid.as_str()) {
                        p.push(format!("an ACE grants {} access mask {:#x}", ace.sid, ace.mask));
                    }
                }
                // Access denied, in its plain, object and callback forms: only ever removes access.
                1 | 6 | 10 | 12 => {}
                other => p.push(format!("it has an ACE of unsupported type {other}")),
            }
        }
        p
    }
}
