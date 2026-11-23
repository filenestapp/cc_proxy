//! Issue #1: the supervisor reads the client's config through one link-safe handle, and writes only into a
//! runtime directory that no other account can write to, rename or replace.

use ccproxy_core::fsguard::policy::{self, WinAce, WinRole};
use ccproxy_core::fsguard::read_regular_file;
use std::fs;
use std::path::PathBuf;

const MAX: u64 = 1 << 20;

fn scratch(tag: &str) -> PathBuf {
    // Canonical, so the privileged-style walk does not meet a symlink such as macOS's /var.
    let base = fs::canonicalize(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let d = base.join(format!("fsguard-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

// ---- policy rules (all platforms) ------------------------------------------------------------------------

#[test]
fn unix_mode_rules() {
    const DIR: u32 = 0o040000;
    assert!(policy::unix_dir_problems(0, DIR | 0o755, None).is_empty());
    assert!(!policy::unix_dir_problems(501, DIR | 0o755, None).is_empty(), "non-root owner");
    assert!(policy::unix_dir_problems(501, DIR | 0o700, Some(501)).is_empty());
    assert!(!policy::unix_dir_problems(0, DIR | 0o775, None).is_empty(), "group-writable");
    assert!(!policy::unix_dir_problems(0, DIR | 0o1777, None).is_empty(), "sticky does not help");
    assert!(!policy::unix_dir_problems(0, 0o100644, None).is_empty(), "not a directory");
}

fn posix_acl(entries: &[(u16, u16)]) -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    for (tag, perm) in entries {
        v.extend(tag.to_le_bytes());
        v.extend(perm.to_le_bytes());
        v.extend(0u32.to_le_bytes());
    }
    v
}

#[test]
fn linux_posix_acl_rules() {
    let (user_obj, user, group_obj, mask, other) = (0x01, 0x02, 0x04, 0x10, 0x20);
    let plain = posix_acl(&[(user_obj, 7), (group_obj, 5), (other, 5)]);
    assert_eq!(policy::posix_acl_grants_write(&plain), Ok(false));
    let named_rwx_mask_rwx = posix_acl(&[(user_obj, 7), (user, 7), (group_obj, 5), (mask, 7), (other, 5)]);
    assert_eq!(policy::posix_acl_grants_write(&named_rwx_mask_rwx), Ok(true));
    let named_rwx_mask_rx = posix_acl(&[(user_obj, 7), (user, 7), (group_obj, 5), (mask, 5), (other, 5)]);
    assert_eq!(policy::posix_acl_grants_write(&named_rwx_mask_rx), Ok(false), "masked out");
    let other_w = posix_acl(&[(user_obj, 7), (group_obj, 5), (other, 7)]);
    assert_eq!(policy::posix_acl_grants_write(&other_w), Ok(true));
    assert!(policy::posix_acl_grants_write(&[1, 0, 0]).is_err(), "malformed");
    assert!(policy::posix_acl_grants_write(&[3, 0, 0, 0]).is_err(), "unknown version");
}

#[test]
fn macos_acl_rules() {
    let (allow, deny) = (policy::MACOS_ACL_EXTENDED_ALLOW, 2);
    let add_file = 1 << 2;
    let read_data = 1 << 1;
    assert!(policy::macos_acl_entry_grants_write(allow, add_file));
    assert!(!policy::macos_acl_entry_grants_write(allow, read_data));
    assert!(!policy::macos_acl_entry_grants_write(deny, add_file), "deny entries only take access away");
}

fn allow(sid: &str, flags: u8, mask: u32) -> WinAce {
    WinAce { ace_type: 0, flags, mask, sid: sid.into() }
}

const SY: &str = policy::SID_SYSTEM;
const BA: &str = policy::SID_ADMINISTRATORS;
const TI: &str = policy::SID_TRUSTED_INSTALLER;
const USERS: &str = "S-1-5-32-545";
const AUTH_USERS: &str = "S-1-5-11";
const CREATOR_OWNER: &str = "S-1-3-0";
const SOME_USER: &str = "S-1-5-21-1-2-3-1001";
const OICI: u8 = 0x01 | 0x02;
const IO: u8 = 0x08;
const INHERITED: u8 = 0x10;

/// What `PROTECTED_SDDL` produces: SYSTEM and Administrators full, Users read + execute.
fn ours() -> Vec<WinAce> {
    vec![allow(SY, OICI, 0x1f01ff), allow(BA, OICI, 0x1f01ff), allow(USERS, OICI, 0x1200a9)]
}

#[test]
fn windows_runtime_dir_rules() {
    assert!(policy::windows_dir_problems(BA, Some(&ours()), WinRole::Target).is_empty());
    assert!(policy::windows_dir_problems(SY, Some(&ours()), WinRole::Target).is_empty());

    // Created by a user before installation: owned by them.
    assert!(!policy::windows_dir_problems(SOME_USER, Some(&ours()), WinRole::Target).is_empty());
    // Pre-existing explicit grant that the old icacls /grant:r call left in place.
    let mut granted = ours();
    granted.push(allow(SOME_USER, OICI, 0x1301bf)); // Modify
    assert!(!policy::windows_dir_problems(BA, Some(&granted), WinRole::Target).is_empty());
    // Inherited from ProgramData: Users may create files and folders.
    let mut inherited = ours();
    inherited.push(allow(USERS, 0x02 | INHERITED, 0x0116)); // WD, AD, WEA, WA
    assert!(!policy::windows_dir_problems(BA, Some(&inherited), WinRole::Target).is_empty());
    // CREATOR OWNER, inherit-only: decides what files created inside allow.
    let mut creator = ours();
    creator.push(allow(CREATOR_OWNER, OICI | IO, 0x1000_0000));
    assert!(!policy::windows_dir_problems(BA, Some(&creator), WinRole::Target).is_empty());
    // A generic write bit counts.
    let mut generic = ours();
    generic.push(allow(AUTH_USERS, 0, 0x4000_0000));
    assert!(!policy::windows_dir_problems(BA, Some(&generic), WinRole::Target).is_empty());
    // NULL DACL.
    assert!(!policy::windows_dir_problems(BA, None, WinRole::Target).is_empty());
    // Deny ACEs never make things worse.
    let mut denied = ours();
    denied.insert(0, WinAce { ace_type: 1, flags: 0, mask: 0x1f01ff, sid: SOME_USER.into() });
    assert!(policy::windows_dir_problems(BA, Some(&denied), WinRole::Target).is_empty());
    // Object / callback allow ACEs are not interpreted, so they are refused.
    let mut object = ours();
    object.push(WinAce { ace_type: 5, flags: 0, mask: 0, sid: String::new() });
    assert!(!policy::windows_dir_problems(BA, Some(&object), WinRole::Target).is_empty());
}

#[test]
fn windows_default_ancestors_are_accepted_and_tampered_ones_refused() {
    // C:\ (owner TrustedInstaller on current Windows) and C:\ProgramData (owner SYSTEM) with their default DACLs.
    let root = vec![
        allow(BA, OICI, 0x1f01ff),
        allow(SY, OICI, 0x1f01ff),
        allow(USERS, OICI, 0x1200a9),
        allow(AUTH_USERS, OICI | IO, 0xe0010000), // Modify, inherit-only
        allow(AUTH_USERS, 0, 0x0004),             // add subdirectory
    ];
    assert!(policy::windows_dir_problems(TI, Some(&root), WinRole::Ancestor).is_empty());
    let program_data = vec![
        allow(SY, OICI, 0x1f01ff),
        allow(BA, OICI, 0x1f01ff),
        allow(CREATOR_OWNER, OICI | IO, 0x1000_0000),
        allow(USERS, OICI, 0x1200a9),
        allow(USERS, 0x02, 0x0116), // WD, AD, WEA, WA: users may add entries
    ];
    assert!(policy::windows_dir_problems(SY, Some(&program_data), WinRole::Ancestor).is_empty());

    // Someone else may delete or rename entries in the parent, so could swap the runtime directory.
    let mut delete_child = program_data.clone();
    delete_child.push(allow(USERS, 0, 0x0040));
    assert!(!policy::windows_dir_problems(SY, Some(&delete_child), WinRole::Ancestor).is_empty());
    let mut write_dac = program_data.clone();
    write_dac.push(allow(SOME_USER, 0, 0x0004_0000));
    assert!(!policy::windows_dir_problems(SY, Some(&write_dac), WinRole::Ancestor).is_empty());
    assert!(!policy::windows_dir_problems(SOME_USER, Some(&program_data), WinRole::Ancestor).is_empty());
}

// ---- reading through one handle (Unix) -------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn config_read_refuses_links_fifos_hard_links_and_oversized_files_on_the_handle() {
    use std::os::unix::fs::symlink;
    let d = scratch("read");
    let cfg = d.join("sing-box.json");
    fs::write(&cfg, b"{\"ok\": true}").unwrap();
    assert_eq!(read_regular_file(&cfg, MAX).unwrap(), b"{\"ok\": true}");

    // A symlink (to a file the user may not read) is not followed.
    let link = d.join("link.json");
    symlink(&cfg, &link).unwrap();
    assert!(read_regular_file(&link, MAX).is_err());

    // A hard link would let the user point a privileged reader at a file they do not own.
    let other = d.join("other");
    fs::write(&other, b"secret").unwrap();
    let hard = d.join("hard.json");
    fs::hard_link(&other, &hard).unwrap();
    let err = read_regular_file(&hard, MAX).unwrap_err().to_string();
    assert!(err.contains("hard link"), "{err}");

    // A FIFO is refused without blocking the supervisor.
    let fifo = d.join("fifo.json");
    let c = std::ffi::CString::new(fifo.as_os_str().to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    assert!(read_regular_file(&fifo, MAX).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(2));

    // A directory, a missing file, an oversized file.
    assert!(read_regular_file(&d, MAX).is_err());
    assert!(read_regular_file(&d.join("missing"), MAX).is_err());
    fs::write(&cfg, vec![b' '; MAX as usize + 1]).unwrap();
    assert!(read_regular_file(&cfg, MAX).is_err());
    fs::remove_dir_all(&d).unwrap();
}

// ---- protected directory (Unix) ---------------------------------------------------------------------------

#[cfg(unix)]
mod unix_dir {
    use super::scratch;
    use ccproxy_core::fsguard::{prepare_dir, verify_dir, Trust};
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::Path;

    fn me() -> Trust {
        Trust::Uid(unsafe { libc::geteuid() })
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    fn quarantined(parent: &Path) -> Vec<String> {
        fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".untrusted-"))
            .collect()
    }

    #[test]
    fn fresh_directory_is_created_owner_only_writable_and_verifies() {
        let d = scratch("fresh");
        let rt = d.join("runtime");
        prepare_dir(&rt, me()).unwrap();
        assert_eq!(mode(&rt), 0o755);
        verify_dir(&rt, me()).unwrap();
        prepare_dir(&rt, me()).unwrap(); // idempotent: a good directory is kept as is
        assert!(quarantined(&d).is_empty());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn group_writable_existing_directory_is_moved_aside_not_repaired() {
        let d = scratch("gw");
        let rt = d.join("runtime");
        fs::create_dir(&rt).unwrap();
        fs::write(rt.join("planted"), b"x").unwrap();
        fs::set_permissions(&rt, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(verify_dir(&rt, me()).is_err(), "verification alone never changes it");
        assert_eq!(mode(&rt), 0o777);
        prepare_dir(&rt, me()).unwrap();
        assert_eq!(mode(&rt), 0o755);
        assert!(!rt.join("planted").exists(), "nothing written by others is carried over");
        assert_eq!(quarantined(&d).len(), 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn symlink_in_place_of_the_directory_is_moved_aside() {
        let d = scratch("link");
        let target = d.join("elsewhere");
        fs::create_dir(&target).unwrap();
        let rt = d.join("runtime");
        symlink(&target, &rt).unwrap();
        assert!(verify_dir(&rt, me()).is_err());
        prepare_dir(&rt, me()).unwrap();
        assert!(!fs::symlink_metadata(&rt).unwrap().file_type().is_symlink());
        assert!(target.is_dir(), "the link target is left alone");
        // In test mode (no ownership checks) a link is still an error, not something to move.
        let rt2 = d.join("runtime2");
        symlink(&target, &rt2).unwrap();
        assert!(prepare_dir(&rt2, Trust::Unchecked).is_err());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn unsafe_ancestors_are_refused() {
        let d = scratch("anc");
        // A symlink in the path.
        let real = d.join("real");
        fs::create_dir(&real).unwrap();
        symlink(&real, d.join("via")).unwrap();
        let err = prepare_dir(&d.join("via").join("runtime"), me()).unwrap_err().to_string();
        assert!(err.contains("not a link"), "{err}");
        assert!(!real.join("runtime").exists());
        // A group-writable directory above it: whoever can write there can swap the runtime directory.
        let open = d.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_dir(&open.join("runtime"), me()).is_err());
        assert!(!open.join("runtime").exists());
        // Relative paths are refused.
        assert!(prepare_dir(Path::new("relative/runtime"), me()).is_err());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn production_trust_requires_root_ownership() {
        if unsafe { libc::geteuid() } == 0 {
            return; // as root, the scratch directory is root-owned; covered by the other tests
        }
        let d = scratch("root");
        assert!(verify_dir(&d, Trust::Privileged).is_err());
        assert!(prepare_dir(&d.join("runtime"), Trust::Privileged).is_err());
        assert!(!d.join("runtime").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_acl_grant_is_refused_on_the_directory_and_its_ancestors() {
        let chmod_acl = |p: &Path, op: &str| {
            let ok = std::process::Command::new("/bin/chmod").args([op, "everyone allow add_file,add_subdirectory"]).arg(p).status().unwrap();
            assert!(ok.success());
        };
        let d = scratch("macacl");
        let rt = d.join("runtime");
        prepare_dir(&rt, me()).unwrap();
        chmod_acl(&rt, "+a");
        assert_eq!(mode(&rt), 0o755, "mode bits alone look fine");
        let err = verify_dir(&rt, me()).unwrap_err().to_string();
        assert!(err.contains("ACL"), "{err}");
        prepare_dir(&rt, me()).unwrap();
        verify_dir(&rt, me()).unwrap();
        assert_eq!(quarantined(&d).len(), 1);

        let parent = d.join("parent");
        fs::create_dir(&parent).unwrap();
        chmod_acl(&parent, "+a");
        assert!(prepare_dir(&parent.join("runtime"), me()).is_err());
        chmod_acl(&parent, "-a");
        fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_acl_grant_is_refused() {
        let have_setfacl = std::process::Command::new("setfacl").arg("--version").output().is_ok();
        if !have_setfacl {
            eprintln!("setfacl not installed; POSIX ACL rule covered by linux_posix_acl_rules only");
            return;
        }
        let d = scratch("lxacl");
        let rt = d.join("runtime");
        prepare_dir(&rt, me()).unwrap();
        // A default ACL does not show in the mode bits but makes everything created inside writable by nobody.
        let ok = std::process::Command::new("setfacl").args(["-d", "-m", "u:nobody:rwx"]).arg(&rt).status().unwrap();
        assert!(ok.success());
        assert_eq!(mode(&rt), 0o755);
        assert!(verify_dir(&rt, me()).is_err());
        prepare_dir(&rt, me()).unwrap();
        verify_dir(&rt, me()).unwrap();
        fs::remove_dir_all(&d).unwrap();
    }
}
