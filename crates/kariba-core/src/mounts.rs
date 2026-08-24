use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub mount_point: PathBuf,
    pub fs_type: String,
    pub source: String,
}

// Filesystem types worth scanning: real local storage users put files on.
// Allow-list (not deny-list) so unknown pseudo-filesystems are never marked.
const WATCHABLE_FS_TYPES: &[&str] = &[
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "tmpfs", "exfat", "vfat", "msdos",
    "ntfs", "ntfs3", "fuseblk", "iso9660", "udf", "jfs", "reiserfs",
];

// Mount points under these paths are runtime/kernel state, never user data.
const SKIP_MOUNT_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/run"];

pub fn list_mounts() -> std::io::Result<Vec<Mount>> {
    Ok(parse_mountinfo(&fs::read_to_string(
        "/proc/self/mountinfo",
    )?))
}

pub fn parse_mountinfo(content: &str) -> Vec<Mount> {
    content.lines().filter_map(parse_line).collect()
}

// mountinfo line: id parent major:minor root mount_point options
//                 [optional fields...]* "-" fs_type source super_options
fn parse_line(line: &str) -> Option<Mount> {
    let mut fields = line.split_whitespace();
    let _mount_id = fields.next()?;
    let _parent_id = fields.next()?;
    let _dev = fields.next()?;
    let _root = fields.next()?;
    let mount_point = unescape(fields.next()?);
    let _options = fields.next()?;
    let fs_type = loop {
        let field = fields.next()?;
        if field == "-" {
            break fields.next()?;
        }
    };
    let source = fields.next().map(unescape).unwrap_or_default();
    Some(Mount {
        mount_point: PathBuf::from(mount_point),
        fs_type: fs_type.to_string(),
        source,
    })
}

// mountinfo escapes spaces/tabs/newlines/backslashes as octal (\040 etc.).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let code: String = chars.by_ref().take(3).collect();
            if code.len() == 3
                && let Ok(byte) = u8::from_str_radix(&code, 8)
            {
                out.push(byte as char);
            } else {
                out.push('\\');
                out.push_str(&code);
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn is_watchable(mount: &Mount) -> bool {
    if !WATCHABLE_FS_TYPES.contains(&mount.fs_type.as_str()) {
        return false;
    }
    let mount_point = mount.mount_point.to_string_lossy();
    !SKIP_MOUNT_PREFIXES
        .iter()
        .any(|prefix| mount_point == *prefix || mount_point.starts_with(&format!("{prefix}/")))
}

/// All mounts worth marking for real-time protection. Bind mounts inside an
/// already-watched mount may produce duplicate events; the verdict cache
/// absorbs those — over-marking costs event volume, under-marking leaves
/// protection gaps, so everything watchable is kept.
pub fn watchable_mounts(mounts: &[Mount]) -> Vec<Mount> {
    mounts.iter().filter(|m| is_watchable(m)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
36 35 98:0 /mnt1 / rw,noatime master:1 - ext4 /dev/sda1 rw,errors=continue
37 36 0:30 / /tmp rw,nosuid,nodev shared:2 - tmpfs tmpfs rw,mode=1777
38 36 0:31 / /run/user/1000 rw,nosuid,nodev - tmpfs tmpfs rw
39 36 0:32 / /proc rw - proc proc rw
40 36 0:33 / /sys rw - sysfs sysfs rw
41 36 8:17 / /home/stikyt rw - btrfs /dev/sdb1 rw
42 36 0:34 / /mnt/usb\\040disk rw - vfat /dev/sdc1 rw
";

    #[test]
    fn parses_mountinfo_fixture() {
        let mounts = parse_mountinfo(FIXTURE);
        assert_eq!(mounts.len(), 7);
        assert_eq!(mounts[0].mount_point, PathBuf::from("/"));
        assert_eq!(mounts[0].fs_type, "ext4");
        assert_eq!(mounts[0].source, "/dev/sda1");
        assert_eq!(mounts[5].fs_type, "btrfs");
    }

    #[test]
    fn unescapes_octal_sequences() {
        let mounts = parse_mountinfo(FIXTURE);
        assert_eq!(mounts[6].mount_point, PathBuf::from("/mnt/usb disk"));
    }

    #[test]
    fn filters_pseudo_and_runtime_mounts() {
        let mounts = parse_mountinfo(FIXTURE);
        let watchable = watchable_mounts(&mounts);
        let points: Vec<&str> = watchable
            .iter()
            .map(|m| m.mount_point.to_str().unwrap())
            .collect();
        assert!(points.contains(&"/"));
        assert!(points.contains(&"/tmp"));
        assert!(points.contains(&"/home/stikyt"));
        assert!(points.contains(&"/mnt/usb disk"));
        assert!(!points.contains(&"/proc"));
        assert!(!points.contains(&"/sys"));
        assert!(!points.contains(&"/run/user/1000"));
    }

    #[test]
    fn live_mounts_include_root() {
        let mounts = list_mounts().expect("read mountinfo");
        assert!(!mounts.is_empty());
        let watchable = watchable_mounts(&mounts);
        assert!(
            watchable
                .iter()
                .any(|m| m.mount_point == PathBuf::from("/")),
            "root filesystem should be watchable"
        );
    }
}
