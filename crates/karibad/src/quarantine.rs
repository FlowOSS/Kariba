use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub struct Quarantine {
    dir: PathBuf,
}

pub struct Quarantined {
    pub blob_path: PathBuf,
    pub size: u64,
    pub original_mode: u32,
}

impl Quarantine {
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn put(&self, threat_id: u64, path: &Path) -> io::Result<Quarantined> {
        let metadata = fs::metadata(path)?;
        let size = metadata.len();
        let original_mode = metadata.permissions().mode() & 0o7777;

        let blob_path = self.dir.join(format!("{threat_id}.quar"));
        move_file(path, &blob_path)?;
        fs::set_permissions(&blob_path, fs::Permissions::from_mode(0o000))?;

        Ok(Quarantined {
            blob_path,
            size,
            original_mode,
        })
    }

    pub fn restore(&self, blob_path: &Path, original: &Path, mode: u32) -> io::Result<()> {
        if let Some(parent) = original.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::set_permissions(blob_path, fs::Permissions::from_mode(0o400))?;
        fs::copy(blob_path, original)?;
        fs::set_permissions(original, fs::Permissions::from_mode(mode))?;
        fs::remove_file(blob_path)
    }

    pub fn delete(&self, blob_path: &Path) -> io::Result<()> {
        fs::remove_file(blob_path)
    }
}

fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    const EXDEV: i32 = 18;
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(EXDEV) => {
            fs::copy(from, to)?;
            fs::remove_file(from)
        }
        Err(e) => Err(e),
    }
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.write_all(&buf[..n])?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_makes_blob_unreadable_and_restore_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::new(dir.path().join("quarantine")).unwrap();

        let original = dir.path().join("subdir/malware.bin");
        fs::create_dir_all(original.parent().unwrap()).unwrap();
        fs::write(&original, b"fake malware bytes").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();

        let quarantined = q.put(1, &original).unwrap();
        assert!(!original.exists());
        assert_eq!(quarantined.size, 18);
        assert_eq!(quarantined.original_mode, 0o644);
        assert_eq!(
            quarantined
                .blob_path
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0
        );

        q.restore(&quarantined.blob_path, &original, quarantined.original_mode)
            .unwrap();
        assert_eq!(fs::read(&original).unwrap(), b"fake malware bytes");
        assert!(!quarantined.blob_path.exists());
    }

    #[test]
    fn sha256_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"hello").unwrap();
        let hash = sha256_file(&file).unwrap();
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
