use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistroFamily {
    Arch,
    Debian,
    Fedora,
    Suse,
    Unknown,
}

impl fmt::Display for DistroFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            DistroFamily::Arch => "Arch",
            DistroFamily::Debian => "Debian",
            DistroFamily::Fedora => "Fedora",
            DistroFamily::Suse => "SUSE",
            DistroFamily::Unknown => "unknown",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distro {
    pub id: String,
    pub id_like: Vec<String>,
    pub name: String,
    pub pretty_name: String,
    pub family: DistroFamily,
}

impl Distro {
    fn unknown() -> Self {
        Distro {
            id: "unknown".into(),
            id_like: Vec::new(),
            name: "Unknown Linux".into(),
            pretty_name: "Unknown Linux".into(),
            family: DistroFamily::Unknown,
        }
    }
}

impl fmt::Display for Distro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.pretty_name, self.family)
    }
}

pub fn detect_distro() -> Distro {
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(content) = fs::read_to_string(path) {
            return parse_os_release(&content);
        }
    }
    Distro::unknown()
}

pub fn parse_os_release(content: &str) -> Distro {
    let mut id = String::new();
    let mut id_like = Vec::new();
    let mut name = String::new();
    let mut pretty_name = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(value.trim());
        match key {
            "ID" => id = value.to_lowercase(),
            "ID_LIKE" => id_like = value.split_whitespace().map(|s| s.to_lowercase()).collect(),
            "NAME" => name = value.to_string(),
            "PRETTY_NAME" => pretty_name = value.to_string(),
            _ => {}
        }
    }

    if name.is_empty() {
        name = id.clone();
    }
    if pretty_name.is_empty() {
        pretty_name = name.clone();
    }

    let family = resolve_family(&id, &id_like);
    Distro {
        id,
        id_like,
        name,
        pretty_name,
        family,
    }
}

fn unquote(value: &str) -> &str {
    value.trim_matches(|c| c == '"' || c == '\'')
}

fn resolve_family(id: &str, id_like: &[String]) -> DistroFamily {
    for token in std::iter::once(id).chain(id_like.iter().map(String::as_str)) {
        let family = match token {
            "arch" | "artix" | "manjaro" | "endeavouros" => Some(DistroFamily::Arch),
            "debian" | "ubuntu" | "mint" => Some(DistroFamily::Debian),
            "fedora" | "rhel" | "centos" | "rocky" | "almalinux" => Some(DistroFamily::Fedora),
            "suse" => Some(DistroFamily::Suse),
            _ => None,
        };
        if let Some(family) = family {
            return family;
        }
        if token.starts_with("opensuse") {
            return DistroFamily::Suse;
        }
    }
    DistroFamily::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_artix() {
        let d = parse_os_release(
            "NAME=\"Artix Linux\"\nPRETTY_NAME=\"Artix Linux\"\nID=artix\nID_LIKE=arch\n",
        );
        assert_eq!(d.id, "artix");
        assert_eq!(d.family, DistroFamily::Arch);
        assert_eq!(d.pretty_name, "Artix Linux");
    }

    #[test]
    fn parses_ubuntu_via_id_like() {
        let d = parse_os_release("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n");
        assert_eq!(d.family, DistroFamily::Debian);
    }

    #[test]
    fn parses_fedora() {
        let d = parse_os_release("ID=fedora\nNAME=Fedora\n");
        assert_eq!(d.family, DistroFamily::Fedora);
    }

    #[test]
    fn handles_quotes_and_comments() {
        let d = parse_os_release("# comment\nID=\"opensuse-tumbleweed\"\n");
        assert_eq!(d.id, "opensuse-tumbleweed");
        assert_eq!(d.family, DistroFamily::Suse);
    }

    #[test]
    fn empty_content_is_unknown() {
        let d = parse_os_release("");
        assert_eq!(d.family, DistroFamily::Unknown);
    }

    #[test]
    fn detects_this_host() {
        let d = detect_distro();
        assert!(!d.id.is_empty());
    }
}
