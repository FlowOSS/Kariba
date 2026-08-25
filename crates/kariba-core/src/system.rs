//! System facts: total RAM (for sizing decisions like the verdict cache).

/// Total system RAM in bytes, from `/proc/meminfo`.
pub fn total_ram_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_total_kb(&meminfo).map(|kb| kb.saturating_mul(1024))
}

/// Parse the `MemTotal` line of meminfo content into kilobytes.
pub fn parse_mem_total_kb(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:")
            && let Some(kb) = rest.split_whitespace().next()
        {
            return kb.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mem_total() {
        let sample = "MemTotal:       65688340 kB\nMemFree:         1234 kB\n";
        assert_eq!(parse_mem_total_kb(sample), Some(65_688_340));
    }

    #[test]
    fn parses_missing_mem_total() {
        assert_eq!(parse_mem_total_kb("MemFree: 1234 kB\n"), None);
    }

    #[test]
    fn reads_real_meminfo() {
        // Any Linux box has RAM; a zero/None here means the parser broke.
        assert!(total_ram_bytes().is_some_and(|b| b > 0));
    }
}
