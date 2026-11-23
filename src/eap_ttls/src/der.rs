//! der.rs - Minimal X.509 validity extraction for time-bypass logic.

pub fn extract_cert_validity_secs(der: &[u8]) -> Option<(u64, u64)> {
    if der.len() < 4 || der[0] != 0x30 {
        return None;
    }
    // Scan for validity SEQUENCE containing two time tags (0x17 UTCTime or 0x18 GeneralizedTime)
    for i in 0..der.len().saturating_sub(32) {
        if der[i] == 0x30 {
            let mut pos = i + 2;
            if der[i + 1] & 0x80 != 0 {
                let nbytes = (der[i + 1] & 0x7f) as usize;
                pos = i + 2 + nbytes;
            }
            if pos >= der.len() {
                continue;
            }
            let tag1 = der[pos];
            if (tag1 == 0x17 || tag1 == 0x18) && pos + 1 < der.len() {
                let len1 = der[pos + 1] as usize;
                let t1_start = pos + 2;
                let t1_end = t1_start + len1;
                if t1_end + 2 < der.len() {
                    let tag2 = der[t1_end];
                    if tag2 == 0x17 || tag2 == 0x18 {
                        let len2 = der[t1_end + 1] as usize;
                        let t2_start = t1_end + 2;
                        let t2_end = t2_start + len2;
                        if t2_end <= der.len() {
                            let s1 = std::str::from_utf8(&der[t1_start..t1_end]).ok()?;
                            let s2 = std::str::from_utf8(&der[t2_start..t2_end]).ok()?;
                            let ts1 = parse_x509_time(s1, tag1 == 0x17)?;
                            let ts2 = parse_x509_time(s2, tag2 == 0x17)?;
                            return Some((ts1, ts2));
                        }
                    }
                }
            }
        }
    }
    None
}

fn parse_x509_time(s: &str, is_utc: bool) -> Option<u64> {
    let (year, rest) = if is_utc {
        if s.len() < 13 {
            return None;
        }
        let yy: u64 = s[0..2].parse().ok()?;
        let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (full_year, &s[2..])
    } else {
        if s.len() < 15 {
            return None;
        }
        let yyyy: u64 = s[0..4].parse().ok()?;
        (yyyy, &s[4..])
    };
    let month: u64 = rest[0..2].parse().ok()?;
    let day: u64 = rest[2..4].parse().ok()?;
    let hour: u64 = rest[4..6].parse().ok()?;
    let min: u64 = rest[6..8].parse().ok()?;
    let sec: u64 = rest[8..10].parse().ok()?;

    let mut days = (year - 1970) * 365 + (year - 1969) / 4;
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[m as usize];
    }
    if month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        days += 1;
    }
    days += day - 1;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_parsing() {
        // 2024-01-01 00:00:00 UTC
        let t1 = parse_x509_time("240101000000Z", true).unwrap();
        assert_eq!(t1, 1704067200);
    }
}
