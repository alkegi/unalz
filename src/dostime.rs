//! DOS timestamp conversion.

use std::time::SystemTime;

/// Convert DOS date/time (as stored in ALZ headers) to SystemTime.
/// DOS time format:
///   bits 0-4:  seconds/2 (0-29)
///   bits 5-10: minutes (0-59)
///   bits 11-15: hours (0-23)
///   bits 16-20: day (1-31)
///   bits 21-24: month (1-12)
///   bits 25-31: year offset from 1980
pub fn dos_datetime_to_systime(dostime: u32) -> Option<SystemTime> {
    let sec = (dostime & 0x1f) << 1;
    let min = (dostime >> 5) & 0x3f;
    let hour = (dostime >> 11) & 0x1f;
    let day = (dostime >> 16) & 0x1f;
    let month = (dostime >> 21) & 0x0f;
    let year = ((dostime >> 25) & 0x7f) + 1980;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let days = days_from_epoch(year, month, day);
    let secs = days as u64 * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64;

    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

/// Format DOS datetime for display (YYYY-MM-DD HH:MM:SS).
pub fn dos_datetime_to_string(dostime: u32) -> String {
    let sec = (dostime & 0x1f) << 1;
    let min = (dostime >> 5) & 0x3f;
    let hour = (dostime >> 11) & 0x1f;
    let day = (dostime >> 16) & 0x1f;
    let month = (dostime >> 21) & 0x0f;
    let year = ((dostime >> 25) & 0x7f) + 1980;

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
}

fn days_from_epoch(year: u32, month: u32, day: u32) -> i64 {
    // Howard Hinnant's algorithm for days since 1970-01-01.
    let y = if month <= 2 {
        year as i64 - 1
    } else {
        year as i64
    };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let m = month as i64;
    let doy = if m > 2 {
        (153 * (m - 3) + 2) / 5 + day as i64 - 1
    } else {
        (153 * (m + 9) + 2) / 5 + day as i64 - 1
    };
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    era * 146097 + doe as i64 - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_datetime_to_string() {
        // 2019-04-12 04:16:18
        assert_eq!(dos_datetime_to_string(0x4E8C2209), "2019-04-12 04:16:18");
        // 1980-01-01 00:00:00 (minimum DOS date)
        assert_eq!(dos_datetime_to_string(0x00210000), "1980-01-01 00:00:00");
    }

    #[test]
    fn test_dos_datetime_to_systime() {
        // 2019-04-12 04:16:18 -> Unix timestamp 1555042578
        let t = dos_datetime_to_systime(0x4E8C2209).unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1555042578);
    }

    #[test]
    fn test_invalid_date() {
        // Month 0 is invalid
        assert!(dos_datetime_to_systime(0).is_none());
    }
}
