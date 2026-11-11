//! Unix time formatting without a date library.

/// Formats a Unix timestamp as an RFC 3339 UTC time, e.g. `2026-11-09T00:00:00Z`.
pub fn format_unix(seconds: u64) -> String {
    let days = seconds / 86_400;
    let rem = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`, for days since 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// Formats a duration in seconds, e.g. `2d 3h`, `3h 5m`, `5m` or `42s`.
pub fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3600;
    let minutes = (seconds % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

/// What a transaction locktime means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LocktimeKind {
    /// Zero: no lock.
    None,
    /// Below 500,000,000: a block height.
    Height,
    /// A Unix time.
    Time,
}

/// Classifies a locktime.
pub fn locktime_kind(value: u32) -> LocktimeKind {
    if value == 0 {
        LocktimeKind::None
    } else if value < bitcoin::absolute::LOCK_TIME_THRESHOLD {
        LocktimeKind::Height
    } else {
        LocktimeKind::Time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_times() {
        assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_unix(1_793_232_000), "2026-10-29T00:00:00Z");
        assert_eq!(format_unix(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_duration(42), "42s");
        assert_eq!(format_duration(300), "5m");
        assert_eq!(format_duration(3 * 3600 + 300), "3h 5m");
        assert_eq!(format_duration(2 * 86_400 + 3 * 3600 + 59), "2d 3h");
    }

    #[test]
    fn classifies_locktimes() {
        assert_eq!(locktime_kind(0), LocktimeKind::None);
        assert_eq!(locktime_kind(850_000), LocktimeKind::Height);
        assert_eq!(locktime_kind(1_800_000_000), LocktimeKind::Time);
    }
}
