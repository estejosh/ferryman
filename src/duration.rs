use std::time::Duration;

use crate::error::{Error, Result};

/// Parse a human window like `30d`, `12h`, `90s`, `1w`, `1h30m`.
///
/// Grammar: one or more `<number><unit>` chunks. Units (case-insensitive):
/// s/sec(s)/second(s), m/min(s)/minute(s), h/hr(s)/hour(s),
/// d/day(s), w/wk(s)/week(s). Zero or empty windows are rejected.
pub fn parse_window(input: &str) -> Result<Duration> {
    let secs = tokenize_window(input)?;
    if secs == 0 {
        return Err(Error::BadInput("window must be greater than zero".into()));
    }
    Ok(Duration::from_secs(secs))
}

/// Like [`parse_window`] but accepts `0s`/zero totals — used where "no wait"
/// is meaningful (e.g. `--max-wait 0s`).
pub fn parse_window_allow_zero(input: &str) -> Result<Duration> {
    Ok(Duration::from_secs(tokenize_window(input)?))
}

fn tokenize_window(input: &str) -> Result<u64> {
    let s = input.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err(Error::BadInput("empty duration (expected e.g. 30d)".into()));
    }
    let bytes = s.as_bytes();
    let mut total: u64 = 0;
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            return Err(Error::BadInput(format!(
                "expected a number at position {i} in {input:?}"
            )));
        }
        let num_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let digits = &s[num_start..unit_start];
        let unit = &s[unit_start..i];
        if unit.is_empty() {
            return Err(Error::BadInput(format!(
                "missing time unit after {digits:?} in {input:?} (try 30d, 12h, 45m, 90s)"
            )));
        }
        let n: u64 = digits
            .parse()
            .map_err(|_| Error::BadInput(format!("bad number {digits:?} in {input:?}")))?;
        let mult = unit_multiplier(unit)?;
        let chunk = n
            .checked_mul(mult)
            .ok_or_else(|| Error::BadInput(format!("duration overflow in {input:?}")))?;
        total = total
            .checked_add(chunk)
            .ok_or_else(|| Error::BadInput(format!("duration overflow in {input:?}")))?;
    }
    if total == 0 {
        return Ok(0);
    }
    Ok(total)
}

fn unit_multiplier(unit: &str) -> Result<u64> {
    match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => Ok(1),
        "m" | "min" | "mins" | "minute" | "minutes" => Ok(60),
        "h" | "hr" | "hrs" | "hour" | "hours" => Ok(3600),
        "d" | "day" | "days" => Ok(86_400),
        "w" | "wk" | "week" | "weeks" => Ok(604_800),
        other => Err(Error::BadInput(format!(
            "unknown time unit {other:?} (supported: s, m, h, d, w)"
        ))),
    }
}

/// Render seconds back into a compact human string.
pub fn format_window(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (hours, rem) = (rem / 3_600, rem % 3_600);
    let (mins, secs) = (rem / 60, rem % 60);
    let mut out = String::new();
    if days > 0 {
        out.push_str(&format!("{days}d"));
    }
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if mins > 0 {
        out.push_str(&format!("{mins}m"));
    }
    if secs > 0 || out.is_empty() {
        out.push_str(&format!("{secs}s"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_units() {
        assert_eq!(parse_window("30d").unwrap(), Duration::from_secs(2_592_000));
        assert_eq!(parse_window("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_window("45m").unwrap(), Duration::from_secs(2_700));
        assert_eq!(parse_window("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_window("1w").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_window("7days").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_window(" 2H ").unwrap(), Duration::from_secs(7_200));
    }

    #[test]
    fn parses_compound() {
        assert_eq!(parse_window("1h30m").unwrap(), Duration::from_secs(5_400));
        assert_eq!(parse_window("1d12h").unwrap(), Duration::from_secs(129_600));
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["", "abc", "30x", "30", "-5d", "0d", "d30", "3.5h"] {
            assert!(parse_window(bad).is_err(), "expected rejection of {bad:?}");
        }
    }

    #[test]
    fn allows_zero_only_for_wait_budgets() {
        assert!(parse_window("0s").is_err());
        assert!(parse_window_allow_zero("0s").unwrap().is_zero());
        assert!(parse_window_allow_zero("banana").is_err());
    }

    #[test]
    fn formats_back() {
        assert_eq!(format_window(2_592_000), "30d");
        assert_eq!(format_window(5_400), "1h30m");
        assert_eq!(format_window(42), "42s");
    }
}
