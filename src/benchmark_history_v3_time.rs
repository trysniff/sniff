const SECONDS_PER_DAY: i64 = 86_400;
type UtcRange = (String, String);

pub(super) fn parse_utc_second(value: &str) -> Result<i64, String> {
    if value.len() != 20
        || !value.is_ascii()
        || &value[4..5] != "-"
        || &value[7..8] != "-"
        || &value[10..11] != "T"
        || &value[13..14] != ":"
        || &value[16..17] != ":"
        || &value[19..20] != "Z"
    {
        return Err(format!("invalid historical-v3 UTC timestamp: {value}"));
    }
    let year = parse_component(value, 0, 4, "year")?;
    let month = parse_component(value, 5, 7, "month")?;
    let day = parse_component(value, 8, 10, "day")?;
    let hour = parse_component(value, 11, 13, "hour")?;
    let minute = parse_component(value, 14, 16, "minute")?;
    let second = parse_component(value, 17, 19, "second")?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(format!("invalid historical-v3 UTC timestamp: {value}"));
    }
    let days = days_before_year(year) + days_before_month(year, month) + i64::from(day - 1);
    Ok(days * SECONDS_PER_DAY
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second))
}

pub(super) fn format_utc_second(timestamp: i64) -> Result<String, String> {
    if timestamp < 0 {
        return Err("historical-v3 UTC timestamp predates 1970".to_string());
    }
    let mut days = timestamp / SECONDS_PER_DAY;
    let seconds = timestamp % SECONDS_PER_DAY;
    let mut year = 1970_u32;
    while days >= i64::from(days_in_year(year)) {
        days -= i64::from(days_in_year(year));
        year += 1;
        if year > 9999 {
            return Err("historical-v3 UTC timestamp exceeds year 9999".to_string());
        }
    }
    let mut month = 1_u32;
    while days >= i64::from(days_in_month(year, month)) {
        days -= i64::from(days_in_month(year, month));
        month += 1;
    }
    let day = days + 1;
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

pub(super) fn split_inclusive_utc_range(
    start: &str,
    end: &str,
) -> Result<(UtcRange, UtcRange), String> {
    let start_second = parse_utc_second(start)?;
    let end_second = parse_utc_second(end)?;
    if start_second >= end_second {
        return Err("historical-v3 UTC range cannot be split further".to_string());
    }
    let midpoint = start_second + (end_second - start_second) / 2;
    Ok((
        (start.to_string(), format_utc_second(midpoint)?),
        (format_utc_second(midpoint + 1)?, end.to_string()),
    ))
}

fn parse_component(value: &str, start: usize, end: usize, label: &str) -> Result<u32, String> {
    value[start..end]
        .parse::<u32>()
        .map_err(|_| format!("invalid historical-v3 UTC {label}: {value}"))
}

fn days_before_year(year: u32) -> i64 {
    (1970..year).map(|year| i64::from(days_in_year(year))).sum()
}

fn days_before_month(year: u32, month: u32) -> i64 {
    (1..month)
        .map(|month| i64::from(days_in_month(year, month)))
        .sum()
}

fn days_in_year(year: u32) -> u32 {
    if is_leap_year(year) { 366 } else { 365 }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_seconds_round_trip_leap_days_and_boundaries() {
        for value in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T23:59:59Z",
            "2026-09-21T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            assert_eq!(
                format_utc_second(parse_utc_second(value).unwrap()).unwrap(),
                value
            );
        }
        assert!(parse_utc_second("2025-02-29T00:00:00Z").is_err());
        assert!(parse_utc_second("2026-09-21T00:00:00+00:00").is_err());
        assert!(parse_utc_second("000\u{e9}09-21T00:00:00Z").is_err());
    }

    #[test]
    fn inclusive_split_has_no_gap_or_overlap() {
        let (left, right) =
            split_inclusive_utc_range("2026-09-20T23:25:59Z", "2026-09-20T23:26:00Z").unwrap();
        assert_eq!(
            left,
            ("2026-09-20T23:25:59Z".into(), "2026-09-20T23:25:59Z".into())
        );
        assert_eq!(
            right,
            ("2026-09-20T23:26:00Z".into(), "2026-09-20T23:26:00Z".into())
        );
        assert!(split_inclusive_utc_range(&left.0, &left.1).is_err());
    }
}
