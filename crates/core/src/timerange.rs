use std::fmt;
use std::ops::{Bound, RangeBounds};
use std::str::FromStr;

use chrono::{
    DateTime, Days, FixedOffset, Local, Months, NaiveDate, NaiveDateTime, NaiveTime, TimeDelta,
    TimeZone, Weekday,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Span {
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
    Exact,
}

impl Span {
    fn format(self) -> &'static str {
        match self {
            Span::Year => "%Y",
            Span::Month => "%Y-%m",
            Span::Day => "%Y-%m-%d",
            Span::Hour => "%Y-%m-%dT%H",
            Span::Minute => "%Y-%m-%dT%H:%M",
            Span::Second => "%Y-%m-%dT%H:%M:%S",
            Span::Exact => "%Y-%m-%dT%H:%M:%S%.6f",
        }
    }

    fn last(self, start: DateTime<FixedOffset>) -> DateTime<FixedOffset> {
        let next = match self {
            Span::Year => start.checked_add_months(Months::new(12)),
            Span::Month => start.checked_add_months(Months::new(1)),
            Span::Day => start.checked_add_days(Days::new(1)),
            Span::Hour => start.checked_add_signed(TimeDelta::hours(1)),
            Span::Minute => start.checked_add_signed(TimeDelta::minutes(1)),
            Span::Second => start.checked_add_signed(TimeDelta::seconds(1)),
            Span::Exact => return start,
        };
        next.and_then(|next| next.checked_sub_signed(TimeDelta::microseconds(1)))
            .unwrap_or(start)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mark {
    At {
        at: DateTime<FixedOffset>,
        span: Span,
    },
    Local {
        at: NaiveDateTime,
        span: Span,
    },
    Ago(TimeDelta),
}

// Tool-schema type: a rustdoc comment here ships as the wire description of
// every field holding one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct TimeRangeBound(Mark);

impl TimeRangeBound {
    pub fn start(&self, now: DateTime<Local>) -> DateTime<FixedOffset> {
        match &self.0 {
            Mark::At { at, .. } => *at,
            Mark::Local { at, .. } => grounded(*at, now),
            Mark::Ago(back) => now.fixed_offset() - *back,
        }
    }

    pub fn end(&self, now: DateTime<Local>) -> DateTime<FixedOffset> {
        match &self.0 {
            Mark::At { at, span } => span.last(*at),
            Mark::Local { at, span } => span.last(grounded(*at, now)),
            Mark::Ago(back) => now.fixed_offset() - *back,
        }
    }
}

fn grounded(at: NaiveDateTime, now: DateTime<Local>) -> DateTime<FixedOffset> {
    match Local.from_local_datetime(&at).earliest() {
        Some(resolved) => resolved.fixed_offset(),
        None => DateTime::from_naive_utc_and_offset(at - *now.offset(), *now.offset()),
    }
}

impl FromStr for TimeRangeBound {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<TimeRangeBound> {
        parse(s.trim()).map(TimeRangeBound)
    }
}

impl TryFrom<String> for TimeRangeBound {
    type Error = NotedError;
    fn try_from(s: String) -> Result<TimeRangeBound> {
        s.parse()
    }
}

impl From<TimeRangeBound> for String {
    fn from(bound: TimeRangeBound) -> String {
        bound.to_string()
    }
}

impl fmt::Display for TimeRangeBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Mark::At { at, span } => {
                write!(f, "{}", at.format(&format!("{}%:z", span.format())))
            }
            Mark::Local { at, span } => write!(f, "{}", at.format(span.format())),
            Mark::Ago(back) => write!(f, "PT{}S", back.num_seconds()),
        }
    }
}

fn parse(text: &str) -> Result<Mark> {
    if text.is_empty() {
        return Err(rejected("a time bound is required"));
    }
    if text.starts_with('P') {
        return duration(text);
    }
    if let Some(coarse) = year_or_month(text)? {
        return Ok(coarse);
    }
    match text.split_once('T') {
        Some((date, clock)) => stamped(date, clock),
        None => Ok(Mark::Local {
            at: day(text)?.into(),
            span: Span::Day,
        }),
    }
}

fn year_or_month(text: &str) -> Result<Option<Mark>> {
    let digits =
        |part: &str, width: usize| part.len() == width && part.bytes().all(|b| b.is_ascii_digit());
    let (padded, span) = match text.split_once('-') {
        None if digits(text, 4) => (format!("{text}-01-01"), Span::Year),
        Some((year, month)) if digits(year, 4) && digits(month, 2) => {
            (format!("{text}-01"), Span::Month)
        }
        _ => return Ok(None),
    };
    let at = day(&padded).map_err(|_| rejected(format!("invalid date: '{text}'")))?;
    Ok(Some(Mark::Local {
        at: at.into(),
        span,
    }))
}

fn day(text: &str) -> Result<NaiveDate> {
    let (rest, parsed) = iso8601::parsers::parse_date(text.as_bytes())
        .map_err(|_| rejected(format!("invalid date: '{text}'")))?;
    if !rest.is_empty() {
        return Err(rejected(format!("invalid date: '{text}'")));
    }
    let at = match parsed {
        iso8601::Date::YMD { year, month, day } => NaiveDate::from_ymd_opt(year, month, day),
        iso8601::Date::Ordinal { year, ddd } => NaiveDate::from_yo_opt(year, ddd),
        iso8601::Date::Week { year, ww, d } => Weekday::try_from(d.saturating_sub(1) as u8)
            .ok()
            .and_then(|weekday| NaiveDate::from_isoywd_opt(year, ww, weekday)),
    };
    at.ok_or_else(|| rejected(format!("invalid date: '{text}'")))
}

fn stamped(date: &str, text: &str) -> Result<Mark> {
    let (time, offset, span) = clock(text)?;
    let at = day(date)?.and_time(time);
    match offset {
        None => Ok(Mark::Local { at, span }),
        Some(offset) => Ok(Mark::At {
            at: offset
                .from_local_datetime(&at)
                .single()
                .ok_or_else(|| rejected(format!("invalid time: '{text}'")))?,
            span,
        }),
    }
}

fn clock(text: &str) -> Result<(NaiveTime, Option<FixedOffset>, Span)> {
    let (head, tail) = split_run(text, |c| c.is_ascii_digit() || c == ':');
    let (fraction, zone) = match tail.strip_prefix(['.', ',']) {
        Some(rest) => {
            let (fraction, zone) = split_run(rest, |c| c.is_ascii_digit());
            (Some(fraction), zone)
        }
        None => (None, tail),
    };
    let span = match (head.bytes().filter(u8::is_ascii_digit).count(), fraction) {
        (6, Some(fraction)) if !fraction.is_empty() => Span::Exact,
        (2, None) => Span::Hour,
        (4, None) => Span::Minute,
        (6, None) => Span::Second,
        _ => return Err(rejected(format!("invalid time: '{text}'"))),
    };
    let padded = match span {
        Span::Hour => format!("{head}:00{zone}"),
        _ => text.to_owned(),
    };
    let (rest, parsed) = iso8601::parsers::parse_time(padded.as_bytes())
        .map_err(|_| rejected(format!("invalid time: '{text}'")))?;
    if !rest.is_empty() {
        return Err(rejected(format!("invalid time: '{text}'")));
    }
    let time = NaiveTime::from_hms_micro_opt(
        parsed.hour,
        parsed.minute,
        parsed.second,
        fraction.map_or(0, micros_of),
    )
    .ok_or_else(|| rejected(format!("invalid time: '{text}'")))?;
    let offset = match zone.is_empty() {
        true => None,
        false => Some(
            FixedOffset::east_opt(parsed.tz_offset_hours * 3600 + parsed.tz_offset_minutes * 60)
                .ok_or_else(|| rejected(format!("invalid time zone offset: '{zone}'")))?,
        ),
    };
    Ok((time, offset, span))
}

fn split_run(text: &str, keep: impl Fn(char) -> bool) -> (&str, &str) {
    text.split_at(text.find(|c: char| !keep(c)).unwrap_or(text.len()))
}

fn micros_of(fraction: &str) -> u32 {
    fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(6)
        .fold(0, |micros, digit| micros * 10 + u32::from(digit - b'0'))
}

fn duration(text: &str) -> Result<Mark> {
    let (rest, parsed) = iso8601::parsers::parse_duration(text.as_bytes())
        .map_err(|_| rejected(format!("invalid duration: '{text}'")))?;
    if !rest.is_empty() {
        return Err(rejected(format!("invalid duration: '{text}'")));
    }
    let back = match parsed {
        iso8601::Duration::Weeks(weeks) => TimeDelta::weeks(weeks as i64),
        iso8601::Duration::YMDHMS {
            year,
            month,
            day,
            hour,
            minute,
            second,
            millisecond,
        } => {
            TimeDelta::days(year as i64 * 365 + month as i64 * 30 + day as i64)
                + TimeDelta::hours(hour as i64)
                + TimeDelta::minutes(minute as i64)
                + TimeDelta::seconds(second as i64)
                + TimeDelta::milliseconds(millisecond as i64)
        }
    };
    Ok(Mark::Ago(back))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimeRange {
    start: Option<DateTime<FixedOffset>>,
    end: Option<DateTime<FixedOffset>>,
}

impl TimeRange {
    pub fn new(since: Option<TimeRangeBound>, until: Option<TimeRangeBound>) -> Result<TimeRange> {
        let now = Local::now();
        let start = since.map(|bound| bound.start(now));
        let end = until.map(|bound| bound.end(now));
        if let (Some(start), Some(end)) = (start, end)
            && start > end
        {
            return Err(rejected(format!(
                "since '{start}' is later than until '{end}'"
            )));
        }
        Ok(TimeRange { start, end })
    }
}

impl RangeBounds<DateTime<FixedOffset>> for TimeRange {
    fn start_bound(&self) -> Bound<&DateTime<FixedOffset>> {
        match &self.start {
            Some(start) => Bound::Included(start),
            None => Bound::Unbounded,
        }
    }

    fn end_bound(&self) -> Bound<&DateTime<FixedOffset>> {
        match &self.end {
            Some(end) => Bound::Included(end),
            None => Bound::Unbounded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound(s: &str) -> TimeRangeBound {
        s.parse().unwrap()
    }

    fn now() -> DateTime<Local> {
        Local::now()
    }

    #[test]
    fn every_shape_parses() {
        for text in [
            "2026",
            "2026-07",
            "2026-07-01",
            "20260701",
            "2026-182",
            "2026-W27-3",
            "2026-07-01T09",
            "2026-07-01T09:15",
            "20260701T091530Z",
            "2026-07-01T09:15:30.123456+02:00",
            "P7D",
            "PT36H",
            "P3W",
        ] {
            assert!(text.parse::<TimeRangeBound>().is_ok(), "rejected '{text}'");
        }
    }

    #[test]
    fn an_impossible_date_is_refused() {
        for text in ["2026-13-01", "2026-02-30", "yesterday", "", "2026-07-01T"] {
            assert!(text.parse::<TimeRangeBound>().is_err(), "accepted '{text}'");
        }
    }

    #[test]
    fn an_invalid_zone_offset_is_refused() {
        for text in [
            "2026-07-01T09:15:30+99:99",
            "2026-07-01T09:15:30+24:00",
            "2026-07-01T09:15:30-24:00",
            "2026-07-01T09:15:30+02:00:00",
            "2026-07-01T09:15:30z",
        ] {
            assert!(text.parse::<TimeRangeBound>().is_err(), "accepted '{text}'");
        }
    }

    #[test]
    fn a_fraction_follows_seconds_only() {
        for text in [
            "2026-07-01T09.5",
            "2026-07-01T09:15.5",
            "2026-07-01T09:15:30.",
            "2026-07-01T09:15:3",
        ] {
            assert!(text.parse::<TimeRangeBound>().is_err(), "accepted '{text}'");
        }
    }

    #[test]
    fn a_zone_offset_is_read_in_every_shape() {
        for text in [
            "20260701T091530+0200",
            "2026-07-01T09:15:30+02",
            "2026-07-01T09:15:30+02:00",
        ] {
            assert_eq!(
                bound(text).start(now()).to_rfc3339(),
                "2026-07-01T09:15:30+02:00",
                "{text}"
            );
        }
        assert_eq!(
            bound("2026-07-01T09:15:30Z").start(now()).to_rfc3339(),
            "2026-07-01T09:15:30+00:00"
        );
        assert_eq!(
            bound("2026-07-01T09Z").end(now()).to_rfc3339(),
            "2026-07-01T09:59:59.999999+00:00"
        );
    }

    #[test]
    fn a_zoneless_stamp_stays_local() {
        assert_eq!(
            bound("2026-07-01T09:15:30").to_string(),
            "2026-07-01T09:15:30"
        );
    }

    #[test]
    fn a_fraction_keeps_microseconds() {
        assert_eq!(
            bound("2026-07-01T09:15:30.123456789Z")
                .start(now())
                .to_rfc3339(),
            "2026-07-01T09:15:30.123456+00:00"
        );
        assert_eq!(
            bound("2026-07-01T09:15:30,5Z").start(now()).to_rfc3339(),
            "2026-07-01T09:15:30.500+00:00"
        );
    }

    #[test]
    fn every_span_round_trips_through_its_text() {
        for text in [
            "2026",
            "2026-07",
            "2026-07-01",
            "2026-07-01T09",
            "2026-07-01T09:15",
            "2026-07-01T09:15:30",
            "2026-07-01T09:15:30.123456",
            "2026-07-01T09:15:30.123456+02:00",
        ] {
            let parsed = bound(text);
            assert_eq!(parsed.to_string(), text);
            assert_eq!(bound(&parsed.to_string()), parsed);
        }
        assert_eq!(bound("P7D"), bound(&bound("P7D").to_string()));
    }

    #[test]
    fn a_coarse_bound_widens_to_its_span() {
        let year = bound("2026");
        assert_eq!(
            year.start(now()).format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-01-01 00:00:00"
        );
        assert_eq!(
            year.end(now()).format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
            "2026-12-31 23:59:59.999999"
        );

        let month = bound("2026-07");
        assert_eq!(
            month.end(now()).format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
            "2026-07-31 23:59:59.999999"
        );

        let day = bound("2026-07-01");
        assert_eq!(
            day.end(now()).format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
            "2026-07-01 23:59:59.999999"
        );
    }

    #[test]
    fn an_offset_bound_keeps_its_offset() {
        let at = bound("2026-07-01T09:15:30+02:00");
        assert_eq!(at.start(now()).to_rfc3339(), "2026-07-01T09:15:30+02:00");
        assert_eq!(
            at.end(now()).format("%H:%M:%S%.6f%:z").to_string(),
            "09:15:30.999999+02:00"
        );
    }

    #[test]
    fn a_duration_counts_back_from_now() {
        let range = TimeRange::new(Some(bound("PT1H")), None).unwrap();
        let start = range.start.unwrap();
        let elapsed = Local::now().fixed_offset() - start;
        assert!(elapsed >= TimeDelta::hours(1));
        assert!(elapsed < TimeDelta::hours(1) + TimeDelta::minutes(1));
    }

    #[test]
    fn a_backwards_range_is_refused() {
        assert!(TimeRange::new(Some(bound("2026-08-01")), Some(bound("2026-07-01"))).is_err());
        assert!(TimeRange::new(Some(bound("2026-07")), Some(bound("2026-07"))).is_ok());
    }
}
