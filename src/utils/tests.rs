use super::*;
use chrono::Timelike;

// --- split_vevents ---

#[test]
fn split_single_vevent() {
    let ical = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:abc\nEND:VEVENT\nEND:VCALENDAR";
    let blocks = split_vevents(ical);
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].starts_with("BEGIN:VEVENT"));
    assert!(blocks[0].ends_with("END:VEVENT"));
}

#[test]
fn split_multiple_vevents() {
    let ical = "\
BEGIN:VCALENDAR\n\
BEGIN:VEVENT\n\
UID:abc\n\
RRULE:FREQ=WEEKLY\n\
END:VEVENT\n\
BEGIN:VEVENT\n\
UID:abc\n\
RECURRENCE-ID:20260309T100000\n\
END:VEVENT\n\
END:VCALENDAR";
    let blocks = split_vevents(ical);
    assert_eq!(blocks.len(), 2);
    assert!(blocks[0].contains("RRULE"));
    assert!(blocks[1].contains("RECURRENCE-ID"));
}

#[test]
fn split_no_vevent_returns_whole() {
    let ical = "BEGIN:VCALENDAR\nEND:VCALENDAR";
    let blocks = split_vevents(ical);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0], ical);
}

#[test]
fn split_missing_end_vevent() {
    let ical = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:abc\n";
    let blocks = split_vevents(ical);
    // No END:VEVENT → falls back to returning whole string
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0], ical);
}

// --- extract_vevent_field ---

#[test]
fn extract_existing_field() {
    let vevent = "BEGIN:VEVENT\nUID:test-uid-123\nSUMMARY:Team meeting\nEND:VEVENT";
    assert_eq!(
        extract_vevent_field(vevent, "UID"),
        Some("test-uid-123".to_string())
    );
    assert_eq!(
        extract_vevent_field(vevent, "SUMMARY"),
        Some("Team meeting".to_string())
    );
}

#[test]
fn extract_field_with_params() {
    // DTSTART has timezone parameters before the colon
    let vevent = "BEGIN:VEVENT\nDTSTART;TZID=Europe/Paris:20260310T100000\nEND:VEVENT";
    assert_eq!(
        extract_vevent_field(vevent, "DTSTART"),
        Some("20260310T100000".to_string())
    );
}

#[test]
fn extract_nonexistent_field() {
    let vevent = "BEGIN:VEVENT\nUID:abc\nEND:VEVENT";
    assert_eq!(extract_vevent_field(vevent, "SUMMARY"), None);
}

#[test]
fn extract_empty_value() {
    let vevent = "BEGIN:VEVENT\nSUMMARY:\nEND:VEVENT";
    assert_eq!(extract_vevent_field(vevent, "SUMMARY"), None);
}

#[test]
fn extract_does_not_match_substring() {
    // DTSTART should not match DTSTART-EXTRA or other prefixed fields
    let vevent = "BEGIN:VEVENT\nDTSTART:20260310T100000\nDTSTART-EXTRA:ignored\nEND:VEVENT";
    assert_eq!(
        extract_vevent_field(vevent, "DTSTART"),
        Some("20260310T100000".to_string())
    );
}

// --- extract_vevent_tzid ---

#[test]
fn tzid_with_explicit_timezone() {
    let vevent = "BEGIN:VEVENT\nDTSTART;TZID=Europe/Paris:20260310T100000\nEND:VEVENT";
    assert_eq!(
        extract_vevent_tzid(vevent, "DTSTART"),
        Some("Europe/Paris".to_string())
    );
}

#[test]
fn tzid_utc_suffix() {
    let vevent = "BEGIN:VEVENT\nDTSTART:20260310T100000Z\nEND:VEVENT";
    assert_eq!(
        extract_vevent_tzid(vevent, "DTSTART"),
        Some("UTC".to_string())
    );
}

#[test]
fn tzid_floating_no_tz() {
    let vevent = "BEGIN:VEVENT\nDTSTART:20260310T100000\nEND:VEVENT";
    assert_eq!(extract_vevent_tzid(vevent, "DTSTART"), None);
}

#[test]
fn tzid_all_day_value_date() {
    let vevent = "BEGIN:VEVENT\nDTSTART;VALUE=DATE:20260310\nEND:VEVENT";
    assert_eq!(extract_vevent_tzid(vevent, "DTSTART"), None);
}

#[test]
fn tzid_america_new_york() {
    let vevent = "BEGIN:VEVENT\nDTSTART;TZID=America/New_York:20260310T100000\nDTEND;TZID=America/New_York:20260310T110000\nEND:VEVENT";
    assert_eq!(
        extract_vevent_tzid(vevent, "DTSTART"),
        Some("America/New_York".to_string())
    );
    assert_eq!(
        extract_vevent_tzid(vevent, "DTEND"),
        Some("America/New_York".to_string())
    );
}

#[test]
fn tzid_no_matching_field() {
    let vevent = "BEGIN:VEVENT\nDTEND;TZID=UTC:20260310T100000\nEND:VEVENT";
    assert_eq!(extract_vevent_tzid(vevent, "DTSTART"), None);
}

#[test]
fn tzid_does_not_match_prefix() {
    let vevent = "BEGIN:VEVENT\nDTSTART-EXTRA;TZID=Europe/Paris:20260310T100000\nDTSTART:20260310T100000\nEND:VEVENT";
    assert_eq!(extract_vevent_tzid(vevent, "DTSTART"), None); // floating, not the -EXTRA line
}

// --- convert_event_to_tz ---

#[test]
fn convert_ny_to_paris() {
    use chrono::NaiveDate;
    // 10:00 in New York (EDT, UTC-4) = 16:00 in Paris (CEST, UTC+2) in summer
    let dt = NaiveDate::from_ymd_opt(2026, 7, 15)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap();
    let result = convert_event_to_tz(
        dt,
        Some("America/New_York"),
        "Europe/Paris".parse::<Tz>().unwrap(),
    );
    assert_eq!(result.hour(), 16);
}

#[test]
fn convert_utc_to_paris() {
    use chrono::NaiveDate;
    // 10:00 UTC = 12:00 Paris (CEST, UTC+2) in summer
    let dt = NaiveDate::from_ymd_opt(2026, 7, 15)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap();
    let result = convert_event_to_tz(dt, Some("UTC"), "Europe/Paris".parse::<Tz>().unwrap());
    assert_eq!(result.hour(), 12);
}

#[test]
fn convert_floating_unchanged() {
    use chrono::NaiveDate;
    let dt = NaiveDate::from_ymd_opt(2026, 7, 15)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap();
    let result = convert_event_to_tz(dt, None, "Europe/Paris".parse::<Tz>().unwrap());
    assert_eq!(result, dt); // unchanged
}

#[test]
fn convert_invalid_tz_unchanged() {
    use chrono::NaiveDate;
    let dt = NaiveDate::from_ymd_opt(2026, 7, 15)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap();
    let result = convert_event_to_tz(
        dt,
        Some("Invalid/Zone"),
        "Europe/Paris".parse::<Tz>().unwrap(),
    );
    assert_eq!(result, dt); // unchanged
}

// --- render_inline_markdown ---

#[test]
fn bio_plain_text() {
    let result = render_inline_markdown("Hello world");
    assert_eq!(result, "Hello world");
}

#[test]
fn bio_link() {
    let result = render_inline_markdown("[My site](https://example.com)");
    assert!(result.contains("href=\"https://example.com\""));
    assert!(result.contains("target=\"_blank\""));
    assert!(result.contains("rel=\"noopener noreferrer\""));
    assert!(result.contains("My site"));
}

#[test]
fn bio_bold_italic() {
    let result = render_inline_markdown("**bold** and *italic*");
    assert!(result.contains("<strong>bold</strong>"));
    assert!(result.contains("<em>italic</em>"));
}

#[test]
fn bio_strips_headings() {
    let result = render_inline_markdown("# Heading\nSome text");
    assert!(!result.contains("<h1>"));
    assert!(result.contains("Some text"));
}

#[test]
fn bio_strips_images() {
    let result = render_inline_markdown("![alt](https://evil.com/img.png)");
    assert!(!result.contains("<img"));
    assert!(!result.contains("evil.com"));
}

#[test]
fn bio_strips_html_tags() {
    let result = render_inline_markdown("<script>alert('xss')</script>");
    assert!(!result.contains("<script>"));
}

#[test]
fn bio_inline_code() {
    let result = render_inline_markdown("Use `cargo build`");
    assert!(result.contains("<code>cargo build</code>"));
}

#[test]
fn bio_multiple_paragraphs() {
    let result = render_inline_markdown("Line 1\n\nLine 2");
    assert!(result.contains("Line 1"));
    assert!(result.contains("Line 2"));
    assert!(result.contains("<br>"));
}

// --- parse_ical_datetime ---

fn pdt(y: i32, m: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
    chrono::NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(h, mi, 0)
        .unwrap()
}

#[test]
fn parse_ical_compact_format() {
    assert_eq!(
        parse_ical_datetime("20260310T140000"),
        Some(pdt(2026, 3, 10, 14, 0))
    );
}

#[test]
fn parse_ical_iso_format() {
    assert_eq!(
        parse_ical_datetime("2026-03-10T14:00:00"),
        Some(pdt(2026, 3, 10, 14, 0))
    );
}

/// EWS UTC events arrive as `YYYYMMDDTHHMMSSZ`. Before consolidation each
/// busy-time path had its own parser and the `Z` suffix made chrono reject
/// the value, silently dropping the event. Pair with the DST round-trip
/// tests below to guard the parse + tz-conversion combo.
#[test]
fn parse_ical_compact_with_z_suffix() {
    assert_eq!(
        parse_ical_datetime("20260310T140000Z"),
        Some(pdt(2026, 3, 10, 14, 0))
    );
}

#[test]
fn parse_ical_iso_with_z_suffix() {
    assert_eq!(
        parse_ical_datetime("2026-06-06T08:10:00Z"),
        Some(pdt(2026, 6, 6, 8, 10))
    );
}

#[test]
fn parse_ical_allday_compact() {
    assert_eq!(
        parse_ical_datetime("20260310"),
        Some(pdt(2026, 3, 10, 0, 0))
    );
}

#[test]
fn parse_ical_allday_dashed() {
    assert_eq!(
        parse_ical_datetime("2026-03-10"),
        Some(pdt(2026, 3, 10, 0, 0))
    );
}

#[test]
fn parse_ical_invalid() {
    assert_eq!(parse_ical_datetime("not-a-date"), None);
    assert_eq!(parse_ical_datetime(""), None);
    assert_eq!(parse_ical_datetime("2026"), None);
}

/// Summer round-trip: 08:10 UTC → 10:10 Europe/Paris (CEST, UTC+2).
/// Together with the winter variant below this anchors the end-to-end
/// path from Z-suffixed EWS string to host-local time.
#[test]
fn ews_utc_event_converts_to_paris_summer() {
    let host_tz: Tz = "Europe/Paris".parse().unwrap();
    let dt = parse_ical_datetime("20260606T081000Z").unwrap();
    let converted = convert_event_to_tz(dt, Some("UTC"), host_tz);
    assert_eq!(converted, pdt(2026, 6, 6, 10, 10));
}

/// Winter round-trip: 08:10 UTC → 09:10 Europe/Paris (CET, UTC+1).
#[test]
fn ews_utc_event_converts_to_paris_winter() {
    let host_tz: Tz = "Europe/Paris".parse().unwrap();
    let dt = parse_ical_datetime("20260112T081000Z").unwrap();
    let converted = convert_event_to_tz(dt, Some("UTC"), host_tz);
    assert_eq!(converted, pdt(2026, 1, 12, 9, 10));
}

#[test]
fn convert_winter_time() {
    use chrono::NaiveDate;
    // 10:00 in New York (EST, UTC-5) = 16:00 in Paris (CET, UTC+1) in winter
    let dt = NaiveDate::from_ymd_opt(2026, 1, 15)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap();
    let result = convert_event_to_tz(
        dt,
        Some("America/New_York"),
        "Europe/Paris".parse::<Tz>().unwrap(),
    );
    assert_eq!(result.hour(), 16);
}
