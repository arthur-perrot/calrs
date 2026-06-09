// --- ICS generation ---

/// Sanitize a value for use in an ICS field.
/// Strips CR/LF to prevent ICS injection (RFC 5545 field breakout).
fn sanitize_ics(value: &str) -> String {
    value
        .replace('\r', "")
        .replace('\n', " ")
        .replace(';', "\\;")
        .replace(',', "\\,")
}

/// Convert date + start/end times from a guest timezone to UTC ICS format (YYYYMMDDTHHMMSSZ).
/// Falls back to floating time (no Z) if timezone parsing fails.
fn convert_to_utc(
    date: &str,
    start_time: &str,
    end_time: &str,
    timezone: &str,
) -> (String, String) {
    let fallback_start = format!(
        "{}T{}00",
        date.replace('-', ""),
        start_time.replace(':', "")
    );
    let fallback_end = format!("{}T{}00", date.replace('-', ""), end_time.replace(':', ""));

    let tz: Tz = match timezone.parse() {
        Ok(t) => t,
        Err(_) => return (fallback_start, fallback_end),
    };

    let start_naive = match NaiveDateTime::parse_from_str(
        &format!("{} {}:00", date, start_time),
        "%Y-%m-%d %H:%M:%S",
    ) {
        Ok(dt) => dt,
        Err(_) => return (fallback_start, fallback_end),
    };
    let end_naive = match NaiveDateTime::parse_from_str(
        &format!("{} {}:00", date, end_time),
        "%Y-%m-%d %H:%M:%S",
    ) {
        Ok(dt) => dt,
        Err(_) => return (fallback_start, fallback_end),
    };

    use chrono::TimeZone;
    let start_utc = match tz.from_local_datetime(&start_naive).earliest() {
        Some(dt) => dt.with_timezone(&chrono::Utc),
        None => return (fallback_start, fallback_end),
    };
    let end_utc = match tz.from_local_datetime(&end_naive).earliest() {
        Some(dt) => dt.with_timezone(&chrono::Utc),
        None => return (fallback_start, fallback_end),
    };

    (
        start_utc.format("%Y%m%dT%H%M%SZ").to_string(),
        end_utc.format("%Y%m%dT%H%M%SZ").to_string(),
    )
}

/// Convert a (date, start_time, end_time) tuple from `from_tz` into `to_tz`,
/// returning the wall-clock equivalents.
///
/// Returns `(date, start_time, end_time)` formatted as `YYYY-MM-DD` / `HH:MM`.
/// The date can roll over (e.g. LA 22:00 → Paris 07:00 next day), so the
/// returned date may differ from the input. If either timezone fails to parse
/// or the local time is invalid (DST gap), returns `None` and the caller
/// should fall back to displaying the original values.
fn convert_time_between_tz(
    date: &str,
    start_time: &str,
    end_time: &str,
    from_tz: &str,
    to_tz: &str,
) -> Option<(String, String, String)> {
    use chrono::TimeZone;

    let from: Tz = from_tz.parse().ok()?;
    let to: Tz = to_tz.parse().ok()?;

    let start_naive =
        NaiveDateTime::parse_from_str(&format!("{} {}:00", date, start_time), "%Y-%m-%d %H:%M:%S")
            .ok()?;
    let end_naive =
        NaiveDateTime::parse_from_str(&format!("{} {}:00", date, end_time), "%Y-%m-%d %H:%M:%S")
            .ok()?;

    let start_target = from
        .from_local_datetime(&start_naive)
        .earliest()?
        .with_timezone(&to);
    let end_target = from
        .from_local_datetime(&end_naive)
        .earliest()?
        .with_timezone(&to);

    Some((
        start_target.format("%Y-%m-%d").to_string(),
        start_target.format("%H:%M").to_string(),
        end_target.format("%H:%M").to_string(),
    ))
}

/// Build the date + time strings to display in a host-targeted email.
///
/// When `host_timezone` is set and differs from `guest_timezone`, the times are
/// converted into the host's zone. Otherwise the original guest-zone values are
/// kept. The returned `time_display` always includes a `(TZ)` suffix so the
/// host can tell which zone they're looking at.
pub(crate) fn host_time_display(
    date: &str,
    start_time: &str,
    end_time: &str,
    guest_timezone: &str,
    host_timezone: &str,
) -> (String, String) {
    if !host_timezone.is_empty() && host_timezone != guest_timezone {
        if let Some((host_date, host_start, host_end)) =
            convert_time_between_tz(date, start_time, end_time, guest_timezone, host_timezone)
        {
            return (
                host_date,
                format!("{} \u{2013} {} ({})", host_start, host_end, host_timezone),
            );
        }
    }

    let tz_label = if !guest_timezone.is_empty() {
        guest_timezone
    } else if !host_timezone.is_empty() {
        host_timezone
    } else {
        ""
    };

    let time_display = if tz_label.is_empty() {
        format!("{} \u{2013} {}", start_time, end_time)
    } else {
        format!("{} \u{2013} {} ({})", start_time, end_time, tz_label)
    };

    (date.to_string(), time_display)
}

/// Generate an .ics VCALENDAR string for a booking
/// Extract first name (first word) from a full name.
fn first_name(full_name: &str) -> &str {
    full_name.split_whitespace().next().unwrap_or(full_name)
}

pub fn generate_ics(details: &BookingDetails, method: &str) -> String {
    let guest_first = first_name(&details.guest_name);
    let host_first = first_name(&details.host_name);
    let summary = sanitize_ics(&format!(
        "{} \u{2014} {} & {}",
        details.event_title, guest_first, host_first
    ));
    let host_name = sanitize_ics(&details.host_name);
    let guest_name = sanitize_ics(&details.guest_name);
    let host_email = sanitize_ics(&details.host_email);
    let guest_email = sanitize_ics(&details.guest_email);
    let location_line = details
        .location
        .as_ref()
        .map(|l| format!("LOCATION:{}\r\n", sanitize_ics(l)))
        .unwrap_or_default();
    let description_line = details
        .notes
        .as_ref()
        .filter(|n| !n.trim().is_empty())
        .map(|n| format!("DESCRIPTION:{}\r\n", sanitize_ics(n)))
        .unwrap_or_default();
    let valarm = details
        .reminder_minutes
        .filter(|&m| m > 0)
        .map(|m| {
            format!(
                "BEGIN:VALARM\r\n\
                 TRIGGER:-PT{m}M\r\n\
                 ACTION:DISPLAY\r\n\
                 DESCRIPTION:Reminder\r\n\
                 END:VALARM\r\n"
            )
        })
        .unwrap_or_default();
    let additional_attendee_lines: String = details
        .additional_attendees
        .iter()
        .map(|email| format!("ATTENDEE;RSVP=TRUE:mailto:{}\r\n", sanitize_ics(email)))
        .collect();
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    // Convert guest-timezone times to UTC for the ICS
    let (dtstart, dtend) = convert_to_utc(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
    );
    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//calrs//calrs//EN\r\n\
         {method_line}\
         BEGIN:VEVENT\r\n\
         UID:{uid}\r\n\
         DTSTAMP:{dtstamp}\r\n\
         DTSTART:{dtstart}\r\n\
         DTEND:{dtend}\r\n\
         SUMMARY:{summary}\r\n\
         {description_line}\
         {location_line}\
         ORGANIZER;CN={host_name}:mailto:{host_email}\r\n\
         ATTENDEE;CN={guest_name};RSVP=TRUE:mailto:{guest_email}\r\n\
         {additional_attendee_lines}\
         STATUS:CONFIRMED\r\n\
         {valarm}\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
        method_line = if method.is_empty() {
            String::new()
        } else {
            format!("METHOD:{method}\r\n")
        },
        uid = details.uid,
        dtstamp = dtstamp,
        dtstart = dtstart,
        dtend = dtend,
        summary = summary,
        description_line = description_line,
        location_line = location_line,
        host_name = host_name,
        host_email = host_email,
        guest_name = guest_name,
        guest_email = guest_email,
        additional_attendee_lines = additional_attendee_lines,
    )
}

/// Generate an .ics VCALENDAR for cancellation (METHOD:CANCEL)
fn generate_cancel_ics(details: &CancellationDetails) -> String {
    let guest_first = first_name(&details.guest_name);
    let host_first = first_name(&details.host_name);
    let summary = sanitize_ics(&format!(
        "{} \u{2014} {} & {}",
        details.event_title, guest_first, host_first
    ));
    let host_name = sanitize_ics(&details.host_name);
    let guest_name = sanitize_ics(&details.guest_name);
    let host_email = sanitize_ics(&details.host_email);
    let guest_email = sanitize_ics(&details.guest_email);
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (dtstart, dtend) = convert_to_utc(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
    );
    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//calrs//calrs//EN\r\n\
         METHOD:CANCEL\r\n\
         BEGIN:VEVENT\r\n\
         UID:{uid}\r\n\
         DTSTAMP:{dtstamp}\r\n\
         DTSTART:{dtstart}\r\n\
         DTEND:{dtend}\r\n\
         SUMMARY:{summary}\r\n\
         ORGANIZER;CN={host_name}:mailto:{host_email}\r\n\
         ATTENDEE;CN={guest_name}:mailto:{guest_email}\r\n\
         STATUS:CANCELLED\r\n\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
        uid = details.uid,
        dtstamp = dtstamp,
        dtstart = dtstart,
        dtend = dtend,
        summary = summary,
        host_name = host_name,
        host_email = host_email,
        guest_name = guest_name,
        guest_email = guest_email,
    )
}

