// --- Reschedule emails ---

#[derive(Default)]
pub struct RescheduleDetails {
    pub event_title: String,
    pub old_date: String,
    pub old_start_time: String,
    pub old_end_time: String,
    pub new_date: String,
    pub new_start_time: String,
    pub new_end_time: String,
    pub guest_name: String,
    pub guest_email: String,
    pub guest_timezone: String,
    pub host_name: String,
    pub host_email: String,
    pub uid: String,
    pub location: Option<String>,
    /// Host's IANA timezone (from `users.timezone`). See `BookingDetails::host_timezone`.
    pub host_timezone: String,
}

/// Ask the guest to pick a new time (host-initiated reschedule).
/// The guest clicks the link to choose a slot — no time is pre-selected.
pub async fn send_guest_pick_new_time(
    config: &SmtpConfig,
    details: &BookingDetails,
    reschedule_url: &str,
    cancel_url: Option<&str>,
) -> Result<()> {
    let from = config.mailbox_from()?;
    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let plain = format!(
        "Hi {},\n\n\
         {} needs to reschedule your booking.\n\n\
         Event: {}\n\
         Originally: {} at {}\n\n\
         Please pick a new time: {}\n\
         {}\n\
         \u{2014} calrs",
        details.guest_name,
        details.host_name,
        details.event_title,
        details.date,
        time_display,
        reschedule_url,
        cancel_url
            .map(|u| format!("\nOr cancel: {}\n", u))
            .unwrap_or_default(),
    );

    let rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Originally".to_string(),
            value: format!("{} at {}", details.date, time_display),
        },
        EmailRow {
            label: "Host".to_string(),
            value: details.host_name.clone(),
        },
    ];

    let mut actions = vec![EmailAction {
        label: "Pick a new time".to_string(),
        url: reschedule_url.to_string(),
        color: "#d97706".to_string(),
    }];
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: "Cancel booking".to_string(),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(&details.guest_name)),
        &format!(
            "{} needs to reschedule your booking. Please pick a new time.",
            h(&details.host_name)
        ),
        "#d97706",
        &rows,
        None,
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(from)
        .to(to)
        .subject(format!(
            "Reschedule: {} \u{2014} please pick a new time",
            details.event_title
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Notify the guest that their booking was rescheduled by the host.
/// Includes updated ICS calendar invite.
pub async fn send_guest_reschedule_notification(
    config: &SmtpConfig,
    details: &RescheduleDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
) -> Result<()> {
    let new_time_display = format!(
        "{} \u{2013} {} ({})",
        details.new_start_time, details.new_end_time, details.guest_timezone
    );

    let booking_details = BookingDetails {
        event_title: details.event_title.clone(),
        date: details.new_date.clone(),
        start_time: details.new_start_time.clone(),
        end_time: details.new_end_time.clone(),
        guest_name: details.guest_name.clone(),
        guest_email: details.guest_email.clone(),
        guest_timezone: details.guest_timezone.clone(),
        host_name: details.host_name.clone(),
        host_email: details.host_email.clone(),
        uid: details.uid.clone(),
        notes: None,
        location: details.location.clone(),
        reminder_minutes: None,
        additional_attendees: vec![],
        ..Default::default()
    };
    let ics = generate_ics(&booking_details, "REQUEST");

    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let plain = format!(
        "Hi {},\n\n\
         Your booking has been rescheduled by {}.\n\n\
         Event: {}\n\
         Previous: {} at {} \u{2013} {}\n\
         New: {} at {}\n\
         {}\
         An updated calendar invite is attached.\n\
         {}{}\n\
         \u{2014} calrs",
        details.guest_name,
        details.host_name,
        details.event_title,
        details.old_date,
        details.old_start_time,
        details.old_end_time,
        details.new_date,
        new_time_display,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!("Need to cancel? {}\n", u))
            .unwrap_or_default(),
        reschedule_url
            .map(|u| format!("Need to reschedule? {}\n", u))
            .unwrap_or_default(),
    );

    let rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Previous".to_string(),
            value: format!(
                "{} at {} \u{2013} {}",
                details.old_date, details.old_start_time, details.old_end_time
            ),
        },
        EmailRow {
            label: "New date".to_string(),
            value: details.new_date.clone(),
        },
        EmailRow {
            label: "New time".to_string(),
            value: new_time_display,
        },
        EmailRow {
            label: "With".to_string(),
            value: details.host_name.clone(),
        },
    ];

    let mut actions = Vec::new();
    if let Some(u) = reschedule_url {
        actions.push(EmailAction {
            label: "Reschedule".to_string(),
            url: u.to_string(),
            color: "#d97706".to_string(),
        });
    }
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: "Cancel booking".to_string(),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(&details.guest_name)),
        &format!(
            "Your booking has been rescheduled by {}.",
            h(&details.host_name)
        ),
        "#d97706",
        &rows,
        Some("An updated calendar invite is attached to this email."),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("invite.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=REQUEST; charset=UTF-8")?,
    );

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Rescheduled: {} \u{2014} {}",
            details.event_title, details.new_date
        ))
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Notify the host that a guest wants to reschedule — includes approve/decline buttons.
pub async fn send_host_reschedule_request(
    config: &SmtpConfig,
    details: &RescheduleDetails,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    let (old_date_display, old_time_display) = host_time_display(
        &details.old_date,
        &details.old_start_time,
        &details.old_end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );
    let (new_date_display, new_time_display) = host_time_display(
        &details.new_date,
        &details.new_start_time,
        &details.new_end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (approve_url, decline_url) = match (confirm_token, base_url) {
        (Some(token), Some(url)) => (
            Some(format!(
                "{}/booking/approve/{}",
                url.trim_end_matches('/'),
                token
            )),
            Some(format!(
                "{}/booking/decline/{}",
                url.trim_end_matches('/'),
                token
            )),
        ),
        _ => (None, None),
    };

    let action_text = match (&approve_url, &decline_url) {
        (Some(a), Some(d)) => format!("Approve: {}\nDecline: {}", a, d),
        _ => "Log in to your dashboard to confirm or decline.".to_string(),
    };

    let plain = format!(
        "{} wants to reschedule their booking.\n\n\
         Event: {}\n\
         Previous: {} at {}\n\
         Requested: {} at {}\n\
         Guest: {} <{}>\n\
         {}\n\n\
         {}\n\n\
         \u{2014} calrs",
        details.guest_name,
        details.event_title,
        old_date_display,
        old_time_display,
        new_date_display,
        new_time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        action_text,
    );

    let rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Previous".to_string(),
            value: format!("{} at {}", old_date_display, old_time_display),
        },
        EmailRow {
            label: "Requested".to_string(),
            value: format!("{} at {}", new_date_display, new_time_display),
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];

    let mut actions = Vec::new();
    if let Some(u) = &approve_url {
        actions.push(EmailAction {
            label: "Approve".to_string(),
            url: u.clone(),
            color: "#16a34a".to_string(),
        });
    }
    if let Some(u) = &decline_url {
        actions.push(EmailAction {
            label: "Decline".to_string(),
            url: u.clone(),
            color: "#dc2626".to_string(),
        });
    }

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(&details.host_name)),
        &format!(
            "{} wants to reschedule their booking.",
            h(&details.guest_name)
        ),
        "#d97706",
        &rows,
        None,
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Reschedule request: {} \u{2014} {} <{}>",
            details.event_title, details.guest_name, details.guest_email
        ))
        .multipart(body)?;

    send_email(config, email).await
}

