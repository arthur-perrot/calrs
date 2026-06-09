// --- Email senders ---

/// Send booking confirmation to the guest
pub async fn send_guest_confirmation(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    send_guest_confirmation_ex(config, details, cancel_url, None, None, None).await
}

pub async fn send_guest_confirmation_ex(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
    cancel_notice_min: Option<i32>,
    reschedule_notice_min: Option<i32>,
) -> Result<()> {
    let ics = generate_ics(details, "REQUEST");
    let lang = guest_lang(details);

    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = t(lang, "email-confirm-headline");
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_location = t(lang, "confirmed-detail-location");
    let label_notes = t(lang, "confirmed-detail-notes");
    let ics_attached_plain = t(lang, "email-confirm-ics-attached-plain");
    let ics_attached_html = t(lang, "email-confirm-ics-attached-html");
    let signature = t(lang, "email-signature");

    // Notice-window policy lines, mentioned just before the cancel link in
    // both the plain and HTML bodies. Translated to the guest's language.
    let cancel_notice_line = cancel_notice_min.filter(|m| *m > 0).map(|m| {
        ta(
            lang,
            "email-confirm-cancel-notice",
            [("minutes", m.to_string().as_str())],
        )
    });
    let reschedule_notice_line = reschedule_notice_min.filter(|m| *m > 0).map(|m| {
        ta(
            lang,
            "email-confirm-reschedule-notice",
            [("minutes", m.to_string().as_str())],
        )
    });

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {}{}\
         {}\n\
         {}{}{}\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        details
            .location
            .as_ref()
            .map(|l| format!("{} {}\n", label_location, l))
            .unwrap_or_default(),
        details
            .notes
            .as_ref()
            .map(|n| format!("{} {}\n", label_notes, n))
            .unwrap_or_default(),
        ics_attached_plain,
        reschedule_notice_line
            .as_ref()
            .map(|l| format!("\n{}\n", l))
            .unwrap_or_default(),
        cancel_notice_line
            .as_ref()
            .map(|l| format!("\n{}\n", l))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!(
                "\n{}\n",
                ta(lang, "email-confirm-need-to-cancel", [("url", u)])
            ))
            .unwrap_or_default(),
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: label_location.clone(),
            value: loc.clone(),
        });
    }
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: label_notes.clone(),
            value: notes.clone(),
        });
    }

    let mut actions: Vec<EmailAction> = Vec::new();
    if let Some(u) = reschedule_url {
        actions.push(EmailAction {
            label: t(lang, "email-action-reschedule"),
            url: u.to_string(),
            color: "#3b82f6".to_string(),
        });
    }
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: t(lang, "email-action-cancel-booking"),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    // Append notice lines to the footer note so they sit just below the
    // action buttons, alongside the existing "ICS attached" copy.
    let mut footer_note_html = ics_attached_html.clone();
    if let Some(line) = &reschedule_notice_line {
        footer_note_html.push('\n');
        footer_note_html.push_str(line);
    }
    if let Some(line) = &cancel_notice_line {
        footer_note_html.push('\n');
        footer_note_html.push_str(line);
    }
    let html = render_html_email_with_actions(
        &h(&greeting),
        &headline,
        "#16a34a",
        &rows,
        Some(&footer_note_html),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("invite.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=REQUEST; charset=UTF-8")?,
    );

    let subject = ta(
        lang,
        "email-confirm-subject",
        [("event", &details.event_title), ("date", &details.date)],
    );

    let from = config.mailbox_from()?;

    let email = Message::builder()
        .from(from.clone())
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await?;

    // Send confirmation to additional attendees
    for attendee_email in &details.additional_attendees {
        let ics2 = generate_ics(details, "REQUEST");
        let to2: lettre::message::Mailbox = attendee_email.parse()?;
        let plain2 = format!(
            "Hi,\n\n\
             You've been added as an attendee to a booking.\n\n\
             Event: {}\n\
             Date: {}\n\
             Time: {} \u{2013} {} ({})\n\
             Organizer: {}\n\
             Booked by: {} <{}>\n\n\
             A calendar invite is attached.\n\n\
             \u{2014} calrs",
            details.event_title,
            details.date,
            details.start_time,
            details.end_time,
            details.guest_timezone,
            details.host_name,
            details.guest_name,
            details.guest_email,
        );
        let html2 = render_html_email(
            "Hi,",
            "You've been added as an attendee to a booking.",
            "#16a34a",
            &[
                EmailRow {
                    label: "Event".to_string(),
                    value: details.event_title.clone(),
                },
                EmailRow {
                    label: "Date".to_string(),
                    value: details.date.clone(),
                },
                EmailRow {
                    label: "Time".to_string(),
                    value: format!(
                        "{} \u{2013} {} ({})",
                        details.start_time, details.end_time, details.guest_timezone
                    ),
                },
                EmailRow {
                    label: "Organizer".to_string(),
                    value: details.host_name.clone(),
                },
                EmailRow {
                    label: "Booked by".to_string(),
                    value: format!("{} <{}>", details.guest_name, details.guest_email),
                },
            ],
            Some("A calendar invite is attached to this email."),
        );
        let body2 = build_multipart_body(&plain2, &html2);
        let att2 = Attachment::new("invite.ics".to_string()).body(
            ics2,
            ContentType::parse("text/calendar; method=REQUEST; charset=UTF-8")?,
        );
        let email2 = Message::builder()
            .from(from.clone())
            .to(to2)
            .subject(format!(
                "Invite: {} \u{2014} {}",
                details.event_title, details.date
            ))
            .multipart(MultiPart::mixed().multipart(body2).singlepart(att2))?;
        if let Err(e) = send_email(config, email2).await {
            tracing::warn!(attendee = %attendee_email, error = %e, "failed to send attendee confirmation");
        }
    }

    Ok(())
}

/// Send booking notification to the host
pub async fn send_host_notification(config: &SmtpConfig, details: &BookingDetails) -> Result<()> {
    let ics = generate_ics(details, "REQUEST");

    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let plain = format!(
        "New booking!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}{}\n\
         A calendar invite is attached.\n\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        details
            .notes
            .as_ref()
            .map(|n| format!("Notes: {}\n", n))
            .unwrap_or_default(),
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: "Notes".to_string(),
            value: notes.clone(),
        });
    }

    let html = render_html_email(
        "New booking!",
        &format!("{} booked a slot with you.", h(&details.guest_name)),
        "#16a34a",
        &rows,
        Some("A calendar invite is attached to this email."),
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
            "New booking: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Send host a confirmation that a pending booking was approved (no ICS — event is already
/// pushed via CalDAV write-back).
pub async fn send_host_booking_confirmed(
    config: &SmtpConfig,
    details: &BookingDetails,
) -> Result<()> {
    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let plain = format!(
        "Booking confirmed!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}\
         The event has been added to your calendar.\n\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }

    let html = render_html_email(
        "Booking confirmed",
        &format!("You approved the booking with {}.", h(&details.guest_name)),
        "#16a34a",
        &rows,
        Some("The event has been added to your calendar."),
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Confirmed: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Send booking reminder to the guest
pub async fn send_guest_reminder(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    let lang = guest_lang(details);
    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = t(lang, "email-reminder-headline");
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_location = t(lang, "confirmed-detail-location");
    let signature = t(lang, "email-signature");

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {}{}\n\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        details
            .location
            .as_ref()
            .map(|l| format!("{} {}\n", label_location, l))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!(
                "\n{}\n",
                ta(lang, "email-confirm-need-to-cancel", [("url", u)])
            ))
            .unwrap_or_default(),
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: label_location.clone(),
            value: loc.clone(),
        });
    }

    let actions: Vec<EmailAction> = cancel_url
        .map(|u| {
            vec![EmailAction {
                label: t(lang, "email-action-cancel-booking"),
                url: u.to_string(),
                color: "#dc2626".to_string(),
            }]
        })
        .unwrap_or_default();

    let html =
        render_html_email_with_actions(&h(&greeting), &headline, "#3b82f6", &rows, None, &actions);

    let body = build_multipart_body(&plain, &html);

    let subject = ta(
        lang,
        "email-reminder-subject",
        [
            ("event", &details.event_title),
            ("time", &details.start_time),
        ],
    );
    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(subject)
        .multipart(body)?;

    send_email(config, email).await
}

/// Send booking reminder to the host
pub async fn send_host_reminder(config: &SmtpConfig, details: &BookingDetails) -> Result<()> {
    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let plain = format!(
        "Reminder: you have an upcoming booking.\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
    );

    let rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];

    let html = render_html_email(
        "Upcoming booking",
        &format!(
            "Reminder: you have a booking with {} coming up.",
            h(&details.guest_name)
        ),
        "#3b82f6",
        &rows,
        None,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Reminder: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Send cancellation notification to the guest
pub async fn send_guest_cancellation(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let ics = generate_cancel_ics(details);
    let lang = details.guest_language.as_deref().unwrap_or("en");

    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = if details.guest_timezone.is_empty() {
        format!("{} \u{2013} {}", details.start_time, details.end_time)
    } else {
        format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        )
    };

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = if details.cancelled_by_host {
        ta(
            lang,
            "email-cancel-headline-by-host",
            [("host", &details.host_name)],
        )
    } else {
        t(lang, "email-cancel-headline-by-guest")
    };
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_reason = t(lang, "common-detail-reason");
    let ics_attached_plain = t(lang, "email-cancel-ics-attached-plain");
    let ics_attached_html = t(lang, "email-cancel-ics-attached-html");
    let signature = t(lang, "email-signature");

    let reason_text = details
        .reason
        .as_ref()
        .map(|r| format!("{} {}\n\n", label_reason, r))
        .unwrap_or_default();

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\n\
         {}\
         {}\n\n\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        reason_text,
        ics_attached_plain,
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(reason) = &details.reason {
        rows.push(EmailRow {
            label: label_reason.clone(),
            value: reason.clone(),
        });
    }

    let html = render_html_email(
        &h(&greeting),
        &headline,
        "#dc2626",
        &rows,
        Some(&ics_attached_html),
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("cancel.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=CANCEL; charset=UTF-8")?,
    );

    let subject = ta(
        lang,
        "email-cancel-subject",
        [("event", &details.event_title), ("date", &details.date)],
    );
    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Send cancellation notification to the host
pub async fn send_host_cancellation(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let ics = generate_cancel_ics(details);

    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );
    let reason_text = details
        .reason
        .as_ref()
        .map(|r| format!("Reason: {}\n\n", r))
        .unwrap_or_default();

    let plain = format!(
        "Booking cancelled.\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\n\
         {}\
         A calendar cancellation is attached.\n\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        reason_text,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(reason) = &details.reason {
        rows.push(EmailRow {
            label: "Reason".to_string(),
            value: reason.clone(),
        });
    }

    let html = render_html_email(
        "Booking cancelled.",
        &if details.cancelled_by_host {
            "You cancelled this booking.".to_string()
        } else {
            format!("{} cancelled their booking.", h(&details.guest_name))
        },
        "#dc2626",
        &rows,
        Some("A calendar cancellation is attached to this email."),
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("cancel.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=CANCEL; charset=UTF-8")?,
    );

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Cancelled: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Send pending notice to guest (booking awaits host approval)
pub async fn send_guest_pending_notice(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    send_guest_pending_notice_ex(config, details, cancel_url, None).await
}

pub async fn send_guest_pending_notice_ex(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
) -> Result<()> {
    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    // Don't include location in pending emails — it should only be revealed
    // after the booking is confirmed (prevents meeting link leaking).
    let plain = format!(
        "Hi {},\n\n\
         Your booking request has been received and is awaiting confirmation from {}.\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         {}\
         You'll receive another email once it's confirmed.\n\
         {}\n\
         \u{2014} calrs",
        details.guest_name,
        details.host_name,
        details.event_title,
        details.date,
        time_display,
        details
            .notes
            .as_ref()
            .map(|n| format!("Notes: {}\n", n))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!("\nNeed to cancel? {}\n", u))
            .unwrap_or_default(),
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: details.date.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Host".to_string(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: "Notes".to_string(),
            value: notes.clone(),
        });
    }

    let mut actions: Vec<EmailAction> = Vec::new();
    if let Some(u) = reschedule_url {
        actions.push(EmailAction {
            label: "Reschedule".to_string(),
            url: u.to_string(),
            color: "#3b82f6".to_string(),
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
            "Your booking request is awaiting confirmation from {}.",
            h(&details.host_name)
        ),
        "#f59e0b",
        &rows,
        Some("You\u{2019}ll receive another email once it\u{2019}s confirmed."),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Pending: {} \u{2014} {}",
            details.event_title, details.date
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Send approval request to host with approve/decline buttons
pub async fn send_host_approval_request(
    config: &SmtpConfig,
    details: &BookingDetails,
    _booking_id: &str,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

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
        _ => "Log in to your dashboard to confirm or decline this booking.".to_string(),
    };

    let plain = format!(
        "New booking request requiring your approval!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}{}\n\
         {}\n\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        details
            .notes
            .as_ref()
            .map(|n| format!("Notes: {}\n", n))
            .unwrap_or_default(),
        action_text,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: "Notes".to_string(),
            value: notes.clone(),
        });
    }

    let actions: Vec<EmailAction> = match (approve_url, decline_url) {
        (Some(a), Some(d)) => vec![
            EmailAction {
                label: "Approve".to_string(),
                url: a,
                color: "#16a34a".to_string(),
            },
            EmailAction {
                label: "Decline".to_string(),
                url: d,
                color: "#dc2626".to_string(),
            },
        ],
        _ => vec![],
    };

    let html = render_html_email_with_actions(
        "Action required",
        &format!("{} wants to book a slot with you.", h(&details.guest_name)),
        "#f59e0b",
        &rows,
        Some("You can also manage this from your dashboard."),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Action required: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Send decline notification to the guest
pub async fn send_guest_decline_notice(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = if details.guest_timezone.is_empty() {
        format!("{} \u{2013} {}", details.start_time, details.end_time)
    } else {
        format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        )
    };
    let reason_text = details
        .reason
        .as_ref()
        .map(|r| format!("Reason: {}\n\n", r))
        .unwrap_or_default();

    let plain = format!(
        "Hi {},\n\n\
         Your booking request has been declined.\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         With: {}\n\n\
         {}\
         \u{2014} calrs",
        details.guest_name,
        details.event_title,
        details.date,
        time_display,
        details.host_name,
        reason_text,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: details.date.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "With".to_string(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(reason) = &details.reason {
        rows.push(EmailRow {
            label: "Reason".to_string(),
            value: reason.clone(),
        });
    }

    let html = render_html_email(
        &format!("Hi {},", h(&details.guest_name)),
        "Your booking request has been declined.",
        "#dc2626",
        &rows,
        None,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Declined: {} \u{2014} {}",
            details.event_title, details.date
        ))
        .multipart(body)?;

    send_email(config, email).await
}

