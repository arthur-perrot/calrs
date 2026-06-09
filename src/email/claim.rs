// --- Watcher claim emails ---

pub async fn send_watcher_claim_notification(
    config: &SmtpConfig,
    details: &BookingDetails,
    watcher_name: &str,
    watcher_email: &str,
    assigned_to_name: &str,
    claim_url: &str,
) -> Result<()> {
    let to = format!("{} <{}>", watcher_name, watcher_email).parse()?;

    let time_display = format!("{} \u{2013} {}", details.start_time, details.end_time);

    let plain = format!(
        "New booking available to claim!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         Assigned to: {}\n\
         {}\
         Claim this booking: {}\n\n\
         \u{2014} calrs",
        details.event_title,
        details.date,
        time_display,
        details.guest_name,
        details.guest_email,
        assigned_to_name,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        claim_url,
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
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
        EmailRow {
            label: "Assigned to".to_string(),
            value: assigned_to_name.to_string(),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }

    let actions = vec![EmailAction {
        label: "Claim this booking".to_string(),
        url: claim_url.to_string(),
        color: "#3b82f6".to_string(),
    }];

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(watcher_name)),
        "A new booking is available to claim. Click below to join as an attendee.",
        "#3b82f6",
        &rows,
        Some("You can also claim from your dashboard."),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Claim available: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, details.date
        ))
        .multipart(body)?;

    send_email(config, email).await
}

pub async fn send_claim_confirmation(
    config: &SmtpConfig,
    details: &BookingDetails,
    claimant_name: &str,
    claimant_email: &str,
) -> Result<()> {
    let to = format!("{} <{}>", claimant_name, claimant_email).parse()?;

    let time_display = format!("{} \u{2013} {}", details.start_time, details.end_time);

    let plain = format!(
        "You claimed this booking!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}\
         A calendar invite has been sent.\n\n\
         \u{2014} calrs",
        details.event_title,
        details.date,
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
            value: details.date.clone(),
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
        &format!("Hi {},", h(claimant_name)),
        "You have successfully claimed this booking. A calendar invite is attached.",
        "#16a34a",
        &rows,
        Some("You will be added as an attendee on this meeting."),
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Booking claimed: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, details.date
        ))
        .multipart(body)?;

    send_email(config, email).await
}
