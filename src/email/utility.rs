// --- Utility ---

const SMTP_ENV_VARS: &[&str] = &[
    "CALRS_SMTP_HOST",
    "CALRS_SMTP_PORT",
    "CALRS_SMTP_TLS_MODE",
    "CALRS_SMTP_USERNAME",
    "CALRS_SMTP_PASSWORD",
    "CALRS_SMTP_FROM_EMAIL",
    "CALRS_SMTP_FROM_NAME",
];

fn required_smtp_env(name: &str) -> Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => bail!("{} must not be empty", name),
        Err(_) => bail!(
            "{} is required when SMTP is configured via environment",
            name
        ),
    }
}

fn load_smtp_config_from_env() -> Result<Option<SmtpConfig>> {
    if !SMTP_ENV_VARS
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return Ok(None);
    }

    let host = required_smtp_env("CALRS_SMTP_HOST")?;
    let username = required_smtp_env("CALRS_SMTP_USERNAME")?;
    let password = required_smtp_env("CALRS_SMTP_PASSWORD")?;
    let from_email = required_smtp_env("CALRS_SMTP_FROM_EMAIL")?;
    let port = match std::env::var("CALRS_SMTP_PORT") {
        Ok(value) if value.trim().is_empty() => bail!("CALRS_SMTP_PORT must not be empty"),
        Ok(value) => value.trim().parse::<u16>().map_err(|_| {
            anyhow::anyhow!("CALRS_SMTP_PORT must be a valid TCP port (got '{}')", value)
        })?,
        Err(_) => 587u16,
    };
    let tls_mode = match std::env::var("CALRS_SMTP_TLS_MODE") {
        Ok(value) if value.trim().is_empty() => bail!("CALRS_SMTP_TLS_MODE must not be empty"),
        Ok(value) => SmtpTlsMode::parse(&value)?,
        Err(_) => SmtpTlsMode::StartTls,
    };
    let from_name = std::env::var("CALRS_SMTP_FROM_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty());

    Ok(Some(SmtpConfig {
        host,
        port,
        username,
        password,
        from_email,
        from_name,
        tls_mode,
    }))
}

/// Load SMTP config from environment or database.
pub async fn load_smtp_config(pool: &SqlitePool, key: &[u8; 32]) -> Result<Option<SmtpConfig>> {
    if let Some(config) = load_smtp_config_from_env()? {
        return Ok(Some(config));
    }

    let row: Option<(String, i32, String, String, String, Option<String>, String)> =
        sqlx::query_as(
            "SELECT host, port, username, password_enc, from_email, from_name, tls_mode
         FROM smtp_config WHERE enabled = 1 LIMIT 1",
        )
        .fetch_optional(pool)
        .await?;

    match row {
        Some((host, port, username, password_enc, from_email, from_name, tls_mode)) => {
            let password = crate::crypto::decrypt_password(key, &password_enc)?;
            let tls_mode = SmtpTlsMode::parse(&tls_mode).unwrap_or(SmtpTlsMode::StartTls);
            Ok(Some(SmtpConfig {
                host,
                port: port as u16,
                username,
                password,
                from_email,
                from_name,
                tls_mode,
            }))
        }
        None => Ok(None),
    }
}

/// Load non-secret SMTP status for admin display.
///
/// Unlike [`load_smtp_config`] this does NOT filter by `enabled = 1` — the
/// admin panel needs to surface a disabled-but-configured row so the operator
/// can see that SMTP exists and re-enable it. `load_smtp_config` only returns
/// rows that are actually usable for sending, so it keeps the `WHERE enabled`
/// guard.
pub async fn load_smtp_status(pool: &SqlitePool) -> Result<Option<SmtpStatus>> {
    if let Some(config) = load_smtp_config_from_env()? {
        return Ok(Some(SmtpStatus {
            host: config.host,
            port: config.port,
            from_email: config.from_email,
            enabled: true,
            from_env: true,
        }));
    }

    let row: Option<(String, i32, String, bool)> =
        sqlx::query_as("SELECT host, port, from_email, enabled FROM smtp_config LIMIT 1")
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(host, port, from_email, enabled)| SmtpStatus {
        host,
        port: port as u16,
        from_email,
        enabled,
        from_env: false,
    }))
}

/// Send a test email
pub async fn send_test_email(config: &SmtpConfig, to_email: &str) -> Result<()> {
    let to = to_email.parse()?;

    let plain = "This is a test email from calrs. SMTP is working!".to_string();

    let html = render_html_email(
        "SMTP test",
        "This is a test email from calrs. SMTP is working!",
        "#6366f1",
        &[],
        None,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject("calrs \u{2014} SMTP test")
        .multipart(body)?;

    // Debug is only useful when sending a test email
    tracing::debug!("Sending: {:?}", email);
    send_email(config, email).await
}

/// Send a booking invite email to a guest
pub async fn send_invite_email(
    config: &SmtpConfig,
    guest_name: &str,
    guest_email: &str,
    event_title: &str,
    host_name: &str,
    message: Option<&str>,
    invite_url: &str,
    expires_at: Option<&str>,
) -> Result<()> {
    let from = config.mailbox_from()?;
    let to = format!("{} <{}>", guest_name, guest_email).parse()?;

    let expiry_note = expires_at
        .map(|e| format!("\nThis invite expires on {}.", e))
        .unwrap_or_default();
    let message_note = message
        .filter(|m| !m.trim().is_empty())
        .map(|m| format!("\n\n\"{}\"\n", m))
        .unwrap_or_default();

    let plain = format!(
        "Hi {},\n\n\
         {} has invited you to book: {}\n\
         {}\
         Click the link below to choose a time:\n\
         {}\n\
         {}\n\
         \u{2014} calrs",
        guest_name, host_name, event_title, message_note, invite_url, expiry_note,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: event_title.to_string(),
        },
        EmailRow {
            label: "Invited by".to_string(),
            value: host_name.to_string(),
        },
    ];
    if let Some(msg) = message.filter(|m| !m.trim().is_empty()) {
        rows.push(EmailRow {
            label: "Message".to_string(),
            value: msg.to_string(),
        });
    }
    if let Some(exp) = expires_at {
        rows.push(EmailRow {
            label: "Expires".to_string(),
            value: exp.to_string(),
        });
    }

    let actions = vec![EmailAction {
        label: "Choose a time".to_string(),
        url: invite_url.to_string(),
        color: "#6366f1".to_string(),
    }];

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(guest_name)),
        &format!(
            "{} has invited you to book: {}",
            h(host_name),
            h(event_title)
        ),
        "#6366f1",
        &rows,
        None,
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(from)
        .to(to)
        .subject(format!(
            "{} invited you to book: {}",
            host_name, event_title
        ))
        .multipart(body)?;

    send_email(config, email).await
}

async fn send_email(config: &SmtpConfig, email: Message) -> Result<()> {
    let creds = Credentials::new(config.username.clone(), config.password.clone());

    let mailer = match config.tls_mode {
        SmtpTlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
            .port(config.port)
            .credentials(creds)
            .build(),
        SmtpTlsMode::StartTls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)?
                .port(config.port)
                .credentials(creds)
                .build()
        }
    };

    let to_addrs: Vec<String> = email
        .envelope()
        .to()
        .iter()
        .map(|a| a.to_string())
        .collect();
    let to_display = to_addrs.join(", ");
    match mailer.send(email).await {
        Ok(_) => {
            tracing::debug!(to = %to_display, "email delivered");
            Ok(())
        }
        Err(e) => {
            tracing::error!(to = %to_display, error = %e, "email delivery failed");
            Err(e.into())
        }
    }
}

