use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::utils::prompt;

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// Configure SMTP for email notifications
    Smtp {
        /// SMTP server host
        #[arg(long)]
        host: Option<String>,
        /// SMTP port (default: 587)
        #[arg(long)]
        port: Option<u16>,
        /// SMTP username
        #[arg(long)]
        username: Option<String>,
        /// From email address
        #[arg(long)]
        from_email: Option<String>,
        /// From display name
        #[arg(long)]
        from_name: Option<String>,
    },
    /// Show current configuration
    Show,
    /// Send a test email
    SmtpTest {
        /// Email address to send test to
        to: String,
    },
    /// Configure authentication settings
    Auth {
        /// Enable or disable registration
        #[arg(long)]
        registration: Option<bool>,
        /// Comma-separated list of allowed email domains (empty to allow all)
        #[arg(long)]
        allowed_domains: Option<String>,
    },
    /// Dump all configuration as JSON
    Dump {
        /// Pretty-print the JSON output
        #[arg(long)]
        pretty: bool,
    },
    /// Configure OIDC (OpenID Connect) for SSO login
    Oidc {
        /// OIDC issuer URL (e.g. https://keycloak.example.com/realms/myrealm)
        #[arg(long)]
        issuer_url: Option<String>,
        /// OIDC client ID
        #[arg(long)]
        client_id: Option<String>,
        /// OIDC client secret
        #[arg(long)]
        client_secret: Option<String>,
        /// Enable or disable OIDC
        #[arg(long)]
        enabled: Option<bool>,
        /// Auto-register users on first OIDC login
        #[arg(long)]
        auto_register: Option<bool>,
    },
}

// ── Dump-specific structs (no secret fields) ──

// Note: oidc_client_secret, captcha_secret, google_oauth2_client_secret and
// meeting_webhook_secret are deliberately excluded (secrets).
#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct AuthConfigDump {
    registration_enabled: bool,
    allowed_email_domains: Option<String>,
    oidc_enabled: bool,
    oidc_issuer_url: Option<String>,
    oidc_client_id: Option<String>,
    oidc_auto_register: bool,
    accent_color: String,
    theme: String,
    custom_accent: Option<String>,
    custom_accent_hover: Option<String>,
    custom_bg: Option<String>,
    custom_surface: Option<String>,
    custom_text: Option<String>,
    company_link: Option<String>,
    captcha_instance_url: Option<String>,
    captcha_site_key: Option<String>,
    captcha_widget_url: Option<String>,
    google_oauth2_client_id: Option<String>,
    jitsi_base_url: Option<String>,
    jitsi_pattern: Option<String>,
    jitsi_display_name: Option<String>,
    meeting_webhook_url: Option<String>,
    meeting_webhook_auth_mode: Option<String>,
    meeting_webhook_display_name: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct SmtpConfigDump {
    id: String,
    host: String,
    port: i32,
    username: String,
    from_email: String,
    from_name: Option<String>,
    tls_mode: String,
    enabled: bool,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct UserDump {
    id: String,
    email: String,
    name: String,
    timezone: String,
    role: String,
    auth_provider: String,
    oidc_subject: Option<String>,
    enabled: bool,
    created_at: String,
    username: Option<String>,
    booking_email: Option<String>,
    title: Option<String>,
    bio: Option<String>,
    allow_dynamic_group: bool,
    language: Option<String>,
}

// Note: password_enc, access_token_enc and refresh_token_enc are deliberately
// excluded (secrets). last_synced / sync_token / last_full_sync /
// token_expires_at are excluded too — they are operational sync state, not
// configuration, and must not be transplanted by a future `config import`
// onto a fresh deployment.
#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct CaldavSourceDump {
    id: String,
    account_id: String,
    name: String,
    url: String,
    username: String,
    provider_type: String,
    auth_type: String,
    oauth2_provider: Option<String>,
    write_calendar_href: Option<String>,
    enabled: bool,
    created_at: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct EventTypeDump {
    id: String,
    account_id: String,
    slug: String,
    title: String,
    duration_min: i32,
    location_type: String,
    location_value: Option<String>,
    buffer_before: i32,
    buffer_after: i32,
    min_notice_min: i32,
    enabled: bool,
    requires_confirmation: bool,
    reminder_minutes: Option<i32>,
    max_additional_guests: Option<i32>,
    scheduling_mode: String,
    first_slot_only: bool,
    default_calendar_view: String,
    visibility: String,
    slot_interval_min: Option<i32>,
    timezone: Option<String>,
    cancel_notice_min: Option<i32>,
    reschedule_notice_min: Option<i32>,
    meeting_pattern_override: Option<String>,
    team_id: Option<String>,
    group_id: Option<String>,
    created_by_user_id: Option<String>,
    created_at: String,
    description: Option<String>,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct TeamDump {
    id: String,
    name: String,
    slug: Option<String>,
    description: Option<String>,
    avatar_path: Option<String>,
    visibility: String,
    created_at: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct GroupDump {
    id: String,
    name: String,
    source: String,
    oidc_id: Option<String>,
    created_at: String,
    slug: Option<String>,
    description: Option<String>,
    avatar_path: Option<String>,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct AccountDump {
    id: String,
    user_id: Option<String>,
    name: String,
    email: String,
    timezone: String,
    created_at: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct AvailabilityRuleDump {
    id: String,
    event_type_id: String,
    day_of_week: i32,
    start_time: String,
    end_time: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct AvailabilityOverrideDump {
    id: String,
    event_type_id: String,
    date: String,
    start_time: Option<String>,
    end_time: Option<String>,
    is_blocked: bool,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct UserAvailabilityRuleDump {
    id: String,
    user_id: String,
    day_of_week: i32,
    start_time: String,
    end_time: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct EventTypeCalendarDump {
    event_type_id: String,
    calendar_id: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct EventTypeMemberWeightDump {
    event_type_id: String,
    user_id: String,
    weight: i32,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct EventTypeWatcherDump {
    event_type_id: String,
    team_id: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct TeamMemberDump {
    team_id: String,
    user_id: String,
    role: String,
    source: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct TeamGroupDump {
    team_id: String,
    group_id: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct UserGroupDump {
    user_id: String,
    group_id: String,
    weight: i32,
}

#[derive(serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "snake_case")]
struct BookingFrequencyLimitDump {
    id: String,
    event_type_id: String,
    max_bookings: i32,
    period: String,
    per_member: bool,
}

/// Fetch all rows of a dump struct and serialize them as a JSON array.
async fn dump_table<T>(pool: &SqlitePool, sql: &str) -> Result<serde_json::Value>
where
    T: for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> + serde::Serialize + Send + Unpin,
{
    let rows: Vec<T> = sqlx::query_as::<_, T>(sql).fetch_all(pool).await?;
    Ok(serde_json::to_value(&rows)?)
}

/// Build the full dump output as a JSON value, querying each config section.
async fn build_dump_output(pool: &SqlitePool) -> Result<serde_json::Value> {
    // Auth config — SELECT only non-secret columns (omit oidc_client_secret)
    let auth_json = sqlx::query_as::<_, AuthConfigDump>(
        "SELECT registration_enabled, allowed_email_domains, oidc_enabled, \
         oidc_issuer_url, oidc_client_id, oidc_auto_register, \
         accent_color, theme, custom_accent, custom_accent_hover, custom_bg, \
         custom_surface, custom_text, company_link, \
         captcha_instance_url, captcha_site_key, captcha_widget_url, \
         google_oauth2_client_id, \
         jitsi_base_url, jitsi_pattern, jitsi_display_name, \
         meeting_webhook_url, meeting_webhook_auth_mode, meeting_webhook_display_name, \
         created_at, updated_at \
         FROM auth_config WHERE id = 'singleton'",
    )
    .fetch_one(pool)
    .await?;
    let auth_json = serde_json::to_value(&auth_json)?;

    // SMTP config — skip password_enc (secret)
    let smtp_json: serde_json::Value = match sqlx::query_as::<_, SmtpConfigDump>(
        "SELECT id, host, port, username, from_email, from_name, tls_mode, enabled \
         FROM smtp_config LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    {
        Some(row) => serde_json::to_value(&row)?,
        None => serde_json::Value::Null,
    };

    // Accounts — scheduling profiles linked to users
    let accounts_json = dump_table::<AccountDump>(
        pool,
        "SELECT id, user_id, name, email, timezone, created_at \
         FROM accounts ORDER BY email",
    )
    .await?;

    // Users — all users including disabled ones (the `enabled` flag is part of
    // the configuration); skip password_hash (secret)
    let users_json = dump_table::<UserDump>(
        pool,
        "SELECT id, email, name, timezone, role, auth_provider, \
         oidc_subject, enabled, created_at, username, booking_email, \
         title, bio, allow_dynamic_group, language \
         FROM users ORDER BY email",
    )
    .await?;

    // Per-user default working hours
    let user_availability_rules_json = dump_table::<UserAvailabilityRuleDump>(
        pool,
        "SELECT id, user_id, day_of_week, start_time, end_time \
         FROM user_availability_rules ORDER BY user_id, day_of_week, start_time",
    )
    .await?;

    // OIDC group membership + round-robin weight
    let user_groups_json = dump_table::<UserGroupDump>(
        pool,
        "SELECT user_id, group_id, weight FROM user_groups ORDER BY group_id, user_id",
    )
    .await?;

    // CalDAV/EWS sources — skip credentials (secrets) and sync state (operational)
    let caldav_sources_json = dump_table::<CaldavSourceDump>(
        pool,
        "SELECT id, account_id, name, url, username, \
         provider_type, auth_type, oauth2_provider, \
         write_calendar_href, enabled, created_at \
         FROM caldav_sources ORDER BY name",
    )
    .await?;

    // Event types — selected config fields, no operational data
    let event_types_json = dump_table::<EventTypeDump>(
        pool,
        "SELECT id, account_id, slug, title, duration_min, location_type, \
         location_value, buffer_before, buffer_after, min_notice_min, enabled, \
         requires_confirmation, reminder_minutes, max_additional_guests, \
         scheduling_mode, first_slot_only, default_calendar_view, visibility, \
         slot_interval_min, timezone, cancel_notice_min, reschedule_notice_min, \
         meeting_pattern_override, team_id, group_id, created_by_user_id, \
         created_at, description \
         FROM event_types ORDER BY title",
    )
    .await?;

    // Weekly availability windows per event type
    let availability_rules_json = dump_table::<AvailabilityRuleDump>(
        pool,
        "SELECT id, event_type_id, day_of_week, start_time, end_time \
         FROM availability_rules ORDER BY event_type_id, day_of_week, start_time",
    )
    .await?;

    // Date-specific exceptions per event type
    let availability_overrides_json = dump_table::<AvailabilityOverrideDump>(
        pool,
        "SELECT id, event_type_id, date, start_time, end_time, is_blocked \
         FROM availability_overrides ORDER BY event_type_id, date",
    )
    .await?;

    // Per-event-type calendar selection
    let event_type_calendars_json = dump_table::<EventTypeCalendarDump>(
        pool,
        "SELECT event_type_id, calendar_id \
         FROM event_type_calendars ORDER BY event_type_id, calendar_id",
    )
    .await?;

    // Per-event-type round-robin member weights
    let event_type_member_weights_json = dump_table::<EventTypeMemberWeightDump>(
        pool,
        "SELECT event_type_id, user_id, weight \
         FROM event_type_member_weights ORDER BY event_type_id, user_id",
    )
    .await?;

    // Teams watching an event type for booking claims
    let event_type_watchers_json = dump_table::<EventTypeWatcherDump>(
        pool,
        "SELECT event_type_id, team_id \
         FROM event_type_watchers ORDER BY event_type_id, team_id",
    )
    .await?;

    // Per-event-type booking caps
    let booking_frequency_limits_json = dump_table::<BookingFrequencyLimitDump>(
        pool,
        "SELECT id, event_type_id, max_bookings, period, per_member \
         FROM booking_frequency_limits ORDER BY event_type_id",
    )
    .await?;

    // Teams — skip invite_token (secret: grants access to private teams)
    let teams_json = dump_table::<TeamDump>(
        pool,
        "SELECT id, name, slug, description, avatar_path, \
         visibility, created_at \
         FROM teams ORDER BY name",
    )
    .await?;

    // Team composition (direct members and OIDC-synced members)
    let team_members_json = dump_table::<TeamMemberDump>(
        pool,
        "SELECT team_id, user_id, role, source FROM team_members ORDER BY team_id, user_id",
    )
    .await?;

    // OIDC group linkage for automatic member sync
    let team_groups_json = dump_table::<TeamGroupDump>(
        pool,
        "SELECT team_id, group_id FROM team_groups ORDER BY team_id, group_id",
    )
    .await?;

    // Groups (legacy — kept for OIDC identity sync)
    let groups_json = dump_table::<GroupDump>(
        pool,
        "SELECT id, name, source, oidc_id, created_at, \
         slug, description, avatar_path \
         FROM groups ORDER BY name",
    )
    .await?;

    Ok(serde_json::json!({
        "schema_version": 1,
        "auth": auth_json,
        "smtp": smtp_json,
        "accounts": accounts_json,
        "users": users_json,
        "user_availability_rules": user_availability_rules_json,
        "user_groups": user_groups_json,
        "caldav_sources": caldav_sources_json,
        "event_types": event_types_json,
        "availability_rules": availability_rules_json,
        "availability_overrides": availability_overrides_json,
        "event_type_calendars": event_type_calendars_json,
        "event_type_member_weights": event_type_member_weights_json,
        "event_type_watchers": event_type_watchers_json,
        "booking_frequency_limits": booking_frequency_limits_json,
        "teams": teams_json,
        "team_members": team_members_json,
        "team_groups": team_groups_json,
        "groups": groups_json,
    }))
}

pub async fn run(pool: &SqlitePool, key: &[u8; 32], cmd: ConfigCommands) -> Result<()> {
    match cmd {
        ConfigCommands::Smtp {
            host,
            port,
            username,
            from_email,
            from_name,
        } => {
            let host = host.unwrap_or_else(|| prompt("SMTP host"));
            let port = port.unwrap_or_else(|| {
                let p = prompt("SMTP port (default 587)");
                if p.is_empty() {
                    587
                } else {
                    p.parse().unwrap_or(587)
                }
            });
            let username = username.unwrap_or_else(|| prompt("SMTP username"));
            let password = prompt("SMTP password");
            let from_email = from_email.unwrap_or_else(|| prompt("From email"));
            let from_name = from_name.or_else(|| {
                let name = prompt("From name (optional, press Enter to skip)");
                if name.is_empty() {
                    None
                } else {
                    Some(name)
                }
            });
            let tls_mode = {
                let raw = prompt("TLS mode (starttls/tls, default starttls)");
                let normalized = raw.trim().to_ascii_lowercase();
                match normalized.as_str() {
                    "" | "starttls" => "starttls",
                    "tls" => "tls",
                    other => {
                        anyhow::bail!(
                            "Invalid TLS mode '{}'. Use 'starttls' (default, port 587) or 'tls' (implicit TLS, port 465).",
                            other
                        );
                    }
                }
            };

            let password_enc = crate::crypto::encrypt_password(key, &password)?;
            let id = Uuid::new_v4().to_string();

            // SMTP is a system-wide singleton: clear any prior row before inserting.
            sqlx::query("DELETE FROM smtp_config").execute(pool).await?;

            sqlx::query(
                "INSERT INTO smtp_config (id, host, port, username, password_enc, from_email, from_name, tls_mode)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(&host)
            .bind(port as i32)
            .bind(&username)
            .bind(&password_enc)
            .bind(&from_email)
            .bind(&from_name)
            .bind(tls_mode)
            .execute(pool)
            .await?;

            println!(
                "{} SMTP configured ({}:{}, {})",
                "✓".green(),
                host,
                port,
                tls_mode
            );
        }
        ConfigCommands::Show => {
            let smtp: Option<(String, i32, String, String, Option<String>, bool)> = sqlx::query_as(
                "SELECT host, port, username, from_email, from_name, enabled FROM smtp_config LIMIT 1",
            )
            .fetch_optional(pool)
            .await?;

            match smtp {
                Some((host, port, username, from_email, from_name, enabled)) => {
                    println!("{}:", "SMTP".bold());
                    println!("  Host:     {}:{}", host, port);
                    println!("  Username: {}", username);
                    println!(
                        "  From:     {} <{}>",
                        from_name.as_deref().unwrap_or(""),
                        from_email
                    );
                    println!("  Enabled:  {}", if enabled { "✓" } else { "✗" });
                }
                None => {
                    println!("No SMTP configured. Run `calrs config smtp` to set it up.");
                }
            }

            println!();
            let auth_config = crate::auth::get_auth_config(pool).await?;
            println!("{}:", "Authentication".bold());
            println!(
                "  Registration:  {}",
                if auth_config.registration_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            match &auth_config.allowed_email_domains {
                Some(d) if !d.is_empty() => println!("  Allowed domains: {}", d),
                _ => println!("  Allowed domains: {}", "(any)".dimmed()),
            }

            println!();
            println!("{}:", "OIDC".bold());
            if auth_config.oidc_enabled {
                println!("  Enabled:       {}", "✓".green());
                println!(
                    "  Issuer:        {}",
                    auth_config
                        .oidc_issuer_url
                        .as_deref()
                        .unwrap_or("(not set)")
                );
                println!(
                    "  Client ID:     {}",
                    auth_config.oidc_client_id.as_deref().unwrap_or("(not set)")
                );
                println!(
                    "  Client secret: {}",
                    if auth_config.oidc_client_secret.is_some() {
                        "****"
                    } else {
                        "(not set)"
                    }
                );
                println!(
                    "  Auto-register: {}",
                    if auth_config.oidc_auto_register {
                        "yes"
                    } else {
                        "no"
                    }
                );
            } else {
                println!("  Enabled:       {}", "✗".dimmed());
                println!("  {}", "Run `calrs config oidc` to set up SSO.".dimmed());
            }
        }
        ConfigCommands::SmtpTest { to } => {
            let smtp_config = crate::email::load_smtp_config(pool, key).await?;
            match smtp_config {
                Some(config) => {
                    println!("{} Sending test email to {}…", "…".dimmed(), to);
                    crate::email::send_test_email(&config, &to).await?;
                    println!("{} Test email sent!", "✓".green());
                }
                None => {
                    println!(
                        "{} No SMTP configured. Run `calrs config smtp` first.",
                        "✗".red()
                    );
                }
            }
        }
        ConfigCommands::Auth {
            registration,
            allowed_domains,
        } => {
            if registration.is_none() && allowed_domains.is_none() {
                // Show current auth config
                let config = crate::auth::get_auth_config(pool).await?;
                println!("{}:", "Authentication".bold());
                println!(
                    "  Registration: {}",
                    if config.registration_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                match &config.allowed_email_domains {
                    Some(domains) if !domains.is_empty() => {
                        println!("  Allowed domains: {}", domains);
                    }
                    _ => {
                        println!("  Allowed domains: {}", "(any)".dimmed());
                    }
                }
            } else {
                if let Some(reg) = registration {
                    sqlx::query(
                        "UPDATE auth_config SET registration_enabled = ?, updated_at = datetime('now') WHERE id = 'singleton'",
                    )
                    .bind(reg)
                    .execute(pool)
                    .await?;
                    println!(
                        "{} Registration {}",
                        "✓".green(),
                        if reg { "enabled" } else { "disabled" }
                    );
                }
                if let Some(domains) = allowed_domains {
                    let domains = if domains.is_empty() || domains == "any" {
                        None
                    } else {
                        Some(domains)
                    };
                    sqlx::query(
                        "UPDATE auth_config SET allowed_email_domains = ?, updated_at = datetime('now') WHERE id = 'singleton'",
                    )
                    .bind(&domains)
                    .execute(pool)
                    .await?;
                    match &domains {
                        Some(d) => println!("{} Allowed domains set to: {}", "✓".green(), d),
                        None => println!("{} Allowed domain restriction removed", "✓".green()),
                    }
                }
            }
        }
        ConfigCommands::Dump { pretty } => {
            let output = build_dump_output(pool).await?;
            let json = if pretty {
                serde_json::to_string_pretty(&output)
            } else {
                serde_json::to_string(&output)
            }
            .context("Failed to serialize dump output")?;
            println!("{json}");
        }
        ConfigCommands::Oidc {
            issuer_url,
            client_id,
            client_secret,
            enabled,
            auto_register,
        } => {
            // If no flags, prompt interactively
            if issuer_url.is_none()
                && client_id.is_none()
                && client_secret.is_none()
                && enabled.is_none()
                && auto_register.is_none()
            {
                let issuer =
                    prompt("OIDC issuer URL (e.g. https://keycloak.example.com/realms/myrealm)");
                let cid = prompt("Client ID");
                let csecret = prompt("Client secret");
                let auto_reg = prompt("Auto-register users on first login? (y/n)");

                let encrypted_secret = crate::crypto::encrypt_value(key, &csecret)?;
                sqlx::query(
                    "UPDATE auth_config SET oidc_enabled = 1, oidc_issuer_url = ?, oidc_client_id = ?, oidc_client_secret = ?, oidc_auto_register = ?, updated_at = datetime('now') WHERE id = 'singleton'",
                )
                .bind(&issuer)
                .bind(&cid)
                .bind(&encrypted_secret)
                .bind(auto_reg.starts_with('y') || auto_reg.starts_with('Y'))
                .execute(pool)
                .await?;

                println!("{} OIDC configured and enabled", "✓".green());
                println!("  Issuer:    {}", issuer);
                println!("  Client ID: {}", cid);
            } else {
                if let Some(url) = issuer_url {
                    sqlx::query("UPDATE auth_config SET oidc_issuer_url = ?, updated_at = datetime('now') WHERE id = 'singleton'")
                        .bind(&url)
                        .execute(pool)
                        .await?;
                    println!("{} OIDC issuer URL set", "✓".green());
                }
                if let Some(cid) = client_id {
                    sqlx::query("UPDATE auth_config SET oidc_client_id = ?, updated_at = datetime('now') WHERE id = 'singleton'")
                        .bind(&cid)
                        .execute(pool)
                        .await?;
                    println!("{} OIDC client ID set", "✓".green());
                }
                if let Some(cs) = client_secret {
                    let encrypted_secret = crate::crypto::encrypt_value(key, &cs)?;
                    sqlx::query("UPDATE auth_config SET oidc_client_secret = ?, updated_at = datetime('now') WHERE id = 'singleton'")
                        .bind(&encrypted_secret)
                        .execute(pool)
                        .await?;
                    println!("{} OIDC client secret set", "✓".green());
                }
                if let Some(en) = enabled {
                    sqlx::query("UPDATE auth_config SET oidc_enabled = ?, updated_at = datetime('now') WHERE id = 'singleton'")
                        .bind(en)
                        .execute(pool)
                        .await?;
                    println!(
                        "{} OIDC {}",
                        "✓".green(),
                        if en { "enabled" } else { "disabled" }
                    );
                }
                if let Some(ar) = auto_register {
                    sqlx::query("UPDATE auth_config SET oidc_auto_register = ?, updated_at = datetime('now') WHERE id = 'singleton'")
                        .bind(ar)
                        .execute(pool)
                        .await?;
                    println!(
                        "{} OIDC auto-register {}",
                        "✓".green(),
                        if ar { "enabled" } else { "disabled" }
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
