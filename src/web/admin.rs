// --- Admin dashboard ---

async fn admin_dashboard(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let current_user = &admin.0;
    let error_message = query.get("error").cloned().unwrap_or_default();

    // Fetch all users
    let users: Vec<(String, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT id, name, email, role, auth_provider, enabled FROM users ORDER BY created_at",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let user_count = users.len();

    // Fetch groups per user
    let user_groups_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT ug.user_id, g.name FROM user_groups ug JOIN groups g ON g.id = ug.group_id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // Build a map of user_id -> comma-separated group names
    let mut user_groups_map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (uid, gname) in &user_groups_rows {
        user_groups_map
            .entry(uid.clone())
            .or_default()
            .push(gname.clone());
    }

    let users_ctx: Vec<minijinja::Value> = users
        .iter()
        .map(|(id, name, email, role, auth_provider, enabled)| {
            let groups = user_groups_map.get(id).cloned().unwrap_or_default();
            context! {
                id => id,
                name => name,
                email => email,
                role => role,
                auth_provider => auth_provider,
                enabled => enabled,
                groups => groups,
            }
        })
        .collect();

    // Fetch groups with member count
    let groups_rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, COUNT(ug.user_id) as member_count \
         FROM groups g LEFT JOIN user_groups ug ON ug.group_id = g.id \
         GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let group_count = groups_rows.len();

    // Fetch all group members with weights
    let all_members: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT ug.group_id, ug.user_id, u.name, ug.weight \
         FROM user_groups ug JOIN users u ON u.id = ug.user_id \
         ORDER BY ug.weight DESC, u.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let groups_ctx: Vec<minijinja::Value> = groups_rows
        .iter()
        .map(|(id, name, member_count)| {
            let members: Vec<minijinja::Value> = all_members
                .iter()
                .filter(|(gid, _, _, _)| gid == id)
                .map(|(_, uid, uname, w)| {
                    context! {
                        user_id => uid,
                        name => uname,
                        weight => w,
                    }
                })
                .collect();
            context! {
                id => id,
                name => name,
                member_count => member_count,
                members => members,
            }
        })
        .collect();

    // Fetch auth config
    let auth_config = crate::auth::get_auth_config(&state.pool).await.ok();
    let registration_enabled = auth_config
        .as_ref()
        .map(|c| c.registration_enabled)
        .unwrap_or(false);
    let allowed_email_domains = auth_config
        .as_ref()
        .and_then(|c| c.allowed_email_domains.clone())
        .unwrap_or_default();
    let oidc_enabled = auth_config
        .as_ref()
        .map(|c| c.oidc_enabled)
        .unwrap_or(false);
    let oidc_issuer_url = auth_config
        .as_ref()
        .and_then(|c| c.oidc_issuer_url.clone())
        .unwrap_or_default();
    let oidc_client_id = auth_config
        .as_ref()
        .and_then(|c| c.oidc_client_id.clone())
        .unwrap_or_default();
    let oidc_auto_register = auth_config
        .as_ref()
        .map(|c| c.oidc_auto_register)
        .unwrap_or(true);
    let google_oauth2_client_id = auth_config
        .as_ref()
        .and_then(|c| c.google_oauth2_client_id.clone())
        .unwrap_or_default();
    let google_oauth2_configured = !google_oauth2_client_id.is_empty();

    let (
        smtp_configured,
        smtp_host,
        smtp_port,
        smtp_from_email,
        smtp_enabled,
        smtp_from_env,
        smtp_error,
    ) = match crate::email::load_smtp_status(&state.pool).await {
        Ok(Some(status)) => (
            true,
            status.host,
            status.port,
            status.from_email,
            status.enabled,
            status.from_env,
            String::new(),
        ),
        Ok(None) => (
            false,
            String::new(),
            0u16,
            String::new(),
            false,
            false,
            String::new(),
        ),
        Err(e) => (
            false,
            String::new(),
            0u16,
            String::new(),
            false,
            true,
            e.to_string(),
        ),
    };

    let tmpl = match state.templates.get_template("admin.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let sidebar = context! {
        user_name => current_user.name,
        user_title => current_user.title.as_deref().unwrap_or(""),
        user_id => current_user.id,
        user_role => "admin",
        user_timezone => current_user.timezone,
        has_avatar => current_user.avatar_path.is_some(),
        user_initials => compute_initials(&current_user.name),
        active => "admin",
        version => env!("CARGO_PKG_VERSION"),
    };

    let captcha_cfg = state.captcha_config.read().await;
    let captcha_configured = captcha_cfg.is_some();
    let captcha_instance_url = captcha_cfg
        .as_ref()
        .map(|c| c.instance_url.clone())
        .unwrap_or_default();
    let captcha_site_key = captcha_cfg
        .as_ref()
        .map(|c| c.site_key.clone())
        .unwrap_or_default();
    let captcha_widget_url = captcha_cfg
        .as_ref()
        .map(|c| c.widget_url.clone())
        .unwrap_or_else(|| captcha::DEFAULT_WIDGET_URL.to_string());
    drop(captcha_cfg);

    let meeting_cfg = state.meeting_config.read().await;
    let jitsi_configured = meeting_cfg.jitsi.is_some();
    let jitsi_base_url = meeting_cfg
        .jitsi
        .as_ref()
        .map(|j| j.base_url.clone())
        .unwrap_or_default();
    let jitsi_pattern = meeting_cfg
        .jitsi
        .as_ref()
        .map(|j| j.pattern.clone())
        .unwrap_or_else(|| meeting::DEFAULT_JITSI_PATTERN.to_string());
    let jitsi_display_name = meeting_cfg
        .jitsi
        .as_ref()
        .and_then(|j| j.display_name.clone())
        .unwrap_or_default();
    let meeting_webhook_configured = meeting_cfg.webhook.is_some();
    let meeting_webhook_url = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| w.url.clone())
        .unwrap_or_default();
    let meeting_webhook_auth_mode = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| w.auth_mode.as_str().to_string())
        .unwrap_or_else(|| meeting::WEBHOOK_AUTH_NONE.to_string());
    let meeting_webhook_has_secret = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| !w.secret.is_empty())
        .unwrap_or(false);
    let meeting_webhook_display_name = meeting_cfg
        .webhook
        .as_ref()
        .and_then(|w| w.display_name.clone())
        .unwrap_or_default();
    drop(meeting_cfg);

    Html(
        tmpl.render(context! {
            current_user_id => current_user.id,
            users => users_ctx,
            user_count => user_count,
            groups => groups_ctx,
            group_count => group_count,
            registration_enabled => registration_enabled,
            allowed_email_domains => allowed_email_domains,
            oidc_enabled => oidc_enabled,
            oidc_issuer_url => oidc_issuer_url,
            oidc_client_id => oidc_client_id,
            oidc_auto_register => oidc_auto_register,
            google_oauth2_client_id => google_oauth2_client_id,
            google_oauth2_configured => google_oauth2_configured,
            base_url => std::env::var("CALRS_BASE_URL").unwrap_or_default(),
            smtp_configured => smtp_configured,
            smtp_host => smtp_host,
            smtp_port => smtp_port,
            smtp_from_email => smtp_from_email,
            smtp_enabled => smtp_enabled,
            smtp_from_env => smtp_from_env,
            smtp_error => smtp_error,
            captcha_configured => captcha_configured,
            captcha_instance_url => captcha_instance_url,
            captcha_site_key => captcha_site_key,
            captcha_widget_url => captcha_widget_url,
            jitsi_configured => jitsi_configured,
            jitsi_base_url => jitsi_base_url,
            jitsi_pattern => jitsi_pattern,
            jitsi_display_name => jitsi_display_name,
            jitsi_default_pattern => meeting::DEFAULT_JITSI_PATTERN,
            meeting_webhook_configured => meeting_webhook_configured,
            meeting_webhook_url => meeting_webhook_url,
            meeting_webhook_auth_mode => meeting_webhook_auth_mode,
            meeting_webhook_has_secret => meeting_webhook_has_secret,
            meeting_webhook_display_name => meeting_webhook_display_name,
            has_logo => state.data_dir.join("logo.png").exists(),
            company_link => get_company_link(&state.pool).await.unwrap_or_default(),
            current_theme => get_theme_name(&state.pool).await,
            custom_colors => {
                let (a, ah, bg, s, t) = get_custom_colors(&state.pool).await;
                context! { accent => a, accent_hover => ah, bg => bg, surface => s, text => t }
            },
            sidebar => sidebar,
            impersonating => false,
            impersonating_name => "",
            error_message => error_message,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn admin_toggle_role(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    // Get current role
    let current_role: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    if let Some((role,)) = current_role {
        let new_role = if role == "admin" { "user" } else { "admin" };
        let _ = sqlx::query("UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(new_role)
            .bind(&user_id)
            .execute(&state.pool)
            .await;
        tracing::info!(target_user = %user_id, new_role = %new_role, admin = %_admin.0.email, "admin: role changed");
    }

    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_toggle_enabled(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    // Get current enabled status
    let current: Option<(bool,)> = sqlx::query_as("SELECT enabled FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    if let Some((enabled,)) = current {
        let new_enabled = !enabled;
        let _ =
            sqlx::query("UPDATE users SET enabled = ?, updated_at = datetime('now') WHERE id = ?")
                .bind(new_enabled)
                .bind(&user_id)
                .execute(&state.pool)
                .await;
        tracing::info!(target_user = %user_id, enabled = %new_enabled, admin = %_admin.0.email, "admin: user toggled");
    }

    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let admin_user = &admin.0;
    let avatars_dir = state.data_dir.join("avatars");
    match crate::auth::delete_user(
        &state.pool,
        &user_id,
        Some(&admin_user.id),
        Some(&avatars_dir),
    )
    .await
    {
        Ok(()) => {
            tracing::info!(target_user = %user_id, admin = %admin_user.email, "admin: user deleted");
            Redirect::to("/dashboard/admin").into_response()
        }
        Err(e) => {
            tracing::warn!(target_user = %user_id, admin = %admin_user.email, error = %e, "admin: user delete refused");
            let encoded = urlencoding::encode(&e.to_string()).into_owned();
            Redirect::to(&format!("/dashboard/admin?error={}", encoded)).into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminAuthForm {
    _csrf: Option<String>,
    registration_enabled: Option<String>,
    allowed_email_domains: Option<String>,
}

async fn admin_update_auth(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminAuthForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let registration_enabled = form.registration_enabled.is_some();
    let allowed_domains = form.allowed_email_domains.filter(|d| !d.trim().is_empty());

    let _ = sqlx::query(
        "UPDATE auth_config SET registration_enabled = ?, allowed_email_domains = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(registration_enabled)
    .bind(&allowed_domains)
    .execute(&state.pool)
    .await;

    tracing::info!(admin = %_admin.0.email, "admin: auth config updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminThemeForm {
    _csrf: Option<String>,
    theme: Option<String>,
    custom_accent: Option<String>,
    custom_accent_hover: Option<String>,
    custom_bg: Option<String>,
    custom_surface: Option<String>,
    custom_text: Option<String>,
}

async fn admin_update_accent(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminThemeForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let theme = form
        .theme
        .filter(|t| {
            matches!(
                t.as_str(),
                "default"
                    | "nord"
                    | "dracula"
                    | "gruvbox"
                    | "solarized"
                    | "tokyo-night"
                    | "vates"
                    | "custom"
            )
        })
        .unwrap_or_else(|| "default".to_string());

    if theme == "custom" {
        let accent = form.custom_accent.as_deref().unwrap_or("#2563eb");
        let accent_hover = form.custom_accent_hover.as_deref().unwrap_or("#1d4ed8");
        let bg = form.custom_bg.as_deref().unwrap_or("#f4f4f5");
        let surface = form.custom_surface.as_deref().unwrap_or("#ffffff");
        let text = form.custom_text.as_deref().unwrap_or("#18181b");

        let _ = sqlx::query(
            "UPDATE auth_config SET theme = 'custom', custom_accent = ?, custom_accent_hover = ?, custom_bg = ?, custom_surface = ?, custom_text = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(accent)
        .bind(accent_hover)
        .bind(bg)
        .bind(surface)
        .bind(text)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET theme = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&theme)
        .execute(&state.pool)
        .await;
    }

    // Rebuild and cache the CSS
    let new_css = build_theme_css(&state.pool).await;
    *state.theme_css.write().await = new_css;

    tracing::info!(admin = %_admin.0.email, theme = %theme, "admin: theme updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminOidcForm {
    _csrf: Option<String>,
    oidc_enabled: Option<String>,
    oidc_issuer_url: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_auto_register: Option<String>,
}

async fn admin_update_oidc(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminOidcForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let oidc_enabled = form.oidc_enabled.is_some();
    let issuer_url = form.oidc_issuer_url.filter(|s| !s.trim().is_empty());
    let client_id = form.oidc_client_id.filter(|s| !s.trim().is_empty());
    let auto_register = form.oidc_auto_register.is_some();

    // If client_secret is provided (non-empty), update it; otherwise keep current value
    let secret_provided = form
        .oidc_client_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let client_secret = form.oidc_client_secret.unwrap_or_default();
        // Encrypt the secret at rest. We carry the auth_config row's
        // singleton SQLite primary key, so on the read side it goes
        // through crypto::decrypt_value.
        let encrypted_secret = match crate::crypto::encrypt_value(&state.secret_key, &client_secret)
        {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt oidc client_secret", &e),
        };
        let _ = sqlx::query(
            "UPDATE auth_config SET oidc_enabled = ?, oidc_issuer_url = ?, oidc_client_id = ?, oidc_client_secret = ?, oidc_auto_register = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(oidc_enabled)
        .bind(&issuer_url)
        .bind(&client_id)
        .bind(&encrypted_secret)
        .bind(auto_register)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET oidc_enabled = ?, oidc_issuer_url = ?, oidc_client_id = ?, oidc_auto_register = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(oidc_enabled)
        .bind(&issuer_url)
        .bind(&client_id)
        .bind(auto_register)
        .execute(&state.pool)
        .await;
    }

    tracing::info!(admin = %_admin.0.email, "admin: OIDC config updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminGoogleOAuth2Form {
    _csrf: Option<String>,
    google_oauth2_client_id: Option<String>,
    google_oauth2_client_secret: Option<String>,
}

async fn admin_update_google_oauth2(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminGoogleOAuth2Form>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let client_id = form
        .google_oauth2_client_id
        .filter(|s| !s.trim().is_empty());

    let secret_provided = form
        .google_oauth2_client_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let client_secret = form.google_oauth2_client_secret.unwrap_or_default();
        let encrypted_secret = match crate::crypto::encrypt_value(&state.secret_key, &client_secret)
        {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt google_oauth2 client_secret", &e),
        };
        let _ = sqlx::query(
            "UPDATE auth_config SET google_oauth2_client_id = ?, google_oauth2_client_secret = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&client_id)
        .bind(&encrypted_secret)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET google_oauth2_client_id = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&client_id)
        .execute(&state.pool)
        .await;
    }

    tracing::info!(admin = %_admin.0.email, "admin: Google OAuth2 config updated");
    Redirect::to("/dashboard/admin").into_response()
}

// --- Google Calendar OAuth2 connect flow ---

async fn google_connect(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    // Load Google OAuth2 client credentials
    let creds: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT google_oauth2_client_id, google_oauth2_client_secret FROM auth_config LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let client_id = match creds.and_then(|(id, _)| id).filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => {
            return Html("Google Calendar integration is not configured. Ask your administrator to set up Google OAuth2 credentials in the admin panel.".to_string()).into_response();
        }
    };

    let base_url = std::env::var("CALRS_BASE_URL").unwrap_or_default();
    if base_url.is_empty() {
        return Html(
            "CALRS_BASE_URL environment variable must be set for OAuth2 flows.".to_string(),
        )
        .into_response();
    }

    let redirect_uri = format!(
        "{}/dashboard/sources/google/callback",
        base_url.trim_end_matches('/')
    );
    let csrf_state = uuid::Uuid::new_v4().to_string();

    let auth_url =
        crate::oauth2_caldav::build_google_auth_url(&client_id, &redirect_uri, &csrf_state);

    // Store state in cookies via Set-Cookie headers (CookieJar's String→Cookie
    // conversion treats the whole formatted string as the cookie name and drops
    // attributes, so set the headers directly).
    let cookie_opts = "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600";
    let state_cookie = format!("__Host-calrs_google_state={}{}", csrf_state, cookie_opts);
    let user_cookie = format!(
        "__Host-calrs_google_user={}{}",
        auth_user.user.id, cookie_opts
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        axum::http::header::SET_COOKIE,
        state_cookie.parse().unwrap(),
    );
    headers.append(axum::http::header::SET_COOKIE, user_cookie.parse().unwrap());

    (headers, Redirect::to(&auth_url)).into_response()
}

#[derive(Deserialize)]
struct GoogleCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn google_callback(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    jar: axum_extra::extract::CookieJar,
    Query(query): Query<GoogleCallbackQuery>,
) -> impl IntoResponse {
    // Check for errors from Google
    if let Some(error) = &query.error {
        return Html(format!("Google authorization failed: {}", error)).into_response();
    }

    // Verify CSRF state
    let stored_state = jar
        .get("__Host-calrs_google_state")
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    let query_state = query.state.unwrap_or_default();
    if stored_state.is_empty() || stored_state != query_state {
        return Html("Invalid state parameter. Please try again.".to_string()).into_response();
    }

    // Cross-tab defense-in-depth: the user cookie set at /connect must match
    // the current session. Guards against a tab swap where the OAuth flow was
    // started as user A but the callback fires while user B is logged in.
    let stored_user = jar
        .get("__Host-calrs_google_user")
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if stored_user.is_empty() || stored_user != auth_user.user.id {
        tracing::warn!(
            session_user = %auth_user.user.id,
            cookie_user = %stored_user,
            "Google OAuth2 callback: user cookie missing or does not match session"
        );
        return Html(
            "Session changed during Google authorization. Please start the connect flow again."
                .to_string(),
        )
        .into_response();
    }

    let code = match query.code {
        Some(c) => c,
        None => return Html("No authorization code received.".to_string()).into_response(),
    };

    // Load Google OAuth2 credentials
    let creds: Option<(String, String)> = sqlx::query_as(
        "SELECT google_oauth2_client_id, google_oauth2_client_secret FROM auth_config LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (client_id, client_secret_enc) = match creds {
        Some(c) => c,
        None => return Html("Google OAuth2 not configured.".to_string()).into_response(),
    };

    // The stored Google OAuth2 client secret is encrypted at rest; the
    // startup migration ensures any pre-existing plaintext is upgraded
    // before we reach this path.
    let client_secret = match crate::crypto::decrypt_value(&state.secret_key, &client_secret_enc) {
        Ok(s) => s,
        Err(e) => return internal_error_response("decrypt google_oauth2 client_secret", &e),
    };

    let base_url = std::env::var("CALRS_BASE_URL").unwrap_or_default();
    let redirect_uri = format!(
        "{}/dashboard/sources/google/callback",
        base_url.trim_end_matches('/')
    );

    // Exchange code for tokens
    let (access_token, refresh_token, expires_in) =
        match crate::oauth2_caldav::exchange_google_code(
            &client_id,
            &client_secret,
            &code,
            &redirect_uri,
        )
        .await
        {
            Ok(t) => t,
            Err(e) => return Html(format!("Token exchange failed: {}", e)).into_response(),
        };

    // Identify the Google account that authorized us; its email is what goes in the CalDAV URL.
    // The local calrs user's email is unrelated and may not match the Google account.
    let google_email = match crate::oauth2_caldav::fetch_google_email(&access_token).await {
        Ok(e) => e,
        Err(e) => {
            return Html(format!("Failed to fetch Google account email: {}", e)).into_response();
        }
    };
    let caldav_url = crate::oauth2_caldav::google_caldav_url_for_email(&google_email);

    // Test the CalDAV connection (PROPFIND requires the per-user URL)
    let client = crate::caldav::CaldavClient::with_bearer(&caldav_url, &access_token);
    if let Err(e) = client.check_connection().await {
        tracing::warn!(error = %e, "Google CalDAV connection test failed (non-fatal)");
    }

    // Get user's account
    let account: Option<(String,)> =
        sqlx::query_as("SELECT a.id FROM accounts a WHERE a.user_id = ? LIMIT 1")
            .bind(&auth_user.user.id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let account_id = match account {
        Some((id,)) => id,
        None => return Html("No scheduling account found.".to_string()).into_response(),
    };

    // Encrypt tokens
    let access_token_enc = match crate::crypto::encrypt_password(&state.secret_key, &access_token) {
        Ok(enc) => enc,
        Err(_) => return Html("Encryption error.".to_string()).into_response(),
    };
    let refresh_token_enc = match crate::crypto::encrypt_password(&state.secret_key, &refresh_token)
    {
        Ok(enc) => enc,
        Err(_) => return Html("Encryption error.".to_string()).into_response(),
    };
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in);

    // Create the CalDAV source
    let source_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO caldav_sources (id, account_id, name, url, username, auth_type, oauth2_provider, access_token_enc, refresh_token_enc, token_expires_at)
         VALUES (?, ?, 'Google Calendar', ?, ?, 'oauth2', 'google', ?, ?, ?)",
    )
    .bind(&source_id)
    .bind(&account_id)
    .bind(&caldav_url)
    .bind(&google_email)
    .bind(&access_token_enc)
    .bind(&refresh_token_enc)
    .bind(expires_at.to_rfc3339())
    .execute(&state.pool)
    .await;

    tracing::info!(user = %auth_user.user.email, google_email = %google_email, "Google Calendar source added via OAuth2");

    // Auto-sync
    let (_, calendar_count) = run_sync_for_source(
        &state.pool,
        &state.secret_key,
        &source_id,
        &caldav_url,
        &google_email,
        None,
        "oauth2",
        Some(&access_token_enc),
        Some(&expires_at.to_rfc3339()),
        crate::providers::factory::kinds::CALDAV,
    )
    .await;

    // Clear transient cookies. The browser only honors removal of
    // __Host-prefixed cookies when the Set-Cookie also has Secure and Path=/,
    // so emit explicit expiring headers (matches admin_stop_impersonate).
    let clear_opts = "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        axum::http::header::SET_COOKIE,
        format!("__Host-calrs_google_state={}", clear_opts)
            .parse()
            .unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        format!("__Host-calrs_google_user={}", clear_opts)
            .parse()
            .unwrap(),
    );

    let redirect = if calendar_count > 0 {
        Redirect::to(&format!("/dashboard/sources/{}/setup-write", source_id))
    } else {
        Redirect::to("/dashboard/sources")
    };
    (headers, redirect).into_response()
}

// --- Captcha settings ---

#[derive(Deserialize)]
struct AdminCaptchaForm {
    _csrf: Option<String>,
    captcha_instance_url: Option<String>,
    captcha_site_key: Option<String>,
    captcha_secret: Option<String>,
    captcha_widget_url: Option<String>,
}

async fn admin_update_captcha(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminCaptchaForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let instance_url = form.captcha_instance_url.filter(|s| !s.trim().is_empty());
    let site_key = form.captcha_site_key.filter(|s| !s.trim().is_empty());
    let widget_url = form.captcha_widget_url.filter(|s| !s.trim().is_empty());

    let secret_provided = form
        .captcha_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let secret = form.captcha_secret.unwrap_or_default();
        let encrypted = match crate::crypto::encrypt_value(&state.secret_key, &secret) {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt captcha secret", &e),
        };
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET captcha_instance_url = ?, captcha_site_key = ?, captcha_secret = ?, captcha_widget_url = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&instance_url)
        .bind(&site_key)
        .bind(&encrypted)
        .bind(&widget_url)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save captcha config");
        }
    } else {
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET captcha_instance_url = ?, captcha_site_key = ?, captcha_widget_url = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&instance_url)
        .bind(&site_key)
        .bind(&widget_url)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save captcha config");
        }
    }

    let new_config = captcha::load_captcha_config(&state.pool, &state.secret_key).await;
    let new_csp = build_csp(&new_config);
    *state.captcha_config.write().await = new_config;
    *state.csp.write().await = new_csp;

    tracing::info!(admin = %_admin.0.email, "admin: captcha config updated");

    Redirect::to("/dashboard/admin").into_response()
}

// --- Auto-generated meeting link settings ---

#[derive(Deserialize)]
struct AdminJitsiForm {
    _csrf: Option<String>,
    jitsi_base_url: Option<String>,
    jitsi_pattern: Option<String>,
    jitsi_display_name: Option<String>,
}

async fn admin_update_jitsi(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminJitsiForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let base_url = form.jitsi_base_url.filter(|s| !s.trim().is_empty());
    let pattern = form.jitsi_pattern.filter(|s| !s.trim().is_empty());
    let display_name = form.jitsi_display_name.filter(|s| !s.trim().is_empty());

    if let Err(e) = sqlx::query(
        "UPDATE auth_config SET jitsi_base_url = ?, jitsi_pattern = ?, jitsi_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(&base_url)
    .bind(&pattern)
    .bind(&display_name)
    .execute(&state.pool)
    .await
    {
        tracing::error!(error = %e, "failed to save jitsi config");
    }

    *state.meeting_config.write().await =
        meeting::load_config(&state.pool, &state.secret_key).await;

    tracing::info!(admin = %_admin.0.email, "admin: jitsi config updated");
    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminMeetingWebhookForm {
    _csrf: Option<String>,
    meeting_webhook_url: Option<String>,
    meeting_webhook_auth_mode: Option<String>,
    meeting_webhook_secret: Option<String>,
    meeting_webhook_display_name: Option<String>,
}

async fn admin_update_meeting_webhook(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminMeetingWebhookForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let url = form.meeting_webhook_url.filter(|s| !s.trim().is_empty());
    let auth_mode = match form.meeting_webhook_auth_mode.as_deref() {
        Some(meeting::WEBHOOK_AUTH_HMAC) => Some(meeting::WEBHOOK_AUTH_HMAC.to_string()),
        Some(meeting::WEBHOOK_AUTH_NONE) => Some(meeting::WEBHOOK_AUTH_NONE.to_string()),
        _ => None,
    };
    let display_name = form
        .meeting_webhook_display_name
        .filter(|s| !s.trim().is_empty());

    // Empty secret field on submit means "keep the current value" (same
    // pattern as OIDC and captcha). Wiping the secret requires switching
    // auth_mode away from "hmac".
    let secret_provided = form
        .meeting_webhook_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let secret = form.meeting_webhook_secret.unwrap_or_default();
        let encrypted = match crate::crypto::encrypt_value(&state.secret_key, &secret) {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt webhook secret", &e),
        };
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET meeting_webhook_url = ?, meeting_webhook_auth_mode = ?, meeting_webhook_secret = ?, meeting_webhook_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&url)
        .bind(&auth_mode)
        .bind(&encrypted)
        .bind(&display_name)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save meeting webhook config");
        }
    } else if let Err(e) = sqlx::query(
        "UPDATE auth_config SET meeting_webhook_url = ?, meeting_webhook_auth_mode = ?, meeting_webhook_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(&url)
    .bind(&auth_mode)
    .bind(&display_name)
    .execute(&state.pool)
    .await
    {
        tracing::error!(error = %e, "failed to save meeting webhook config");
    }

    *state.meeting_config.write().await =
        meeting::load_config(&state.pool, &state.secret_key).await;

    tracing::info!(admin = %_admin.0.email, "admin: meeting webhook config updated");
    Redirect::to("/dashboard/admin").into_response()
}

// --- Logo management ---

async fn serve_logo(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let logo_path = state.data_dir.join("logo.png");
    match tokio::fs::read(&logo_path).await {
        Ok(bytes) => {
            let content_type = if logo_path.exists() {
                // Detect from magic bytes
                if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
                    "image/png"
                } else if bytes.starts_with(&[0xFF, 0xD8]) {
                    "image/jpeg"
                } else if bytes.starts_with(b"<svg") || bytes.starts_with(b"<?xml") {
                    "image/svg+xml"
                } else {
                    "image/png"
                }
            } else {
                "image/png"
            };
            axum::response::Response::builder()
                .status(200)
                .header("Content-Type", content_type)
                .header("Cache-Control", "public, max-age=3600")
                .body(axum::body::Body::from(bytes))
                .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
                .into_response()
        }
        Err(_) => (axum::http::StatusCode::NOT_FOUND, "").into_response(),
    }
}

async fn serve_accent_css(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let css = state.theme_css.read().await.clone();
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "no-cache")
        .body(axum::body::Body::from(css))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

async fn serve_brand_logo() -> impl IntoResponse {
    static BRAND_LOGO: &[u8] = include_bytes!("../../assets/calrs.png");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "image/png")
        .header("Cache-Control", "public, max-age=86400")
        .body(axum::body::Body::from(BRAND_LOGO))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

/// Serves the embed runtime that consumers paste into their own sites. It's
/// loaded cross-origin, so we set permissive CORS — there's no auth state to
/// leak. The contents are checked into `assets/embed.js` and baked into the
/// binary via `include_str!`.
async fn serve_embed_js() -> impl IntoResponse {
    static EMBED_JS: &str = include_str!("../../assets/embed.js");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/javascript; charset=utf-8")
        .header("Cache-Control", "public, max-age=3600")
        .header("Access-Control-Allow-Origin", "*")
        .body(axum::body::Body::from(EMBED_JS))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

async fn serve_font_inter_latin() -> impl IntoResponse {
    static FONT: &[u8] = include_bytes!("../../assets/inter-latin.woff2");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "font/woff2")
        .header("Cache-Control", "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(FONT))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

async fn serve_font_inter_latin_ext() -> impl IntoResponse {
    static FONT: &[u8] = include_bytes!("../../assets/inter-latin-ext.woff2");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "font/woff2")
        .header("Cache-Control", "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(FONT))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

async fn admin_upload_logo(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Query(csrf_query): Query<CsrfQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf_query._csrf) {
        return resp;
    }
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("logo") {
            let content_type = field.content_type().unwrap_or("").to_string();
            if !content_type.starts_with("image/") {
                return Redirect::to("/dashboard/admin").into_response();
            }
            if let Ok(bytes) = field.bytes().await {
                if bytes.len() > 2 * 1024 * 1024 {
                    return Redirect::to("/dashboard/admin").into_response();
                }
                // Trust magic bytes, not the multipart Content-Type header.
                if detect_image_ext(&bytes).is_none() {
                    return Redirect::to("/dashboard/admin").into_response();
                }
                let logo_path = state.data_dir.join("logo.png");
                let _ = tokio::fs::write(&logo_path, &bytes).await;
            }
        }
    }
    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_delete_logo(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let logo_path = state.data_dir.join("logo.png");
    let _ = tokio::fs::remove_file(&logo_path).await;
    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_update_company_link(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<CompanyLinkForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let link = form.company_link.trim().to_string();
    // Reject anything that isn't http(s). An admin (or attacker who has
    // taken over an admin account) could otherwise set `javascript:` and
    // turn the company link rendered on every public booking page into
    // stored XSS.
    if !link.is_empty() && !is_safe_company_link(&link) {
        tracing::warn!(
            admin = %_admin.0.email,
            "admin: company_link rejected (only http/https schemes allowed)"
        );
        let msg =
            urlencoding::encode("Company link must start with http:// or https://").into_owned();
        return Redirect::to(&format!("/dashboard/admin?error={}", msg)).into_response();
    }
    let link_value: Option<&str> = if link.is_empty() { None } else { Some(&link) };
    let _ = sqlx::query(
        "UPDATE auth_config SET company_link = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(link_value)
    .execute(&state.pool)
    .await;
    *state.company_link.write().await = if link.is_empty() { None } else { Some(link) };
    Redirect::to("/dashboard/admin").into_response()
}

// --- Impersonation ---

async fn admin_impersonate(
    State(_state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    tracing::warn!(admin = %_admin.0.email, target = %user_id, "admin: impersonation started");
    let cookie = format!(
        "__Host-calrs_impersonate={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        user_id,
        86400 // 24 hours
    );
    ([("Set-Cookie", cookie)], Redirect::to("/dashboard")).into_response()
}

async fn admin_stop_impersonate(
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    tracing::info!("admin: impersonation ended");
    let cookie = "__Host-calrs_impersonate=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    (
        [("Set-Cookie", cookie.to_string())],
        Redirect::to("/dashboard"),
    )
        .into_response()
}

// --- Admin: update member weight ---

#[derive(Deserialize)]
struct WeightForm {
    _csrf: Option<String>,
    weight: i64,
}

async fn admin_update_member_weight(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(String, String)>,
    Form(form): Form<WeightForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let w = form.weight.clamp(1, 100);
    let _ = sqlx::query("UPDATE user_groups SET weight = ? WHERE group_id = ? AND user_id = ?")
        .bind(w)
        .bind(&group_id)
        .bind(&user_id)
        .execute(&state.pool)
        .await;
    tracing::info!(
        group_id,
        user_id,
        weight = w,
        "admin: updated member weight"
    );
    Redirect::to("/dashboard/admin").into_response()
}

