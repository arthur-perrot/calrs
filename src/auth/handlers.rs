// --- Axum auth handlers ---

use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

pub fn auth_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/login", get(login_page).post(login_handler))
        .route("/auth/register", get(register_page).post(register_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/auth/oidc/login", get(oidc_login))
        .route("/auth/oidc/callback", get(oidc_callback))
}

#[derive(Deserialize)]
struct CsrfForm {
    _csrf: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub _csrf: Option<String>,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterForm {
    pub _csrf: Option<String>,
    pub name: String,
    pub email: String,
    pub password: String,
}

async fn login_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    // If already authenticated, redirect to dashboard
    if let Some(token) = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()) {
        if validate_session(&state.pool, &token).await.is_some() {
            return Redirect::to("/dashboard").into_response();
        }
    }

    let auth_config = get_auth_config(&state.pool).await.ok();
    let oidc_enabled = auth_config
        .as_ref()
        .map(|c| c.oidc_enabled)
        .unwrap_or(false);
    let registration_enabled = auth_config
        .as_ref()
        .map(|c| c.registration_enabled)
        .unwrap_or(true);

    let csrf_token = generate_csrf_token();

    let tmpl = match state.templates.get_template("auth/login.html") {
        Ok(t) => t,
        Err(e) => return crate::web::internal_error_response("template render", &e),
    };
    let body = Html(
        tmpl.render(minijinja::context! { error => "", oidc_enabled => oidc_enabled, registration_enabled => registration_enabled, csrf_token => csrf_token })
            .unwrap_or_default(),
    );
    ([("Set-Cookie", csrf_cookie_value(&csrf_token))], body).into_response()
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let client_ip = crate::web::client_ip_for_rate_limit(&headers);

    if state.login_limiter.check_limited(&client_ip).await {
        tracing::warn!(ip = %client_ip, "rate limited");
        return render_login_error(&state, "Too many login attempts. Please try again later.");
    }

    let user_row = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email = ? AND auth_provider = 'local' AND enabled = 1",
    )
    .bind(&form.email)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    // Always run Argon2 regardless of whether the user exists to prevent
    // user enumeration via response-time differences (timing oracle).
    let hash_to_check = user_row
        .as_ref()
        .and_then(|u| u.password_hash.as_deref())
        .unwrap_or(DUMMY_HASH);
    let password_ok = verify_password(&form.password, hash_to_check);

    let user = match user_row {
        Some(u) if password_ok => u,
        _ => {
            tracing::warn!(email = %form.email, ip = %client_ip, "login failed");
            return render_login_error(&state, "Invalid email or password");
        }
    };

    let session = match create_session(&state.pool, &user.id).await {
        Ok(s) => s,
        Err(_) => return render_login_error(&state, "Internal error"),
    };

    let cookie = format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        SESSION_COOKIE,
        session.id,
        SESSION_DURATION_DAYS * 86400
    );

    tracing::info!(email = %form.email, ip = %client_ip, "user login");

    (jar, [("Set-Cookie", cookie)], Redirect::to("/dashboard")).into_response()
}

async fn register_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    // If already authenticated, redirect to dashboard
    if let Some(token) = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()) {
        if validate_session(&state.pool, &token).await.is_some() {
            return Redirect::to("/dashboard").into_response();
        }
    }

    let auth_config = get_auth_config(&state.pool).await.unwrap_or(AuthConfig {
        id: "singleton".to_string(),
        registration_enabled: false,
        allowed_email_domains: None,
        created_at: String::new(),
        updated_at: String::new(),
        oidc_enabled: false,
        oidc_issuer_url: None,
        oidc_client_id: None,
        oidc_client_secret: None,
        oidc_auto_register: true,
        google_oauth2_client_id: None,
        google_oauth2_client_secret: None,
    });

    if !auth_config.registration_enabled {
        return Html("Registration is disabled.".to_string()).into_response();
    }

    let csrf_token = generate_csrf_token();

    let tmpl = match state.templates.get_template("auth/register.html") {
        Ok(t) => t,
        Err(e) => return crate::web::internal_error_response("template render", &e),
    };
    let body = Html(
        tmpl.render(minijinja::context! {
            error => "",
            allowed_domains => auth_config.allowed_email_domains,
            csrf_token => csrf_token,
        })
        .unwrap_or_default(),
    );
    ([("Set-Cookie", csrf_cookie_value(&csrf_token))], body).into_response()
}

async fn register_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<RegisterForm>,
) -> Response {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let auth_config = match get_auth_config(&state.pool).await {
        Ok(c) => c,
        Err(_) => return Html("Internal error".to_string()).into_response(),
    };

    if !auth_config.registration_enabled {
        return Html("Registration is disabled.".to_string()).into_response();
    }

    // Validate name
    let name = form.name.trim();
    if name.is_empty() || name.len() > 255 {
        return render_register_error(
            &state,
            "Name must be between 1 and 255 characters",
            &auth_config,
        );
    }

    // Validate email format
    let email = form.email.trim();
    if email.is_empty() || email.len() > 255 {
        return render_register_error(
            &state,
            "Email must be between 1 and 255 characters",
            &auth_config,
        );
    }
    if !email.contains('@')
        || email
            .rsplit('@')
            .next()
            .is_none_or(|domain| !domain.contains('.'))
    {
        return render_register_error(&state, "Please enter a valid email address", &auth_config);
    }

    // Validate email domain
    if !is_email_allowed(&form.email, &auth_config.allowed_email_domains) {
        return render_register_error(&state, "Email domain not allowed", &auth_config);
    }

    // Validate password length
    if form.password.len() < 12 {
        return render_register_error(
            &state,
            "Password must be at least 12 characters",
            &auth_config,
        );
    }

    // Check if email already taken
    let existing: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE email = ?")
        .bind(&form.email)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    if existing.is_some() {
        return render_register_error(&state, "Email already registered", &auth_config);
    }

    let password_hash = match hash_password(&form.password) {
        Ok(h) => h,
        Err(_) => return render_register_error(&state, "Internal error", &auth_config),
    };

    let user_id = uuid::Uuid::new_v4().to_string();
    let username = match generate_username(&state.pool, &form.email).await {
        Ok(u) => u,
        Err(_) => return render_register_error(&state, "Internal error", &auth_config),
    };

    if create_local_user(
        &state.pool,
        &user_id,
        &form.email,
        &form.name,
        &password_hash,
        &username,
        false,
    )
    .await
    .is_err()
    {
        return render_register_error(&state, "Failed to create account", &auth_config);
    }

    // Link to existing account or create a new one
    let existing_account: Option<(String,)> =
        sqlx::query_as("SELECT id FROM accounts WHERE email = ?")
            .bind(&form.email)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    if let Some((account_id,)) = existing_account {
        let _ = sqlx::query("UPDATE accounts SET user_id = ?, name = ? WHERE id = ?")
            .bind(&user_id)
            .bind(&form.name)
            .bind(&account_id)
            .execute(&state.pool)
            .await;
    } else {
        let account_id = uuid::Uuid::new_v4().to_string();
        let _ = sqlx::query(
            "INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, ?, ?, 'UTC', ?)",
        )
        .bind(&account_id)
        .bind(&form.name)
        .bind(&form.email)
        .bind(&user_id)
        .execute(&state.pool)
        .await;
    }

    // Auto-login
    let session = match create_session(&state.pool, &user_id).await {
        Ok(s) => s,
        Err(_) => return Redirect::to("/auth/login").into_response(),
    };

    let cookie = format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        SESSION_COOKIE,
        session.id,
        SESSION_DURATION_DAYS * 86400
    );

    tracing::info!(email = %form.email, "user registered");

    (jar, [("Set-Cookie", cookie)], Redirect::to("/dashboard")).into_response()
}

async fn logout_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(csrf): Form<CsrfForm>,
) -> Response {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let _ = delete_session(&state.pool, cookie.value()).await;
    }

    tracing::info!("user logout");

    let clear_cookie = format!(
        "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
        SESSION_COOKIE
    );

    ([("Set-Cookie", clear_cookie)], Redirect::to("/auth/login")).into_response()
}

