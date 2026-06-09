// --- OIDC ---

const OIDC_STATE_COOKIE: &str = "calrs_oidc_state";
const OIDC_NONCE_COOKIE: &str = "calrs_oidc_nonce";
const OIDC_PKCE_COOKIE: &str = "calrs_oidc_pkce";

use axum::extract::Query;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};

fn build_http_client() -> Result<openidconnect::reqwest::Client> {
    let client = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;
    Ok(client)
}

async fn build_oidc_client_with_redirect(
    auth_config: &AuthConfig,
    secret_key: &[u8; 32],
) -> Result<
    CoreClient<
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
> {
    let issuer_url = IssuerUrl::new(
        auth_config
            .oidc_issuer_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OIDC issuer URL not configured"))?
            .clone(),
    )
    .map_err(|e| anyhow::anyhow!("Invalid issuer URL: {}", e))?;

    let client_id = ClientId::new(
        auth_config
            .oidc_client_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OIDC client ID not configured"))?
            .clone(),
    );

    // The stored OIDC client secret is encrypted at rest. The startup
    // password migration (db::migrate_passwords) handles converting
    // pre-existing plaintext values, so by the time we reach here the
    // value should always carry the enc:v1: prefix. Surface a decryption
    // failure as an error rather than falling back to an unauthenticated
    // request, so the admin sees a clear OIDC failure (and a tracing log
    // entry from the caller) rather than silently broken sign-ins.
    let client_secret = auth_config
        .oidc_client_secret
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| crate::crypto::decrypt_value(secret_key, s))
        .transpose()
        .map_err(|e| anyhow::anyhow!("OIDC client secret decryption failed: {}", e))?
        .map(ClientSecret::new);

    let http_client = build_http_client()?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery failed: {}", e))?;

    let redirect_url = RedirectUrl::new(format!(
        "{}/auth/oidc/callback",
        std::env::var("CALRS_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    ))
    .map_err(|e| anyhow::anyhow!("Invalid redirect URL: {}", e))?;

    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, client_secret)
        .set_redirect_uri(redirect_url);

    Ok(client)
}

async fn oidc_login(State(state): State<Arc<AppState>>) -> Response {
    let auth_config = match get_auth_config(&state.pool).await {
        Ok(c) if c.oidc_enabled => c,
        _ => return Html("OIDC is not enabled.".to_string()).into_response(),
    };

    let client = match build_oidc_client_with_redirect(&auth_config, &state.secret_key).await {
        Ok(c) => c,
        Err(e) => return crate::web::oidc_error_response("oidc client build (login)", &e),
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store state, nonce, and PKCE verifier in short-lived cookies
    let cookie_opts = "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600";
    let state_cookie = format!(
        "{}={}{}",
        OIDC_STATE_COOKIE,
        csrf_token.secret(),
        cookie_opts
    );
    let nonce_cookie = format!("{}={}{}", OIDC_NONCE_COOKIE, nonce.secret(), cookie_opts);
    let pkce_cookie = format!(
        "{}={}{}",
        OIDC_PKCE_COOKIE,
        pkce_verifier.secret(),
        cookie_opts
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        axum::http::header::SET_COOKIE,
        state_cookie.parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        nonce_cookie.parse().unwrap(),
    );
    headers.append(axum::http::header::SET_COOKIE, pkce_cookie.parse().unwrap());

    (headers, Redirect::to(auth_url.as_str())).into_response()
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    let auth_config = match get_auth_config(&state.pool).await {
        Ok(c) if c.oidc_enabled => c,
        _ => return Html("OIDC is not enabled.".to_string()).into_response(),
    };

    // Verify CSRF state
    let stored_state = match jar.get(OIDC_STATE_COOKIE) {
        Some(c) => c.value().to_string(),
        None => return Html("Missing OIDC state. Please try again.".to_string()).into_response(),
    };
    if query.state != stored_state {
        tracing::warn!("OIDC callback failed: state mismatch");
        return Html("Invalid OIDC state. Possible CSRF attack.".to_string()).into_response();
    }

    let stored_nonce = match jar.get(OIDC_NONCE_COOKIE) {
        Some(c) => c.value().to_string(),
        None => return Html("Missing OIDC nonce. Please try again.".to_string()).into_response(),
    };

    let pkce_verifier_secret = match jar.get(OIDC_PKCE_COOKIE) {
        Some(c) => c.value().to_string(),
        None => {
            return Html("Missing PKCE verifier. Please try again.".to_string()).into_response()
        }
    };

    let client = match build_oidc_client_with_redirect(&auth_config, &state.secret_key).await {
        Ok(c) => c,
        Err(e) => return crate::web::oidc_error_response("oidc client build (callback)", &e),
    };

    let http_client = match build_http_client() {
        Ok(c) => c,
        Err(e) => return crate::web::oidc_error_response("oidc http client", &e),
    };

    // Exchange code for tokens
    let token_request = match client.exchange_code(AuthorizationCode::new(query.code)) {
        Ok(r) => r,
        Err(e) => return crate::web::oidc_error_response("oidc exchange_code", &e),
    };
    let token_response = match token_request
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier_secret))
        .request_async(&http_client)
        .await
    {
        Ok(t) => t,
        Err(e) => return crate::web::oidc_error_response("oidc token exchange", &e),
    };

    // Verify and extract ID token claims
    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => return Html("No ID token in response.".to_string()).into_response(),
    };

    let verifier = client.id_token_verifier();
    let claims = match id_token.claims(&verifier, &Nonce::new(stored_nonce)) {
        Ok(c) => c,
        Err(e) => return crate::web::oidc_error_response("oidc id_token verify", &e),
    };

    let subject = claims.subject().to_string();
    let email = claims
        .email()
        .map(|e: &openidconnect::EndUserEmail| e.to_string())
        .unwrap_or_default();
    // `email_verified` is optional in the spec. If the IdP doesn't assert
    // verification, we treat it as unverified (conservative).
    let email_verified = claims.email_verified().unwrap_or(false);
    let name = claims
        .name()
        .and_then(
            |n: &openidconnect::LocalizedClaim<openidconnect::EndUserName>| {
                n.get(None)
                    .map(|v: &openidconnect::EndUserName| v.to_string())
            },
        )
        .unwrap_or_else(|| email.split('@').next().unwrap_or("User").to_string());

    if email.is_empty() {
        tracing::warn!("OIDC callback failed: no email in token");
        return Html("OIDC provider did not return an email address.".to_string()).into_response();
    }

    // Check email domain restriction
    if !is_email_allowed(&email, &auth_config.allowed_email_domains) {
        tracing::warn!(email = %email, "OIDC callback failed: email domain not allowed");
        return Html("Your email domain is not allowed.".to_string()).into_response();
    }

    // Extract groups and title from ID token JWT payload
    let claims = extract_claims_from_id_token(id_token.to_string().as_str());

    // Find or create user
    let user_id = match find_or_create_oidc_user(
        &state.pool,
        &subject,
        &email,
        email_verified,
        &name,
        &auth_config,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(email = %email, error = %e, "OIDC callback failed: account error");
            return crate::web::oidc_error_response("oidc account link/create", &e);
        }
    };

    // Sync title from OIDC token (best-effort)
    if let Some(ref title) = claims.title {
        let _ =
            sqlx::query("UPDATE users SET title = ?, updated_at = datetime('now') WHERE id = ?")
                .bind(title)
                .bind(&user_id)
                .execute(&state.pool)
                .await;
    }

    // Sync groups from OIDC token (best-effort, don't fail login)
    if let Some(groups) = &claims.groups {
        if let Err(e) = sync_user_groups(&state.pool, &user_id, groups).await {
            tracing::warn!(error = %e, "failed to sync OIDC groups");
        }
    }

    // Create session
    let session = match create_session(&state.pool, &user_id).await {
        Ok(s) => s,
        Err(_) => return Html("Failed to create session.".to_string()).into_response(),
    };

    tracing::info!(email = %email, provider = "oidc", "user login via OIDC");

    let session_cookie = format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        SESSION_COOKIE,
        session.id,
        SESSION_DURATION_DAYS * 86400
    );

    // Clear OIDC transient cookies
    let clear = "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    let clear_state = format!("{OIDC_STATE_COOKIE}={clear}");
    let clear_nonce = format!("{OIDC_NONCE_COOKIE}={clear}");
    let clear_pkce = format!("{OIDC_PKCE_COOKIE}={clear}");

    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        axum::http::header::SET_COOKIE,
        session_cookie.parse().unwrap(),
    );
    headers.append(axum::http::header::SET_COOKIE, clear_state.parse().unwrap());
    headers.append(axum::http::header::SET_COOKIE, clear_nonce.parse().unwrap());
    headers.append(axum::http::header::SET_COOKIE, clear_pkce.parse().unwrap());

    (headers, Redirect::to("/dashboard")).into_response()
}

/// Find an existing user by OIDC subject or email, or create a new one.
///
/// `email_verified` is the `email_verified` claim from the ID token. It gates
/// the two branches that trust the email at face value:
///
/// - **Email-based linking** (step 2) — attaches a new `oidc_subject` to an
///   existing local user matching the email. If `email_verified` is false,
///   an attacker who can register at the IdP with any email they want would
///   silently hijack the matching local account on first OIDC login.
/// - **Auto-register** (step 3) — creates a brand-new user keyed on the
///   email. Same concern: unverified emails could be used to squat on
///   addresses the attacker doesn't actually own.
///
/// Step 1 (match by `oidc_subject`) is always allowed — the subject claim is
/// the IdP-issued stable identifier and doesn't rely on the email being
/// accurate, so a returning user can always sign in once their account
/// exists.
async fn find_or_create_oidc_user(
    pool: &SqlitePool,
    subject: &str,
    email: &str,
    email_verified: bool,
    name: &str,
    auth_config: &AuthConfig,
) -> Result<String> {
    // 1. Try to find by oidc_subject — always allowed, subject is the stable
    //    IdP-issued identity. Email is only a display attribute at this point.
    if let Some((id,)) = sqlx::query_as::<_, (String,)>(
        "SELECT id FROM users WHERE oidc_subject = ? AND auth_provider = 'oidc' AND enabled = 1",
    )
    .bind(subject)
    .fetch_optional(pool)
    .await?
    {
        // Update email in case it changed on the IdP; only update name if currently empty
        sqlx::query(
            "UPDATE users SET name = CASE WHEN name IS NULL OR name = '' THEN ? ELSE name END, email = ?, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(name)
        .bind(email)
        .bind(&id)
        .execute(pool)
        .await?;
        return Ok(id);
    }

    // 2. Link to existing local user by email — only if the IdP asserts the
    //    email is verified. Otherwise an attacker could register at the IdP
    //    with the target's email and silently take over their local account.
    if let Some((id, _existing_provider)) = sqlx::query_as::<_, (String, String)>(
        "SELECT id, auth_provider FROM users WHERE email = ? AND enabled = 1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?
    {
        if !email_verified {
            tracing::warn!(
                email = %email, subject = %subject,
                "OIDC login refused: email matches existing local user but IdP did not assert email_verified=true"
            );
            anyhow::bail!(
                "An account with this email already exists. The identity provider has not verified that you own this address, so we cannot link them automatically. Contact an administrator."
            );
        }
        sqlx::query(
            "UPDATE users SET oidc_subject = ?, auth_provider = 'oidc', updated_at = datetime('now') WHERE id = ?",
        )
        .bind(subject)
        .bind(&id)
        .execute(pool)
        .await?;
        return Ok(id);
    }

    // 3. Create new user if auto-register is enabled — also gated on
    //    email_verified. Otherwise an attacker could create accounts keyed on
    //    addresses they don't own (squatting) or pollute the directory.
    if !auth_config.oidc_auto_register {
        anyhow::bail!("No account found for this email. Contact an administrator.");
    }
    if !email_verified {
        tracing::warn!(
            email = %email, subject = %subject,
            "OIDC auto-register refused: IdP did not assert email_verified=true"
        );
        anyhow::bail!(
            "The identity provider has not verified your email address. Ask your administrator to verify it at the provider and try again."
        );
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    let username = generate_username(pool, email).await?;

    // Compute the role inside the INSERT so "first user gets admin" is
    // atomic with the row creation; see create_local_user for the rationale.
    sqlx::query(
        "INSERT INTO users (id, email, name, timezone, role, auth_provider, oidc_subject, username)
         VALUES (?, ?, ?, 'UTC',
                 CASE WHEN NOT EXISTS (SELECT 1 FROM users) THEN 'admin' ELSE 'user' END,
                 'oidc', ?, ?)",
    )
    .bind(&user_id)
    .bind(email)
    .bind(name)
    .bind(subject)
    .bind(&username)
    .execute(pool)
    .await?;

    // Link to existing account or create a new one
    let existing_account: Option<(String,)> =
        sqlx::query_as("SELECT id FROM accounts WHERE email = ?")
            .bind(email)
            .fetch_optional(pool)
            .await?;

    if let Some((account_id,)) = existing_account {
        sqlx::query("UPDATE accounts SET user_id = ?, name = ? WHERE id = ?")
            .bind(&user_id)
            .bind(name)
            .bind(&account_id)
            .execute(pool)
            .await?;
    } else {
        let account_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, ?, ?, 'UTC', ?)",
        )
        .bind(&account_id)
        .bind(name)
        .bind(email)
        .bind(&user_id)
        .execute(pool)
        .await?;
    }

    Ok(user_id)
}

