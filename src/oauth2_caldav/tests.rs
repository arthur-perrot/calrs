use super::*;

#[test]
fn build_google_auth_url_encodes_components() {
    // A `+` in the client_id is the interesting case: if left as a literal
    // `+`, Google's server would decode it as a space (application/x-www-
    // form-urlencoded rules in the query string) and the OAuth2 lookup
    // would fail. RFC 3986 percent-encoding (%2B) is required.
    let client_id = "1234+abc.apps.googleusercontent.com";
    let redirect_uri = "https://cal.example.com/auth/google/callback";
    let state = "csrf token with spaces & symbols";

    let url = build_google_auth_url(client_id, redirect_uri, state);

    assert!(
        url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"),
        "url: {}",
        url
    );

    assert!(
        url.contains("client_id=1234%2Babc.apps.googleusercontent.com"),
        "client_id `+` not encoded as %2B: {}",
        url
    );
    assert!(
        !url.contains("client_id=1234+abc"),
        "raw + leaked into client_id: {}",
        url
    );

    assert!(
        url.contains("redirect_uri=https%3A%2F%2Fcal.example.com%2Fauth%2Fgoogle%2Fcallback"),
        "redirect_uri not percent-encoded: {}",
        url
    );

    assert!(
        url.contains("scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcalendar%20openid%20email"),
        "scope not encoded with %20 between calendar + openid email: {}",
        url
    );

    assert!(
        url.contains("state=csrf%20token%20with%20spaces%20%26%20symbols"),
        "state spaces/`&` not encoded: {}",
        url
    );

    assert!(url.contains("response_type=code"), "url: {}", url);
    assert!(url.contains("access_type=offline"), "url: {}", url);
    assert!(url.contains("prompt=consent"), "url: {}", url);
}
