use super::*;

// --- extract_origin tests ---

#[test]
fn extract_origin_returns_scheme_and_host() {
    assert_eq!(
        extract_origin("https://cdn.jsdelivr.net/npm/cap-widget"),
        "https://cdn.jsdelivr.net"
    );
}

#[test]
fn extract_origin_handles_root_url() {
    assert_eq!(
        extract_origin("https://cap.example.com"),
        "https://cap.example.com"
    );
}

#[test]
fn extract_origin_handles_trailing_slash() {
    assert_eq!(
        extract_origin("https://cap.example.com/"),
        "https://cap.example.com"
    );
}

#[test]
fn extract_origin_rejects_invalid_url() {
    assert_eq!(extract_origin("not-a-url"), "");
    assert_eq!(extract_origin(""), "");
}

// --- api_endpoint tests ---

#[test]
fn api_endpoint_strips_trailing_slash_on_instance() {
    let cfg = CaptchaConfig {
        instance_url: "https://cap.example.com/".to_string(),
        site_key: "mykey".to_string(),
        secret: "s".to_string(),
        widget_url: DEFAULT_WIDGET_URL.to_string(),
    };
    assert_eq!(cfg.api_endpoint(), "https://cap.example.com/mykey/");
}

#[test]
fn api_endpoint_no_trailing_slash_on_instance() {
    let cfg = CaptchaConfig {
        instance_url: "https://cap.example.com".to_string(),
        site_key: "mykey".to_string(),
        secret: "s".to_string(),
        widget_url: DEFAULT_WIDGET_URL.to_string(),
    };
    assert_eq!(cfg.api_endpoint(), "https://cap.example.com/mykey/");
}

// --- verify passthrough tests (no network) ---

#[tokio::test]
async fn verify_passes_through_when_no_config() {
    assert!(verify(&None, None).await.is_ok());
    assert!(verify(&None, Some("any-token")).await.is_ok());
}

#[tokio::test]
async fn verify_fails_when_config_set_and_token_missing() {
    let cfg = Some(CaptchaConfig {
        instance_url: "https://cap.example.com".to_string(),
        site_key: "key".to_string(),
        secret: "secret".to_string(),
        widget_url: DEFAULT_WIDGET_URL.to_string(),
    });
    assert!(verify(&cfg, None).await.is_err());
}

#[tokio::test]
async fn verify_fails_when_config_set_and_token_empty() {
    let cfg = Some(CaptchaConfig {
        instance_url: "https://cap.example.com".to_string(),
        site_key: "key".to_string(),
        secret: "secret".to_string(),
        widget_url: DEFAULT_WIDGET_URL.to_string(),
    });
    assert!(verify(&cfg, Some("")).await.is_err());
    assert!(verify(&cfg, Some("   ")).await.is_err());
}
