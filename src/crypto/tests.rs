use super::*;

#[test]
fn test_roundtrip() {
    let key = [42u8; 32];
    let password = "hunter2";
    let encrypted = encrypt_password(&key, password).unwrap();
    let decrypted = decrypt_password(&key, &encrypted).unwrap();
    assert_eq!(decrypted, password);
}

#[test]
fn test_different_nonces() {
    let key = [42u8; 32];
    let e1 = encrypt_password(&key, "test").unwrap();
    let e2 = encrypt_password(&key, "test").unwrap();
    // Same plaintext should produce different ciphertexts (random nonce)
    assert_ne!(e1, e2);
    // But both should decrypt to the same value
    assert_eq!(decrypt_password(&key, &e1).unwrap(), "test");
    assert_eq!(decrypt_password(&key, &e2).unwrap(), "test");
}

#[test]
fn test_wrong_key() {
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];
    let encrypted = encrypt_password(&key1, "secret").unwrap();
    assert!(decrypt_password(&key2, &encrypted).is_err());
}

#[test]
fn test_legacy_detection() {
    // "mypassword" hex-encoded
    let legacy = hex::encode("mypassword".as_bytes());
    assert!(is_legacy_hex(&legacy));

    // base64 encrypted data should not match
    let key = [42u8; 32];
    let encrypted = encrypt_password(&key, "mypassword").unwrap();
    assert!(!is_legacy_hex(&encrypted));
}

#[test]
fn test_migrate_legacy() {
    let key = [42u8; 32];
    let legacy = hex::encode("mypassword".as_bytes());
    let result = migrate_legacy(&key, &legacy).unwrap();
    assert!(result.is_some());
    let decrypted = decrypt_password(&key, &result.unwrap()).unwrap();
    assert_eq!(decrypted, "mypassword");
}

#[test]
fn test_encrypt_value_roundtrip() {
    let key = [42u8; 32];
    let plaintext = "very-secret-oidc-client-secret";
    let encrypted = encrypt_value(&key, plaintext).unwrap();
    assert!(encrypted.starts_with(ENC_PREFIX));
    assert_eq!(decrypt_value(&key, &encrypted).unwrap(), plaintext);
}

#[test]
fn test_is_encrypted_value() {
    let key = [42u8; 32];
    let encrypted = encrypt_value(&key, "secret").unwrap();
    assert!(is_encrypted_value(&encrypted));

    // Plaintext that happens to be valid base64 must NOT be identified
    // as encrypted (this is exactly the case the prefix exists to
    // disambiguate).
    let base64_looking = "aGVsbG8td29ybGQtdGhpcy1pcy1ub3QtZW5jcnlwdGVk";
    assert!(!is_encrypted_value(base64_looking));

    // Empty / arbitrary plaintext.
    assert!(!is_encrypted_value(""));
    assert!(!is_encrypted_value("plain-text"));
}

#[test]
fn test_decrypt_value_rejects_unprefixed() {
    let key = [42u8; 32];
    // Even a valid encrypt_password output is rejected without the prefix.
    let raw = encrypt_password(&key, "secret").unwrap();
    assert!(decrypt_value(&key, &raw).is_err());
    assert!(decrypt_value(&key, "plaintext").is_err());
}

#[test]
fn test_key_file() {
    let dir = std::env::temp_dir().join(format!("calrs_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    // First call generates
    let key1 = load_or_create_key(&dir).unwrap();
    // Second call reads the same key
    let key2 = load_or_create_key(&dir).unwrap();
    assert_eq!(key1, key2);

    std::fs::remove_dir_all(&dir).unwrap();
}
