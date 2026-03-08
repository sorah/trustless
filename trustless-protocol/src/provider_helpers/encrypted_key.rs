use super::ProviderHelperError;

/// If the key PEM is encrypted, decrypt it using the given passphrase and return DER bytes.
/// Returns `Ok(None)` if the key is not encrypted (caller should use PEM as-is).
///
/// Supports two encrypted PEM formats:
/// - PKCS#8 encrypted (`-----BEGIN ENCRYPTED PRIVATE KEY-----`)
/// - Legacy OpenSSL encrypted (`Proc-Type: 4,ENCRYPTED` / `DEK-Info` headers)
pub fn decrypt_key_if_encrypted(
    key_pem: &[u8],
    passphrase: &str,
) -> Result<Option<Vec<u8>>, ProviderHelperError> {
    let pem_str = std::str::from_utf8(key_pem)
        .map_err(|e| ProviderHelperError::KeyDecryption(format!("key PEM is not UTF-8: {e}")))?;

    if pem_str.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return decrypt_pkcs8_encrypted(pem_str, passphrase);
    }

    if pem_str.contains("Proc-Type: 4,ENCRYPTED") {
        return decrypt_legacy_pem(pem_str, passphrase);
    }

    Ok(None)
}

fn decrypt_pkcs8_encrypted(
    pem_str: &str,
    passphrase: &str,
) -> Result<Option<Vec<u8>>, ProviderHelperError> {
    let (_, der_doc) = pkcs8::der::SecretDocument::from_pem(pem_str).map_err(|e| {
        ProviderHelperError::KeyDecryption(format!("failed to parse encrypted PEM: {e}"))
    })?;

    let encrypted_info =
        pkcs8::EncryptedPrivateKeyInfo::try_from(der_doc.as_bytes()).map_err(|e| {
            ProviderHelperError::KeyDecryption(format!(
                "failed to parse EncryptedPrivateKeyInfo: {e}"
            ))
        })?;

    let decrypted = encrypted_info.decrypt(passphrase).map_err(|e| {
        ProviderHelperError::KeyDecryption(format!("failed to decrypt PKCS#8 key: {e}"))
    })?;

    Ok(Some(decrypted.as_bytes().to_vec()))
}

/// Decrypt legacy OpenSSL PEM-encrypted private keys.
///
/// Format:
/// ```text
/// -----BEGIN RSA PRIVATE KEY-----
/// Proc-Type: 4,ENCRYPTED
/// DEK-Info: AES-256-CBC,<hex IV>
///
/// <base64 encrypted data>
/// -----END RSA PRIVATE KEY-----
/// ```
///
/// Key derivation uses OpenSSL's EVP_BytesToKey with MD5.
fn decrypt_legacy_pem(
    pem_str: &str,
    passphrase: &str,
) -> Result<Option<Vec<u8>>, ProviderHelperError> {
    let (algorithm, iv, encrypted_der) = parse_legacy_pem_headers(pem_str)?;
    let key = evp_bytes_to_key(passphrase.as_bytes(), &iv[..8], cipher_key_len(&algorithm)?);

    let decrypted = match algorithm.as_str() {
        "AES-128-CBC" => decrypt_aes_cbc::<aes::Aes128>(&key, &iv, &encrypted_der),
        "AES-192-CBC" => decrypt_aes_cbc::<aes::Aes192>(&key, &iv, &encrypted_der),
        "AES-256-CBC" => decrypt_aes_cbc::<aes::Aes256>(&key, &iv, &encrypted_der),
        _ => {
            return Err(ProviderHelperError::KeyDecryption(format!(
                "unsupported legacy PEM cipher: {algorithm}"
            )));
        }
    }?;

    Ok(Some(decrypted))
}

fn parse_legacy_pem_headers(
    pem_str: &str,
) -> Result<(String, Vec<u8>, Vec<u8>), ProviderHelperError> {
    let mut algorithm = None;
    let mut iv_hex = None;
    let mut in_headers = false;
    let mut base64_body = String::new();
    let mut past_headers = false;

    for line in pem_str.lines() {
        if line.starts_with("-----BEGIN ") {
            in_headers = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if !in_headers {
            continue;
        }

        if !past_headers {
            if line.starts_with("DEK-Info:") {
                let value = line.trim_start_matches("DEK-Info:").trim();
                let (alg, iv) = value.split_once(',').ok_or_else(|| {
                    ProviderHelperError::KeyDecryption(
                        "invalid DEK-Info header: missing comma".to_owned(),
                    )
                })?;
                algorithm = Some(alg.trim().to_owned());
                iv_hex = Some(iv.trim().to_owned());
                continue;
            }
            if line.starts_with("Proc-Type:") {
                continue;
            }
            if line.is_empty() {
                past_headers = true;
                continue;
            }
        }

        base64_body.push_str(line.trim());
    }

    let algorithm = algorithm.ok_or_else(|| {
        ProviderHelperError::KeyDecryption("missing DEK-Info header in encrypted PEM".to_owned())
    })?;
    let iv_hex = iv_hex.unwrap(); // always set with algorithm

    let iv = hex_decode(&iv_hex)
        .map_err(|e| ProviderHelperError::KeyDecryption(format!("failed to decode IV hex: {e}")))?;

    use base64ct::Encoding as _;
    let encrypted_der = base64ct::Base64::decode_vec(&base64_body).map_err(|e| {
        ProviderHelperError::KeyDecryption(format!(
            "failed to decode base64 body in encrypted PEM: {e}"
        ))
    })?;

    Ok((algorithm, iv, encrypted_der))
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_owned());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at offset {i}: {e}"))
        })
        .collect()
}

fn cipher_key_len(algorithm: &str) -> Result<usize, ProviderHelperError> {
    match algorithm {
        "AES-128-CBC" => Ok(16),
        "AES-192-CBC" => Ok(24),
        "AES-256-CBC" => Ok(32),
        _ => Err(ProviderHelperError::KeyDecryption(format!(
            "unsupported legacy PEM cipher: {algorithm}"
        ))),
    }
}

/// OpenSSL EVP_BytesToKey key derivation (MD5-based).
fn evp_bytes_to_key(passphrase: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    use md5::Digest as _;

    let mut key = Vec::with_capacity(key_len);
    let mut prev_hash: Option<[u8; 16]> = None;

    while key.len() < key_len {
        let mut hasher = md5::Md5::new();
        if let Some(ref h) = prev_hash {
            hasher.update(h);
        }
        hasher.update(passphrase);
        hasher.update(salt);
        let hash: [u8; 16] = hasher.finalize().into();
        key.extend_from_slice(&hash);
        prev_hash = Some(hash);
    }

    key.truncate(key_len);
    key
}

fn decrypt_aes_cbc<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, ProviderHelperError>
where
    C: cipher::BlockDecryptMut + cipher::BlockCipher + cipher::KeyInit,
{
    use cipher::{BlockDecryptMut as _, KeyIvInit as _};

    let decryptor = cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|e| {
        ProviderHelperError::KeyDecryption(format!("failed to initialize cipher: {e}"))
    })?;

    decryptor
        .decrypt_padded_vec_mut::<cipher::block_padding::Pkcs7>(data)
        .map_err(|e| {
            ProviderHelperError::KeyDecryption(format!("failed to decrypt legacy PEM: {e}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_encrypted_returns_none() {
        let key_pem = b"-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n";
        assert!(decrypt_key_if_encrypted(key_pem, "pass").unwrap().is_none());
    }

    #[test]
    fn non_utf8_returns_error() {
        let bad = &[0xff, 0xfe, 0xfd];
        assert!(decrypt_key_if_encrypted(bad, "pass").is_err());
    }

    #[test]
    fn evp_bytes_to_key_produces_correct_length() {
        let key = evp_bytes_to_key(b"password", b"saltsalt", 32);
        assert_eq!(key.len(), 32);

        let key16 = evp_bytes_to_key(b"password", b"saltsalt", 16);
        assert_eq!(key16.len(), 16);

        // First 16 bytes should match
        assert_eq!(&key[..16], &key16[..]);
    }

    #[test]
    fn hex_decode_works() {
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_decode("00FF").unwrap(), vec![0x00, 0xff]);
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("zz").is_err());
    }
}
