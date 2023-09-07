# oauth-certs [![CI](https://github.com/pagescrape/oauth-certs/actions/workflows/rust.yml/badge.svg)](https://github.com/pagescrape/oauth-certs/actions/workflows/rust.yml)

The project fetches oauth certificates from providers during build time and stores them as lazy structures for retrieval.

### The gist of basic usage

```rust,no_run
/// `GooglePayload` is the user data from google.
/// see https://developers.google.com/identity/openid-connect/openid-connect for more info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ClaimsGoogle {
    // These fields are marked `always`.
    aud: String,
    exp: u64,
    iat: u64,
    iss: String,
    sub: String,

    /// Email
    email: String,
    /// Email verified or not
    email_verified: Option<bool>,
}

/// decode JWT token into Claims
pub async fn decode(token: &str) -> Result<ClaimsGoogle> {
    let header = jsonwebtoken::decode_header(token)?;

    let certs = oauth_certs::google::oauth2_v3_certs().await.map_err(|e| {
        // tracing::error!("Failed to get google oauth certs: {}", e);
        jsonwebtoken::errors::ErrorKind::RsaFailedSigning
    })?;

    let jwt_key = (certs)
        .keys
        .iter()
        .find(|cert| cert.common.key_id == header.kid)
        .ok_or::<jsonwebtoken::errors::Error>(
            jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into(),
        )?;

    let decoding_key = DecodingKey::from_jwk(jwt_key)?;

    jsonwebtoken::decode::<ClaimsGoogle>(token, &decoding_key, &validation())
        .map(|token_data| token_data.claims)
}
```
