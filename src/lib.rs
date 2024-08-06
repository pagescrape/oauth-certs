//! The project fetches oauth certificates from providers during build time and stores them as lazy structures for retrieval.

#![deny(
    warnings,
    bad_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    deprecated,
    unconditional_recursion,
    unknown_lints,
    unreachable_code,
    unused_mut
)]

use jsonwebtoken::jwk::JwkSet;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

struct Certs {
    value: Option<JwkSet>,
    expires_in: Option<Duration>,
}

impl Certs {}

fn time_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
}

fn is_expired(expires_in: Duration) -> bool {
    time_now() > expires_in
}

/// Google certificates
pub mod google {
    use super::*;
    use cache_control::CacheControl;
    use tokio::sync::RwLock;

    use crate::Certs;

    async fn retrieve() -> Result<(JwkSet, Option<Duration>), reqwest::Error> {
        let response = reqwest::get("https://www.googleapis.com/oauth2/v3/certs").await?;

        let max_age = response
            .headers()
            .get("Cache-Control")
            .map(|value| value.to_str().ok())
            .flatten()
            .map(|value| CacheControl::from_value(value))
            .flatten()
            .map(|value| value.max_age)
            .flatten();

        let jwk_set = response.json().await?;
        Ok((jwk_set, max_age))
    }

    /// Reset Google oauth certificates
    pub async fn reset_oauth2_v3_certs() -> Result<(), reqwest::Error> {
        {
            OAUTH_CERTS.write().await.value = None;
        }
        Ok(())
    }

    /// Google oauth certificates"
    static OAUTH_CERTS: RwLock<Certs> = RwLock::const_new(Certs {
        value: None,
        expires_in: None,
    });

    /// Get JwkSet of Google oauth certificates
    pub async fn oauth2_v3_certs() -> Result<JwkSet, reqwest::Error> {
        {
            let oauth_certs = OAUTH_CERTS.read().await;

            if let Some(ref certs) = oauth_certs.value {
                if !oauth_certs.expires_in.map(is_expired).unwrap_or(false) {
                    return Ok(certs.clone());
                }
            }
        }

        let (certs, max_age) = retrieve().await?;
        let expires_in = time_now() + max_age.unwrap_or(Duration::from_secs(1800));

        // Drop lock ASAP
        {
            let mut v = OAUTH_CERTS.write().await;
            v.value = Some(certs.clone());
            v.expires_in = Some(expires_in)
        }

        Ok(certs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_google_oauth_certs() {
        assert!(google::oauth2_v3_certs().await.is_ok());
    }
}
