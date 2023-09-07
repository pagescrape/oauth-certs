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
    private_in_public,
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

struct Certs {
    value: Option<JwkSet>,
}

impl Certs {}

/// Google certificates
pub mod google {
    use tokio::sync::RwLock;

    use jsonwebtoken::jwk::JwkSet;

    use crate::Certs;

    async fn retrieve() -> Result<JwkSet, reqwest::Error> {
        reqwest::get("https://www.googleapis.com/oauth2/v3/certs")
            .await?
            .json()
            .await
    }

    /// Google oauth certificates"
    static OAUTH_CERTS: RwLock<Certs> = RwLock::const_new(Certs { value: None });

    /// Get JwkSet of Google oauth certificates
    pub async fn oauth2_v3_certs() -> Result<JwkSet, reqwest::Error> {
        {
            if let Some(ref certs) = OAUTH_CERTS.read().await.value {
                return Ok(certs.clone());
            }
        }

        let certs = retrieve().await?;
        {
            OAUTH_CERTS.write().await.value = Some(certs.clone());
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
