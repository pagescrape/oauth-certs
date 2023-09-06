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

/// Google certificates
pub mod google {
    use jsonwebtoken::jwk::JwkSet;
    use once_cell::sync::Lazy;

    fn retrieve() -> Result<JwkSet, reqwest::Error> {
        reqwest::blocking::Client::new()
            .get("https://www.googleapis.com/oauth2/v3/certs")
            .send()?
            .json()
    }

    /// Google oauth certificates"
    pub static OAUTH_CERTS: Lazy<JwkSet> =
        Lazy::new(|| retrieve().expect("Failed to retrieve Google OAuth certificates"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_oauth_certs() {
        assert!(!google::OAUTH_CERTS.keys.is_empty());
    }
}
