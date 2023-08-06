use std::env;
use std::fs::File;
use std::io::{LineWriter, Write};
use std::path::Path;

pub type GenericError = Box<dyn std::error::Error + Send + Sync>;

mod google {
    use jsonwebtoken::jwk::JwkSet;

    pub async fn retrieve() -> Result<JwkSet, reqwest::Error> {
        reqwest::Client::new()
            .get("https://www.googleapis.com/oauth2/v3/certs")
            .send()
            .await?
            .json()
            .await
    }
}

#[tokio::main]
async fn main() -> Result<(), GenericError> {
    let google = google::retrieve().await?;

    let google_json = serde_json::to_string(&google).unwrap();

    let out_dir = env::var("OUT_DIR").unwrap();
    let mut file = LineWriter::new(File::create(Path::new(&out_dir).join("google-certs.rs"))?);

    write!(&mut file, "\n").unwrap();
    write!(
        &mut file,
        r##"static RAW_GOOGLE_OAUTH_JSON: &'static str = r#"{google_json}"#;"##
    )
    .unwrap();
    write!(&mut file, "\n").unwrap();
    write!(&mut file, "/// Google oauth certificates").unwrap();
    write!(&mut file, "\n").unwrap();
    write!(
        &mut file,
        "pub static OAUTH_CERTS: Lazy<JwkSet> = Lazy::new(|| serde_json::from_str(&RAW_GOOGLE_OAUTH_JSON).unwrap());"
    )
    .unwrap();
    write!(&mut file, "\n").unwrap();

    file.flush()?;

    Ok(())
}
