//! The user's folders.
//!
//! A folder belongs to one person rather than to an organisation: its name is
//! encrypted with the user's key, and an organisation's items can lie in it
//! too. Deleting a folder does not delete its items — the server leaves them
//! without a folder.

use crate::orgs::{checked_id, send};

/// Creates a folder and returns its identifier.
pub async fn create(base_url: &str, access_token: &str, encrypted_name: &str) -> anyhow::Result<String> {
    let body = serde_json::json!({ "name": encrypted_name });
    let text = send(base_url, access_token, reqwest::Method::POST, "api/folders", Some(body)).await?;
    crate::orgs::created_id(&text, "folder")
}

pub async fn rename(base_url: &str, access_token: &str, folder_id: &str, encrypted_name: &str) -> anyhow::Result<()> {
    let body = serde_json::json!({ "name": encrypted_name });
    let path = format!("api/folders/{}", checked_id(folder_id)?);
    send(base_url, access_token, reqwest::Method::PUT, &path, Some(body)).await?;
    Ok(())
}

pub async fn delete(base_url: &str, access_token: &str, folder_id: &str) -> anyhow::Result<()> {
    let path = format!("api/folders/{}", checked_id(folder_id)?);
    send(base_url, access_token, reqwest::Method::DELETE, &path, None).await?;
    Ok(())
}
