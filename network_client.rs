use anyhow::Result;
use common::{DeviceInfo, FileManifest};
use std::path::PathBuf;

pub struct SecureClient {
    client: reqwest::Client,
    base_url: String,
    agent_id: String,
}


//à passer ne https pour le Mtls
impl SecureClient {
    pub async fn connect(
        addr: &str,
        agent_id: String,
        _tls_config: std::sync::Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let base_url = format!("https://{}", addr);

        Ok(Self {
            client,
            base_url,
            agent_id,
        })
    }

    pub async fn authenticate(
        &mut self,
        device_info: DeviceInfo,
    ) -> Result<(uuid::Uuid, uuid::Uuid)> {
        let payload = serde_json::json!({
            "agent_id": self.agent_id,
            "device_info": device_info,
        });

        //débug ou pas pour chaner ld fmt,
        println!("Sending auth request to {}/agent/connect", self.base_url);
        let resp = self
            .client
            .post(format!("{}/agent/connect", self.base_url))
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Authentication failed: {} - {}",
                status,
                text
            ));
        }

        let json: serde_json::Value = resp.json().await?;
        let session_id = json["session_id"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid session_id"))?;
        let bucket_id = json["bucket_id"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid bucket_id"))?;

        println!(
            "Authenticated: session={}, bucket={}",
            session_id, bucket_id
        );
        Ok((session_id, bucket_id))
    }

    pub async fn send_manifest(&mut self, manifest: FileManifest) -> Result<()> {
        println!("Manifest contains {} files", manifest.files.len());

        // les objs
        for file in &manifest.files {
            println!("  - {} ({} bytes)", file.path, file.size);
        }
        Ok(())
    }

    pub async fn start_file_operations_handler(&mut self, mount_point: PathBuf) -> Result<()> {
        println!("File operations handler started (HTTP bridge mode)");
        println!("Mount point: {:?}", mount_point);

        Ok(())
    }
}
