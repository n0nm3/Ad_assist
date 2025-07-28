use anyhow::Result;
use nix::sched::{unshare, CloneFlags};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use sha2::{Sha256, Digest};
use uuid::Uuid;

mod usb_monitor;
mod secure_mount;
mod network_client;

use common::{DeviceInfo, FileInfo, FileManifest};

const BACKEND_ADDR: &str = "127.0.0.1:8443";
const ISOLATED_MOUNT_PATH: &str = "/tmp/rustykey_isolated";

pub struct RustyAgent {
    agent_id: String,
    tls_config: Arc<rustls::ClientConfig>,
}

impl RustyAgent {
    pub fn new() -> Result<Self> {
        let agent_id = machine_uid::get()
            .map_err(|e| anyhow::anyhow!("Failed to get machine ID: {}", e))?;
        
        // Obtenir le chemin du projet
        let project_root = std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| "../".to_string());
        let cert_path = format!("{}/certs/agent-cert.pem", project_root);
        let key_path = format!("{}/certs/agent-key.pem", project_root);
        
        // Configuration TLS avec certificats mutuels
        let _cert_chain = load_certs(&cert_path)?;
        let _key = load_private_key(&key_path)?;
        
        // Configuration TLS simplifiée pour le développement
        let _root_store = rustls::RootCertStore::empty();
        
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
            .with_no_client_auth();
            
        Ok(Self {
            agent_id,
            tls_config: Arc::new(config),
        })
    }

    pub async fn run(&self) -> Result<()> {
        // Créer un namespace isolé pour le montage
        self.create_isolated_namespace()?;
        
        // Surveiller les insertions USB
        let mut monitor = usb_monitor::UsbMonitor::new()?;
        
        loop {
            if let Some(device_path) = monitor.wait_for_device().await? {
                println!("USB device detected: {:?}", device_path);
                
                // Ignorer si c'est le disque entier et qu'on a déjà traité une partition
                let device_str = device_path.to_string_lossy();
                if device_str.ends_with(|c: char| c.is_numeric()) {
                    // C'est une partition (ex: sdb1)
                    println!("Processing partition: {:?}", device_path);
                } else {
                    // C'est le disque entier (ex: sdb), attendre la partition
                    println!("Detected whole disk, waiting for partition...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
                
                // Traiter le dispositif dans un thread séparé
                let agent_id = self.agent_id.clone();
                let tls_config = self.tls_config.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = process_device(device_path, agent_id, tls_config).await {
                        eprintln!("Error processing device: {}", e);
                    }
                });
            }
        }
    }

    fn create_isolated_namespace(&self) -> Result<()> {
        // Créer un nouveau namespace de montage
        unshare(CloneFlags::CLONE_NEWNS)?;
        
        // Créer le répertoire de montage isolé
        fs::create_dir_all(ISOLATED_MOUNT_PATH)?;
        
        Ok(())
    }
}

async fn process_device(
    device_path: PathBuf,
    agent_id: String,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<()> {
    println!("Starting to process device: {:?}", device_path);
    
    // Obtenir les informations du dispositif
    let device_info = get_device_info(&device_path)?;
    println!("Device info: {:?}", device_info);
    
    // Monter dans l'espace isolé
    println!("Attempting to mount device...");
    let mount_point = secure_mount::mount_isolated(&device_path)?;
    println!("Device mounted at: {:?}", mount_point);
    
    // Se connecter au backend
    println!("Connecting to backend at {}", BACKEND_ADDR);
    let mut client = network_client::SecureClient::connect(
        BACKEND_ADDR,
        agent_id.clone(),
        tls_config
    ).await?;
    println!("Connected to backend");
    
    // Authentifier la session
    let (session_id, _bucket_id) = client.authenticate(device_info).await?;
    println!("Session authenticated: {}", session_id);
    
    // Scanner et envoyer le manifeste des fichiers
    println!("Scanning device files...");
    let manifest = scan_device(&mount_point, session_id, &agent_id)?;
    println!("Found {} files", manifest.files.len());
    
    client.send_manifest(manifest).await?;
    println!("Manifest sent to backend");
    
    // Démarrer le serveur de streaming pour les opérations fichiers
    println!("Starting file operations handler...");
    client.start_file_operations_handler(mount_point.clone()).await?;
    
    // Attendre la déconnexion
    tokio::signal::ctrl_c().await?;
    
    // Démonter et nettoyer
    secure_mount::unmount_isolated(&mount_point)?;
    
    Ok(())
}

fn get_device_info(device_path: &Path) -> Result<DeviceInfo> {
    // Utiliser udev pour obtenir les infos du dispositif
    let output = Command::new("udevadm")
        .args(&["info", "--query=all", "--name"])
        .arg(device_path)
        .output()?;
        
    let info_str = String::from_utf8_lossy(&output.stdout);
    
    // Parser les infos (simplifié pour l'exemple)
    Ok(DeviceInfo {
        vendor_id: 0x1234,  // À extraire de udev
        product_id: 0x5678, // À extraire de udev
        serial: extract_serial(&info_str).unwrap_or_default(),
        capacity: get_device_capacity(device_path)?,
    })
}

fn scan_device(mount_point: &Path, session_id: Uuid, agent_id: &str) -> Result<FileManifest> {
    let mut files = Vec::new();
    
    fn scan_dir(dir: &Path, base: &Path, files: &mut Vec<FileInfo>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            // Utiliser metadata() au lieu de entry.metadata() pour suivre les liens
            match fs::metadata(&path) {
                Ok(metadata) => {
                    if metadata.is_file() {
                        let relative_path = path.strip_prefix(base)?;
                        let hash = hash_file(&path)?;
                        
                        files.push(FileInfo {
                            path: relative_path.to_string_lossy().to_string(),
                            size: metadata.len(),
                            hash,
                            modified: metadata.modified()?.duration_since(std::time::UNIX_EPOCH)?.as_secs(),
                        });
                    } else if metadata.is_dir() && !is_special_dir(&path) {
                        scan_dir(&path, base, files)?;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read metadata for {:?}: {}", path, e);
                }
            }
        }
        Ok(())
    }
    
    println!("Scanning device at {:?}", mount_point);
    scan_dir(mount_point, mount_point, &mut files)?;
    println!("Found {} files", files.len());
    
    Ok(FileManifest {
        device_id: mount_point.to_string_lossy().to_string(),
        files,
        session_id,
        agent_id: agent_id.to_string(),
    })
}

fn is_special_dir(path: &Path) -> bool {
    if let Some(name) = path.file_name() {
        let name_str = name.to_string_lossy();
        // Ignorer les dossiers système
        matches!(name_str.as_ref(), 
            "System Volume Information" | 
            "$RECYCLE.BIN" | 
            ".Trash-1000" |
            "lost+found")
    } else {
        false
    }
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn extract_serial(udev_info: &str) -> Option<String> {
    udev_info.lines()
        .find(|line| line.contains("ID_SERIAL_SHORT="))
        .and_then(|line| line.split('=').nth(1))
        .map(|s| s.to_string())
}

fn get_device_capacity(device_path: &Path) -> Result<u64> {
    let size_path = format!("/sys/block/{}/size", 
        device_path.file_name().unwrap().to_string_lossy());
    
    let size_str = fs::read_to_string(&size_path)
        .unwrap_or_else(|_| "0".to_string());
    
    let sectors: u64 = size_str.trim().parse().unwrap_or(0);
    Ok(sectors * 512) // 512 bytes par secteur
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let cert_file = fs::read(path)?;
    let mut reader = std::io::BufReader::new(&cert_file[..]);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let key_file = fs::read(path)?;
    let mut reader = std::io::BufReader::new(&key_file[..]);
    
    // Essayer d'abord PKCS8
    let keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    
    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }
    
    // Essayer RSA si PKCS8 échoue
    let mut reader = std::io::BufReader::new(&key_file[..]);
    let keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    
    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }
    
    Err(anyhow::anyhow!("No private key found"))
}

// Module danger pour désactiver la vérification TLS (développement uniquement)
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Installer le provider crypto par défaut pour rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    
    // Vérifier les privilèges
    let uid = nix::unistd::Uid::current();
    if !uid.is_root() {
        eprintln!("RustyKey agent must run as root");
        std::process::exit(1);
    }
    
    // Initialiser le logging
    env_logger::init();
    
    // Créer et démarrer l'agent
    let agent = RustyAgent::new()?;
    agent.run().await?;
    
    Ok(())
}
