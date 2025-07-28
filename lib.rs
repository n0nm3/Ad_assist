// common/src/lib.rs - Structures communes entre agent et backend

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct tusk {
    pub filesystem: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub user_id: Uuid,
    pub perms: Vec<Bucket>,
    pub is_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bucket {
    pub id: Uuid,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileManifest {
    pub device_id: String,
    pub files: Vec<FileInfo>,
    pub session_id: Uuid,
    pub agent_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub hash: String,
    pub modified: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    Authenticate {
        agent_id: String,
        device_info: DeviceInfo,
    },
    SendManifest(FileManifest),
    ReadFile {
        path: String,
        offset: u64,
        length: u64,
    },
    WriteFile {
        path: String,
        data: Vec<u8>,
        offset: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: String,
    pub capacity: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Authenticated { session_id: Uuid, bucket_id: Uuid },
    PermissionDenied,
    Success,
    Error(String),
    Data(Vec<u8>),
}

impl User {
    pub fn has_permission(&self, bucket_id: &Uuid, operation: Operation) -> bool {
        self.perms.iter().any(|bucket| {
            bucket.id == *bucket_id
                && match operation {
                    Operation::Read => bucket.read,
                    Operation::Write => bucket.write,
                    Operation::Delete => bucket.delete,
                }
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Operation {
    Read,
    Write,
    Delete,
}
