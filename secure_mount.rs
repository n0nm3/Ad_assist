use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn mount_isolated(device_path: &Path) -> Result<PathBuf> {
    // moih avec uuid
    let mount_id = uuid::Uuid::new_v4();
    let mount_point = PathBuf::from(format!("/tmp/rustykey/{}", mount_id));

    fs::create_dir_all(&mount_point)?;

    // Owner only
    let mut perms = fs::metadata(&mount_point)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&mount_point, perms)?;

    // Déterminer le système de fichiers
    let fs_type = detect_filesystem(device_path)?;
    println!("Detected filesystem: {}", fs_type);

    // Monter en RO + Ns du pid
    mount(
        Some(device_path),
        &mount_point,
        Some(fs_type.as_str()),
        MsFlags::MS_RDONLY | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .context(format!(
        "Failed to mount device {:?} to {:?}",
        device_path, mount_point
    ))?;

    println!(
        "Successfully mounted {:?} at {:?}",
        device_path, mount_point
    );
    Ok(mount_point)
}

pub fn unmount_isolated(mount_point: &Path) -> Result<()> {
    umount2(mount_point, MntFlags::MNT_DETACH)?;
    fs::remove_dir(mount_point)?;
    Ok(())
}

fn detect_filesystem(device_path: &Path) -> Result<String> {
    use std::process::Command;

    let output = Command::new("blkid")
        .arg("-s")
        .arg("TYPE")
        .arg("-o")
        .arg("value")
        .arg(device_path)
        .output()
        .context("Failed to run blkid")?;
    

    if output.status.success() {
        let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !fs_type.is_empty() {
            return Ok(fs_type);
        }
    }

    // Fallback si sa merde
    let output = Command::new("file")
        .arg("-s")
        .arg(device_path)
        .output()
        .context("Failed to run file command")?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    if output_str.contains("FAT") || output_str.contains("DOS") {
        Ok("vfat".to_string())
    } else if output_str.contains("NTFS") {
        Ok("ntfs-3g".to_string())
    } else if output_str.contains("ext4") {
        Ok("ext4".to_string())
    } else if output_str.contains("ext3") {
        Ok("ext3".to_string())
    } else if output_str.contains("ext2") {
        Ok("ext2".to_string())
    } else if output_str.contains("exFAT") {
        Ok("exfat".to_string())
    } else {
        // Par défaut, essayer auto
        Ok("auto".to_string())
    }
}
