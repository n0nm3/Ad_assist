use anyhow::Result;
use std::path::PathBuf;
use tokio::sync::mpsc;
use udev::{Device, MonitorBuilder};

pub struct UsbMonitor {
    receiver: mpsc::Receiver<PathBuf>,
}

impl UsbMonitor {
    pub fn new() -> Result<Self> {
        let (tx, rx) = mpsc::channel(10);

        // monitor udev dans un thread (pent être faire un fork ?)
        std::thread::spawn(move || {
            if let Err(e) = monitor_usb_devices(tx) {
                eprintln!("USB monitor error: {}", e);
            }
        });

        Ok(Self { receiver: rx })
    }

    pub async fn wait_for_device(&mut self) -> Result<Option<PathBuf>> {
        Ok(self.receiver.recv().await)
    }
}

fn monitor_usb_devices(tx: mpsc::Sender<PathBuf>) -> Result<()> {
    let monitor = MonitorBuilder::new()?.match_subsystem("block")?.listen()?;

    loop {
        let event = monitor.iter().next();
        if let Some(event) = event {
            if event.event_type() == udev::EventType::Add {
                let device = event.device();
                if is_usb_storage(&device) || is_usb_partition(&device) {
                    if let Some(devnode) = device.devnode() {
                        println!("USB device detected: {:?}", devnode);
                        let _ = tx.blocking_send(devnode.to_path_buf());
                    }
                }
            }
        }
    }
}

fn is_usb_storage(device: &Device) -> bool {
    device
        .property_value("ID_BUS")
        .map(|v| v == "usb")
        .unwrap_or(false)
        && device
            .property_value("DEVTYPE")
            .map(|v| v == "disk")
            .unwrap_or(false)
}

fn is_usb_partition(device: &Device) -> bool {
    device
        .property_value("ID_BUS")
        .map(|v| v == "usb")
        .unwrap_or(false)
        && device
            .property_value("DEVTYPE")
            .map(|v| v == "partition")
            .unwrap_or(false)
}
