//! The USB's own boot log, [`BOOT_LOG_FILE`] beside Stela on its volume,
//! which `stela` preallocates: the loader writes it through the
//! firmware's file system from its first line until boot services end
//! ([`open`]), and the system engine writes on to the same clusters, wherever
//! they lie, through Stela's own drivers ([`resume`]), so the stick keeps the
//! whole run.
use crate::Result;
use crate::{
    engine::{bundle::Bytes, translations},
    output::{self, Log},
    status,
};
use alloc::{boxed::Box, format, string::String};
use stela_contracts::refuse;
use stela_drivers::block::{BlockDevice, BlockError, Features, Identity, Shared, Transport};
use stela_loader::mount_interface::BOOT_LOG_FILE;
use stela_runtime::pc::{
    boot_log::{self, LOG_BYTES, Writer},
    device_starts::{self, Skips},
    fat32::Fat32,
    gpt::Guid,
};
use uefi::{
    CString16, Handle,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol},
    proto::{
        ProtocolPointer,
        loaded_image::LoadedImage,
        media::{
            file::{File as _, FileAttribute, FileInfo, FileMode, RegularFile},
            fs::SimpleFileSystem,
        },
    },
};

/// The blocks the firmware's file is addressed in.
const BLOCK: u32 = 512;

/// Open the log on the volume Stela was loaded from, when it has one, and
/// return that partition's GUID, which the system engine opens it by.
pub fn open() -> Option<Guid> {
    status::begin("Opening the boot log on the USB");
    let opened = firmware_file().and_then(|(device, partition)| {
        let mut device: Box<dyn BlockDevice> = Box::new(device);
        // The earlier boots' account, before this boot's marker joins it.
        read_device_skips(&mut *device);
        let writer = Writer::open(&mut *device)
            .map_err(|error| refuse!("firmware boot log: {error}", %error))?;
        report(&writer, "firmware");
        crate::stop_record::set_boot(writer.boots());
        output::add_log(writer, device, Log::Firmware)
            .map_err(|error| refuse!("firmware boot log output: {error}", %error))?;
        Ok(partition)
    });
    finish(opened).flatten()
}

/// The PCI functions an earlier boot did not finish starting, or skipped
/// since (`device_starts`), as [`open`] read them from the log.
static DEVICE_SKIPS: output::Global<Skips> = output::Global(core::cell::RefCell::new(Skips::EMPTY));

/// The skips [`open`] read: none when the log was not opened.
pub fn device_skips() -> Skips {
    DEVICE_SKIPS
        .0
        .try_borrow()
        .map_or(Skips::EMPTY, |skips| *skips)
}

/// Read the log on `device` back from its newest line until it holds a
/// whole boot with a device-start marker, and keep the skips it gives.
fn read_device_skips(device: &mut dyn BlockDevice) {
    let Ok(newest) = boot_log::read_newest(device, 64 * 1024, device_starts::settled) else {
        output::arguments(format_args!(
            "BOOT LOG FILE unreadable for its device-start record: no device is skipped\n"
        ));
        return;
    };
    let skips = device_starts::read(&newest);
    for function in skips.iter() {
        output::arguments(format_args!(
            "{}\n",
            function.line("BOOT LOG FILE device start record:")
        ));
    }
    if let Ok(mut kept) = DEVICE_SKIPS.0.try_borrow_mut() {
        *kept = skips;
    }
}

/// Write on to the loader's log in its file on `partition`, the volume
/// [`open`] found it on.
pub fn resume(partition: Box<dyn BlockDevice>) {
    status::begin("Opening the boot log on the USB again");
    finish(engine_file(partition));
}

/// [`resume`] from inside the device start, which keeps its step on the
/// screen: the log only says whether the file is written on to.
pub fn resume_quietly(partition: Box<dyn BlockDevice>) -> bool {
    match engine_file(partition) {
        Ok(()) => true,
        Err(why) => {
            output::arguments(format_args!("BOOT LOG FILE off: {why}\n"));
            false
        }
    }
}

/// End the step: the log is kept, or why not, which the boot goes on
/// without.
fn finish<T>(opened: Result<T>) -> Option<T> {
    match opened {
        Ok(value) => {
            status::done(BOOT_LOG_FILE);
            Some(value)
        }
        Err(why) => {
            output::arguments(format_args!("BOOT LOG FILE off: {why}\n"));
            status::warn(&format!("not kept: {why}"));
            None
        }
    }
}

fn report(writer: &Writer, through: &str) {
    if let Some(reason) = writer.fresh() {
        output::arguments(format_args!("BOOT LOG FILE fresh: {reason}\n"));
    }
    output::arguments(format_args!(
        "BOOT LOG FILE {BOOT_LOG_FILE} through the {through} boot={} head={:#x}\n",
        writer.boots(),
        writer.head()
    ));
}

/// `handle`'s `P`, shared with whoever else holds it.
fn shared<P: ProtocolPointer + ?Sized>(handle: Handle) -> Option<ScopedProtocol<P>> {
    // SAFETY: used only for queries and file access while boot services
    // run; no driver on `handle` is replaced while it is held.
    unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()
}

fn firmware_file() -> Result<(FileDevice, Option<Guid>)> {
    let device = shared::<LoadedImage>(boot::image_handle())
        .ok_or(refuse!("no loaded image"))?
        .device()
        .ok_or(refuse!("Stela was not loaded from a volume"))?;
    let mut volume =
        shared::<SimpleFileSystem>(device).ok_or(refuse!("Stela's volume has no file system"))?;
    let mut root = volume
        .open_volume()
        .map_err(|_| refuse!("Stela's volume cannot be opened"))?;
    let path =
        CString16::try_from(BOOT_LOG_FILE).map_err(|_| refuse!("the log's path is not UCS-2"))?;
    let mut file = root
        .open(&path, FileMode::ReadWrite, FileAttribute::empty())
        .ok()
        .and_then(|file| file.into_regular_file())
        .ok_or(refuse!("Stela's volume has no \\EFI\\stela\\boot.log"))?;
    let size = file
        .get_boxed_info::<FileInfo>()
        .map_err(|_| refuse!("the log file's size cannot be read"))?
        .file_size();
    if size < LOG_BYTES {
        return Err(refuse!("\\EFI\\stela\\boot.log is shorter than the log"));
    }
    let identity = Identity {
        transport: Transport::Firmware,
        location: String::from(BOOT_LOG_FILE),
        model: String::new(),
        serial: String::new(),
        blocks: LOG_BYTES / u64::from(BLOCK),
        block_size: BLOCK,
        read_only: false,
        // The firmware's file system may hold writes until a flush.
        features: Features {
            write_cache: true,
            ..Features::default()
        },
    };
    Ok((
        FileDevice { identity, file },
        translations::partition(device).map(Guid),
    ))
}

fn engine_file(partition: Box<dyn BlockDevice>) -> Result<()> {
    let block = u64::from(partition.identity().block_size);
    let mut volume = Fat32::open(Bytes::new(partition))
        .map_err(|error| refuse!("boot log volume: {error}", %error))?;
    let file = volume
        .file(&BOOT_LOG_FILE.replace('\\', "/"))
        .map_err(|error| refuse!("boot log file: {error}", %error))?;
    let runs = boot_log::file_runs(&file, block, LOG_BYTES)
        .map_err(|error| refuse!("boot log file runs: {error}", %error))?;
    let partition = volume.into_inner().into_inner();
    let mut device: Box<dyn BlockDevice> = Box::new(
        Shared::new(partition)
            .runs(runs)
            .map_err(|error| refuse!("boot log device: {error}", %error))?,
    );
    let writer = Writer::resume(&mut *device)
        .map_err(|error| refuse!("boot log resume: {error}", %error))?;
    report(&writer, "USB driver");
    output::add_log(writer, device, Log::Usb)
        .map_err(|error| refuse!("USB boot log output: {error}", %error))
}

/// The log file as blocks, through the firmware's file system.
struct FileDevice {
    identity: Identity,
    file: RegularFile,
}

impl FileDevice {
    fn seek(&mut self, lba: u64, bytes: usize) -> Result<(), BlockError> {
        if !bytes.is_multiple_of(BLOCK as usize) {
            return Err(BlockError::Misaligned {
                bytes,
                block_size: BLOCK,
            });
        }
        let blocks = (bytes / BLOCK as usize) as u64;
        if lba.saturating_add(blocks) > self.identity.blocks {
            return Err(BlockError::OutOfRange {
                lba,
                blocks,
                capacity: self.identity.blocks,
            });
        }
        self.file
            .set_position(lba * u64::from(BLOCK))
            .map_err(|error| failed(error.status()))
    }
}

fn failed(status: uefi::Status) -> BlockError {
    BlockError::Device {
        status: status.0 as u32,
    }
}

impl BlockDevice for FileDevice {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.seek(lba, buffer.len())?;
        let mut done = 0;
        while done < buffer.len() {
            match self.file.read(&mut buffer[done..]) {
                Ok(0) => return Err(failed(uefi::Status::END_OF_FILE)),
                Ok(count) => done += count,
                Err(error) => return Err(failed(error.status())),
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.seek(lba, data.len())?;
        self.file
            .write(data)
            .map_err(|error| failed(error.status()))
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.file.flush().map_err(|error| failed(error.status()))
    }
}
