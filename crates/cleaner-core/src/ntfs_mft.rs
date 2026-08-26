//! Direct NTFS `$MFT` inventory enumerator (WizTree-style).
//!
//! This is the complete-accounting fast path for NTFS volumes. It is **not**
//! `FSCTL_ENUM_USN_DATA`: USN records do not carry file sizes and must not be
//! used as the full-scan sizing backend.

use crate::inventory::{
    CoverageGap, CoverageGapReason, DirectoryAggregate, InventoryDisposition, InventoryEntry,
    InventoryObjectType, InventorySink, InventoryVolumeRun, ScanCoverageStatus, VolumeCoverage,
    VolumeSpaceSummary,
};
use crate::{
    full_directory_candidate, full_file_candidate, inventory_disposition_for_path, DirectoryStats,
    ScanController, ScanPhase, VolumeInfo,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_REPARSE_POINT: u32 = 0xc0;
const ATTR_END: u32 = 0xffff_ffff;

const FILE_RECORD_IN_USE: u16 = 0x0001;
const FILE_RECORD_IS_DIRECTORY: u16 = 0x0002;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

const NAME_NAMESPACE_POSIX: u8 = 0;
const NAME_NAMESPACE_WIN32: u8 = 1;
const NAME_NAMESPACE_DOS: u8 = 2;
const NAME_NAMESPACE_WIN32_DOS: u8 = 3;

const NTFS_ROOT_RECORD: u64 = 5;
const MFT_STREAM_CHUNK: usize = 1024 * 1024;
const WINDOWS_ERROR_ACCESS_DENIED: u32 = 5;

#[derive(Clone, Debug)]
pub(crate) struct MftFileName {
    pub parent_reference: u64,
    pub name: String,
    pub namespace: u8,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ParsedMftRecord {
    pub record_number: u64,
    pub in_use: bool,
    pub is_directory: bool,
    #[allow(dead_code)]
    pub sequence_number: u16,
    pub base_record: u64,
    pub attributes: u32,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub reparse_tag: Option<u32>,
    pub names: Vec<MftFileName>,
    pub has_unnamed_data: bool,
    pub has_attribute_list: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum MftScanError {
    AccessDenied(String),
    Unavailable(String),
}

impl MftScanError {
    pub fn message(&self) -> &str {
        match self {
            Self::AccessDenied(message) | Self::Unavailable(message) => message,
        }
    }

    pub fn gap_reason(&self) -> CoverageGapReason {
        match self {
            Self::AccessDenied(_) => CoverageGapReason::AccessDenied,
            Self::Unavailable(_) => CoverageGapReason::BackendFallback,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DataRun {
    /// `None` means a sparse hole (no clusters on disk).
    pub lcn: Option<u64>,
    pub cluster_count: u64,
}

/// Apply NTFS update-sequence (fixup) values to a FILE/INDX record buffer.
pub(crate) fn apply_usa_fixup(record: &mut [u8], sector_size: usize) -> Result<(), String> {
    if record.len() < 8 || sector_size == 0 || !record.len().is_multiple_of(sector_size) {
        return Err("invalid MFT record size for USA fixup".to_string());
    }
    let usa_offset = u16::from_le_bytes([record[4], record[5]]) as usize;
    let usa_count = u16::from_le_bytes([record[6], record[7]]) as usize;
    if usa_count == 0 {
        return Ok(());
    }
    let expected_sectors = record.len() / sector_size;
    if usa_count != expected_sectors + 1 {
        return Err(format!(
            "USA count {usa_count} does not match record sectors {expected_sectors}"
        ));
    }
    let usa_bytes = usa_count.saturating_mul(2);
    if usa_offset == 0 || usa_offset.saturating_add(usa_bytes) > record.len() {
        return Err("USA array exceeds MFT record".to_string());
    }
    let usn = [record[usa_offset], record[usa_offset + 1]];
    for sector_index in 0..expected_sectors {
        let sector_end = (sector_index + 1).saturating_mul(sector_size);
        let marker_offset = sector_end.saturating_sub(2);
        if record[marker_offset] != usn[0] || record[marker_offset + 1] != usn[1] {
            return Err("MFT USA sequence number mismatch".to_string());
        }
        let replacement = usa_offset + 2 + sector_index * 2;
        record[marker_offset] = record[replacement];
        record[marker_offset + 1] = record[replacement + 1];
    }
    Ok(())
}

/// Parse one FILE record after USA fixups have been applied.
pub(crate) fn parse_file_record(record: &[u8], record_number: u64) -> Option<ParsedMftRecord> {
    if record.len() < 0x30 || &record[0..4] != b"FILE" {
        return None;
    }

    let sequence_number = read_u16(record, 0x10)?;
    let first_attr = read_u16(record, 0x14)? as usize;
    let flags = read_u16(record, 0x16)?;
    let used_size = read_u32(record, 0x18)? as usize;
    let base_record = file_reference_record_number(read_u64(record, 0x20)?);
    let in_use = flags & FILE_RECORD_IN_USE != 0;
    let is_directory = flags & FILE_RECORD_IS_DIRECTORY != 0;

    let mut parsed = ParsedMftRecord {
        record_number,
        in_use,
        is_directory,
        sequence_number,
        base_record,
        ..ParsedMftRecord::default()
    };

    if !in_use || first_attr < 0x30 || first_attr >= record.len() {
        return Some(parsed);
    }

    let limit = used_size.min(record.len()).max(first_attr);
    let mut offset = first_attr;
    while offset + 8 <= limit {
        let attr_type = read_u32(record, offset)?;
        if attr_type == ATTR_END {
            break;
        }
        let attr_len = read_u32(record, offset + 4)? as usize;
        if attr_len < 0x18 || offset + attr_len > limit {
            break;
        }
        let non_resident = record[offset + 8];
        let name_length = record[offset + 9] as usize;
        let name_offset = read_u16(record, offset + 10)? as usize;

        match attr_type {
            ATTR_STANDARD_INFORMATION if non_resident == 0 => {
                if let Some(value) = resident_value(record, offset, attr_len) {
                    if value.len() >= 0x24 {
                        parsed.attributes = read_u32(value, 0x20).unwrap_or(0);
                    }
                }
            }
            ATTR_ATTRIBUTE_LIST => {
                parsed.has_attribute_list = true;
            }
            ATTR_FILE_NAME if non_resident == 0 => {
                if let Some(value) = resident_value(record, offset, attr_len) {
                    if let Some(name) = parse_file_name_value(value) {
                        parsed.names.push(name);
                    }
                }
            }
            ATTR_DATA if name_length == 0 => {
                // Unnamed default data stream; only the first extent (LowestVcn == 0)
                // carries authoritative sizes.
                if non_resident == 0 {
                    if let Some(value) = resident_value(record, offset, attr_len) {
                        let logical = value.len() as u64;
                        if !parsed.has_unnamed_data {
                            parsed.logical_bytes = logical;
                            parsed.allocated_bytes = logical;
                            parsed.has_unnamed_data = true;
                        }
                    }
                } else if let Some((logical, allocated, lowest_vcn)) =
                    non_resident_sizes(record, offset, attr_len)
                {
                    if lowest_vcn == 0 && !parsed.has_unnamed_data {
                        parsed.logical_bytes = logical;
                        parsed.allocated_bytes = allocated;
                        parsed.has_unnamed_data = true;
                    }
                }
            }
            ATTR_REPARSE_POINT => {
                parsed.attributes |= FILE_ATTRIBUTE_REPARSE_POINT;
                if non_resident == 0 {
                    if let Some(value) = resident_value(record, offset, attr_len) {
                        if value.len() >= 4 {
                            parsed.reparse_tag = read_u32(value, 0);
                        }
                    }
                }
            }
            _ => {}
        }

        // Named attributes still matter for detecting reparse via STANDARD_INFORMATION.
        let _ = name_offset;
        offset = offset.saturating_add(attr_len);
        // Attributes are 8-byte aligned.
        offset = (offset + 7) & !7;
    }

    if parsed.is_directory || parsed.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        parsed.is_directory = true;
        parsed.attributes |= FILE_ATTRIBUTE_DIRECTORY;
    }

    Some(parsed)
}

/// Select hard-link display names, skipping DOS-only short names when a Win32 name exists.
pub(crate) fn selected_file_names(names: &[MftFileName]) -> Vec<&MftFileName> {
    let has_win32 = names.iter().any(|name| {
        matches!(
            name.namespace,
            NAME_NAMESPACE_WIN32 | NAME_NAMESPACE_WIN32_DOS | NAME_NAMESPACE_POSIX
        )
    });
    names
        .iter()
        .filter(|name| {
            if name.namespace == NAME_NAMESPACE_DOS && has_win32 {
                return false;
            }
            !name.name.is_empty() && name.name != "."
        })
        .collect()
}

pub(crate) fn file_identity_for_record(volume_id: &str, record_number: u64) -> String {
    format!("{volume_id}:mft:{record_number:016x}")
}

pub(crate) fn rebuild_path(
    mount_point: &str,
    record_number: u64,
    parent_by_record: &HashMap<u64, u64>,
    primary_name_by_record: &HashMap<u64, String>,
) -> Option<PathBuf> {
    let mut components = Vec::new();
    let mut current = record_number;
    let mut visited = HashSet::new();

    for _ in 0..512 {
        if current == NTFS_ROOT_RECORD {
            break;
        }
        if !visited.insert(current) {
            return None;
        }
        let name = primary_name_by_record.get(&current)?;
        components.push(name.clone());
        let parent = *parent_by_record.get(&current)?;
        if parent == current {
            break;
        }
        current = parent;
    }

    components.reverse();
    let mut path = PathBuf::from(mount_point);
    for component in components {
        path.push(component);
    }
    Some(path)
}

fn parse_file_name_value(value: &[u8]) -> Option<MftFileName> {
    if value.len() < 0x42 {
        return None;
    }
    let parent_reference = file_reference_record_number(read_u64(value, 0)?);
    let name_length = value[0x40] as usize;
    let namespace = value[0x41];
    let name_bytes = 0x42 + name_length.saturating_mul(2);
    if name_bytes > value.len() {
        return None;
    }
    let units = unsafe {
        std::slice::from_raw_parts(value[0x42..name_bytes].as_ptr() as *const u16, name_length)
    };
    let name = String::from_utf16_lossy(units);
    Some(MftFileName {
        parent_reference,
        name,
        namespace,
    })
}

fn resident_value(record: &[u8], attr_offset: usize, attr_len: usize) -> Option<&[u8]> {
    let value_length = read_u32(record, attr_offset + 0x10)? as usize;
    let value_offset = read_u16(record, attr_offset + 0x14)? as usize;
    let start = attr_offset.saturating_add(value_offset);
    let end = start.saturating_add(value_length);
    if end > attr_offset + attr_len || end > record.len() {
        return None;
    }
    Some(&record[start..end])
}

fn non_resident_sizes(
    record: &[u8],
    attr_offset: usize,
    attr_len: usize,
) -> Option<(u64, u64, i64)> {
    if attr_len < 0x40 || attr_offset + 0x40 > record.len() {
        return None;
    }
    let lowest_vcn = read_i64(record, attr_offset + 0x10)?;
    let allocated = read_i64(record, attr_offset + 0x28)?.max(0) as u64;
    let file_size = read_i64(record, attr_offset + 0x30)?.max(0) as u64;
    // Compressed/sparse attributes may expose TotalAllocated at +0x40.
    let compression_unit = record.get(attr_offset + 0x22).copied().unwrap_or(0);
    let allocated = if attr_len >= 0x48 && compression_unit > 0 {
        read_i64(record, attr_offset + 0x40)
            .map(|value| value.max(0) as u64)
            .unwrap_or(allocated)
    } else {
        allocated
    };
    Some((file_size, allocated, lowest_vcn))
}

pub(crate) fn parse_data_runs(runlist: &[u8]) -> Result<Vec<DataRun>, String> {
    let mut runs = Vec::new();
    let mut offset = 0usize;
    let mut current_lcn: i64 = 0;
    while offset < runlist.len() {
        let header = runlist[offset];
        offset += 1;
        if header == 0 {
            break;
        }
        let length_size = (header & 0x0f) as usize;
        let offset_size = ((header >> 4) & 0x0f) as usize;
        if length_size == 0 || offset + length_size + offset_size > runlist.len() {
            return Err("truncated MFT data runlist".to_string());
        }
        let cluster_count = read_le_uint(&runlist[offset..offset + length_size])?;
        offset += length_size;
        let lcn = if offset_size == 0 {
            None
        } else {
            let delta = read_le_sint(&runlist[offset..offset + offset_size])?;
            offset += offset_size;
            current_lcn = current_lcn.saturating_add(delta);
            if current_lcn < 0 {
                return Err("negative LCN in MFT runlist".to_string());
            }
            Some(current_lcn as u64)
        };
        if cluster_count == 0 {
            continue;
        }
        runs.push(DataRun { lcn, cluster_count });
    }
    Ok(runs)
}

/// Collect unnamed non-resident `$DATA` runlists from a FILE record, ordered by LowestVcn.
///
/// Fragmented `$MFT` commonly spans multiple attribute extents; using only the first
/// extent under-reads the MFT stream and silently truncates inventory.
fn extract_mft_data_runs(record: &[u8]) -> Result<Vec<DataRun>, String> {
    let mut offset = read_u16(record, 0x14).ok_or("missing first attribute offset")? as usize;
    let used = read_u32(record, 0x18).ok_or("missing used size")? as usize;
    let limit = used.min(record.len());
    let mut extents: Vec<(i64, Vec<DataRun>)> = Vec::new();
    while offset + 0x40 <= limit {
        let attr_type = read_u32(record, offset).ok_or("truncated attribute type")?;
        if attr_type == ATTR_END {
            break;
        }
        let attr_len = read_u32(record, offset + 4).ok_or("truncated attribute length")? as usize;
        if attr_len < 0x18 || offset + attr_len > limit {
            break;
        }
        let non_resident = record[offset + 8];
        let name_length = record[offset + 9];
        if attr_type == ATTR_DATA && name_length == 0 && non_resident == 1 {
            let lowest_vcn = read_i64(record, offset + 0x10).unwrap_or(0);
            let mapping_pairs_offset =
                read_u16(record, offset + 0x20).ok_or("missing mapping pairs offset")? as usize;
            let run_start = offset.saturating_add(mapping_pairs_offset);
            if run_start >= offset + attr_len {
                return Err("MFT $DATA runlist offset out of range".to_string());
            }
            let runs = parse_data_runs(&record[run_start..offset + attr_len])?;
            extents.push((lowest_vcn, runs));
        }
        offset = (offset + attr_len + 7) & !7;
    }
    if extents.is_empty() {
        return Err("unable to locate non-resident unnamed $DATA runlist on $MFT".to_string());
    }
    extents.sort_by_key(|(lowest_vcn, _)| *lowest_vcn);
    let mut all_runs = Vec::new();
    for (_, runs) in extents {
        all_runs.extend(runs);
    }
    Ok(all_runs)
}

/// Merge ATTRIBUTE_LIST extension records into base FILE records (sizes, names, reparse).
pub(crate) fn merge_attribute_list_extensions(
    records_by_number: &mut HashMap<u64, ParsedMftRecord>,
    extensions: &[ParsedMftRecord],
) {
    let base_numbers: Vec<u64> = records_by_number
        .values()
        .filter(|record| record.has_attribute_list)
        .map(|record| record.record_number)
        .collect();

    for base_number in base_numbers {
        let Some(base) = records_by_number.get_mut(&base_number) else {
            continue;
        };
        for extension in extensions
            .iter()
            .filter(|record| record.base_record == base_number)
        {
            if extension.has_unnamed_data && !base.has_unnamed_data {
                base.logical_bytes = extension.logical_bytes;
                base.allocated_bytes = extension.allocated_bytes;
                base.has_unnamed_data = true;
            }
            if extension.reparse_tag.is_some() {
                base.reparse_tag = extension.reparse_tag;
                base.attributes |= FILE_ATTRIBUTE_REPARSE_POINT;
            }
            if !extension.names.is_empty() {
                base.names.extend(extension.names.iter().cloned());
            }
        }
    }
}

fn file_reference_record_number(value: u64) -> u64 {
    value & 0x0000_ffff_ffff_ffff
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8).map(|bytes| {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    })
}

fn read_i64(data: &[u8], offset: usize) -> Option<i64> {
    read_u64(data, offset).map(|value| value as i64)
}

fn read_le_uint(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err("invalid unsigned run length".to_string());
    }
    let mut buf = [0_u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

fn read_le_sint(bytes: &[u8]) -> Result<i64, String> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err("invalid signed run offset".to_string());
    }
    let mut buf = [0_u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    if bytes[bytes.len() - 1] & 0x80 != 0 {
        for fill in buf.iter_mut().skip(bytes.len()) {
            *fill = 0xff;
        }
    }
    Ok(i64::from_le_bytes(buf))
}

#[cfg(windows)]
pub(crate) fn try_scan_ntfs_mft_inventory<C: ScanController + ?Sized>(
    session_id: &str,
    volume: &VolumeInfo,
    control: &C,
    sink: &mut dyn InventorySink,
) -> Result<InventoryVolumeRun, MftScanError> {
    let mut enumerator = WindowsMftEnumerator::open(volume)?;
    control.on_progress_reset(Some(enumerator.estimated_records()));
    control.on_phase(ScanPhase::Indexing);
    enumerator.scan(session_id, volume, control, sink)
}

#[cfg(not(windows))]
pub(crate) fn try_scan_ntfs_mft_inventory<C: ScanController + ?Sized>(
    _session_id: &str,
    _volume: &VolumeInfo,
    _control: &C,
    _sink: &mut dyn InventorySink,
) -> Result<InventoryVolumeRun, MftScanError> {
    Err(MftScanError::Unavailable(
        "direct MFT inventory is only available on Windows".to_string(),
    ))
}

#[cfg(windows)]
struct WindowsMftEnumerator {
    handle: windows_sys::Win32::Foundation::HANDLE,
    bytes_per_sector: u32,
    bytes_per_cluster: u32,
    bytes_per_record: u32,
    runs: Vec<DataRun>,
    valid_data_length: u64,
}

#[cfg(windows)]
impl WindowsMftEnumerator {
    fn open(volume: &VolumeInfo) -> Result<Self, MftScanError> {
        use std::{mem::size_of, ptr::null_mut};
        use windows_sys::Win32::{
            Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
            Storage::FileSystem::{
                CreateFileW, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, OPEN_EXISTING,
            },
            System::{
                Ioctl::{FSCTL_GET_NTFS_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER},
                IO::DeviceIoControl,
            },
        };

        let device_path = volume_device_path(volume)?;
        let wide = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() };
            return Err(volume_open_error(&device_path, error));
        }

        let mut data = NTFS_VOLUME_DATA_BUFFER::default();
        let mut bytes_returned = 0_u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_GET_NTFS_VOLUME_DATA,
                null_mut(),
                0,
                &mut data as *mut NTFS_VOLUME_DATA_BUFFER as *mut _,
                size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
                &mut bytes_returned,
                null_mut(),
            )
        };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(volume_open_error(&device_path, error));
        }
        if data.BytesPerCluster == 0
            || data.BytesPerFileRecordSegment == 0
            || data.BytesPerSector == 0
            || data.MftValidDataLength <= 0
            || data.MftStartLcn < 0
        {
            unsafe { CloseHandle(handle) };
            return Err(MftScanError::Unavailable(
                "FSCTL_GET_NTFS_VOLUME_DATA returned incomplete NTFS geometry".to_string(),
            ));
        }

        let bytes_per_record = data.BytesPerFileRecordSegment;
        let mut first_record = vec![0_u8; bytes_per_record as usize];
        let first_offset =
            (data.MftStartLcn as u64).saturating_mul(u64::from(data.BytesPerCluster));
        if let Err(error) = read_volume_exact(handle, first_offset, &mut first_record) {
            unsafe { CloseHandle(handle) };
            return Err(error);
        }
        if let Err(error) = apply_usa_fixup(&mut first_record, data.BytesPerSector as usize) {
            unsafe { CloseHandle(handle) };
            return Err(MftScanError::Unavailable(error));
        }
        let runs = match extract_mft_data_runs(&first_record) {
            Ok(runs) if !runs.is_empty() => runs,
            Ok(_) => {
                unsafe { CloseHandle(handle) };
                return Err(MftScanError::Unavailable(
                    "$MFT data runlist is empty".to_string(),
                ));
            }
            Err(error) => {
                unsafe { CloseHandle(handle) };
                return Err(MftScanError::Unavailable(error));
            }
        };

        Ok(Self {
            handle,
            bytes_per_sector: data.BytesPerSector,
            bytes_per_cluster: data.BytesPerCluster,
            bytes_per_record,
            runs,
            valid_data_length: data.MftValidDataLength as u64,
        })
    }

    fn estimated_records(&self) -> u64 {
        if self.bytes_per_record == 0 {
            0
        } else {
            self.valid_data_length / u64::from(self.bytes_per_record)
        }
    }

    fn scan<C: ScanController + ?Sized>(
        &mut self,
        session_id: &str,
        volume: &VolumeInfo,
        control: &C,
        sink: &mut dyn InventorySink,
    ) -> Result<InventoryVolumeRun, MftScanError> {
        let record_size = self.bytes_per_record as usize;
        let mut records_by_number = HashMap::<u64, ParsedMftRecord>::new();
        let mut extension_records = Vec::<ParsedMftRecord>::new();
        let mut record_index = 0_u64;
        let mut processed_bytes = 0_u64;

        for run in &self.runs {
            control.checkpoint();
            let run_bytes = run
                .cluster_count
                .saturating_mul(u64::from(self.bytes_per_cluster));
            if processed_bytes >= self.valid_data_length {
                break;
            }
            let readable = run_bytes.min(self.valid_data_length - processed_bytes);
            match run.lcn {
                None => {
                    // Sparse hole: advance record index without emitting.
                    let skipped = readable / u64::from(self.bytes_per_record);
                    record_index = record_index.saturating_add(skipped);
                    processed_bytes = processed_bytes.saturating_add(readable);
                }
                Some(lcn) => {
                    let mut remaining = readable;
                    let mut disk_offset = lcn.saturating_mul(u64::from(self.bytes_per_cluster));
                    while remaining > 0 {
                        control.checkpoint();
                        let chunk = remaining.min(MFT_STREAM_CHUNK as u64) as usize;
                        let aligned = chunk - (chunk % record_size);
                        if aligned == 0 {
                            break;
                        }
                        let mut buffer = vec![0_u8; aligned];
                        read_volume_exact(self.handle, disk_offset, &mut buffer)?;
                        for record_bytes in buffer.chunks_exact(record_size) {
                            control.checkpoint();
                            let mut owned = record_bytes.to_vec();
                            if apply_usa_fixup(&mut owned, self.bytes_per_sector as usize).is_err()
                            {
                                record_index = record_index.saturating_add(1);
                                continue;
                            }
                            if let Some(parsed) = parse_file_record(&owned, record_index) {
                                if parsed.in_use {
                                    // Prefer the self-described record number when present.
                                    let number = if owned.len() >= 0x30 {
                                        read_u32(&owned, 0x2c)
                                            .map(u64::from)
                                            .filter(|value| *value != 0)
                                            .unwrap_or(record_index)
                                    } else {
                                        record_index
                                    };
                                    let mut parsed = parsed;
                                    parsed.record_number = number;
                                    control.on_visited(1);
                                    if parsed.base_record == 0 {
                                        records_by_number.insert(number, parsed);
                                    } else {
                                        // Extension records referenced via ATTRIBUTE_LIST.
                                        extension_records.push(parsed);
                                    }
                                }
                            }
                            record_index = record_index.saturating_add(1);
                        }
                        disk_offset = disk_offset.saturating_add(aligned as u64);
                        remaining = remaining.saturating_sub(aligned as u64);
                        processed_bytes = processed_bytes.saturating_add(aligned as u64);
                    }
                }
            }
        }

        merge_attribute_list_extensions(&mut records_by_number, &extension_records);

        Ok(emit_inventory_from_records(
            session_id,
            volume,
            control,
            sink,
            records_by_number,
        ))
    }
}

#[cfg(windows)]
impl Drop for WindowsMftEnumerator {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

fn emit_inventory_from_records<C: ScanController + ?Sized>(
    session_id: &str,
    volume: &VolumeInfo,
    control: &C,
    sink: &mut dyn InventorySink,
    records: HashMap<u64, ParsedMftRecord>,
) -> InventoryVolumeRun {
    let mut sink_available = true;
    let mut coverage = VolumeCoverage {
        volume_id: volume.id.clone(),
        backend: "ntfs-mft".to_string(),
        status: ScanCoverageStatus::Complete,
        ..VolumeCoverage::default()
    };
    let mut gaps = Vec::new();

    let mut parent_by_record = HashMap::new();
    let mut primary_name_by_record = HashMap::new();
    for record in records.values() {
        let selected = selected_file_names(&record.names);
        if let Some(first) = selected.first() {
            parent_by_record.insert(record.record_number, first.parent_reference);
            primary_name_by_record.insert(record.record_number, first.name.clone());
        }
    }

    let mut next_entry_id = 1_u64;
    let root_entry_id = {
        let id = next_entry_id;
        next_entry_id += 1;
        format!("{}:{id}", volume.id)
    };
    let root_path = PathBuf::from(&volume.mount_point);

    let root_entry = InventoryEntry {
        scan_session_id: session_id.to_string(),
        volume_id: volume.id.clone(),
        entry_id: root_entry_id.clone(),
        file_identity: Some(file_identity_for_record(&volume.id, NTFS_ROOT_RECORD)),
        parent_entry_id: None,
        name: volume.mount_point.clone(),
        object_type: InventoryObjectType::Directory,
        logical_bytes: 0,
        allocated_bytes: 0,
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        reparse_tag: None,
        disposition: InventoryDisposition::AnalysisOnly,
        allocation_owner: true,
    };
    write_inventory_entry(
        sink,
        &mut sink_available,
        &mut coverage,
        &mut gaps,
        &root_entry,
    );

    let mut entry_id_by_record = HashMap::new();
    entry_id_by_record.insert(NTFS_ROOT_RECORD, root_entry_id.clone());

    #[derive(Clone)]
    struct PendingLink {
        record_number: u64,
        link_index: usize,
        entry_id: String,
        parent_reference: u64,
        name: String,
        file_identity: String,
        object_type: InventoryObjectType,
        logical_bytes: u64,
        allocated_bytes: u64,
        attributes: u32,
        reparse_tag: Option<u32>,
        allocation_owner: bool,
        is_reparse: bool,
    }

    let mut pending_links = Vec::new();
    let mut seen_file_identities = HashSet::new();
    let mut ordered_records: Vec<u64> = records
        .keys()
        .copied()
        .filter(|number| *number != NTFS_ROOT_RECORD)
        .collect();
    ordered_records.sort_unstable();

    for record_number in ordered_records {
        control.checkpoint();
        let Some(record) = records.get(&record_number) else {
            continue;
        };
        let selected = selected_file_names(&record.names);
        if selected.is_empty() {
            continue;
        }

        let file_identity = file_identity_for_record(&volume.id, record.record_number);
        let allocation_owner = seen_file_identities.insert(file_identity.clone());
        let is_reparse = record.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let object_type = if is_reparse {
            InventoryObjectType::ReparsePoint
        } else if record.is_directory {
            InventoryObjectType::Directory
        } else {
            InventoryObjectType::File
        };

        for (link_index, name_attr) in selected.into_iter().enumerate() {
            let entry_id = {
                let id = next_entry_id;
                next_entry_id += 1;
                format!("{}:{id}", volume.id)
            };
            if link_index == 0 {
                entry_id_by_record.insert(record.record_number, entry_id.clone());
            }
            pending_links.push(PendingLink {
                record_number: record.record_number,
                link_index,
                entry_id,
                parent_reference: name_attr.parent_reference,
                name: name_attr.name.clone(),
                file_identity: file_identity.clone(),
                object_type,
                logical_bytes: record.logical_bytes,
                allocated_bytes: record.allocated_bytes,
                attributes: record.attributes,
                reparse_tag: record.reparse_tag,
                allocation_owner: allocation_owner && link_index == 0,
                is_reparse,
            });
        }
    }

    let mut candidates = Vec::new();
    let mut children_by_parent: HashMap<String, Vec<String>> = HashMap::new();
    let mut stats_by_entry: HashMap<String, AggregateNode> = HashMap::new();
    stats_by_entry.insert(
        root_entry_id.clone(),
        AggregateNode {
            path: root_path.clone(),
            object_type: InventoryObjectType::Directory,
            logical_bytes: 0,
            allocated_bytes: 0,
            file_count: 0,
            directory_count: 1,
            analysis_only_count: 1,
            blocked_count: 0,
            candidate_children: 0,
        },
    );

    control.on_progress_reset(Some(pending_links.len() as u64));
    control.on_phase(ScanPhase::Walking);

    for link in pending_links {
        control.checkpoint();
        let parent_path = if link.parent_reference == NTFS_ROOT_RECORD {
            Some(PathBuf::from(&volume.mount_point))
        } else {
            rebuild_path(
                &volume.mount_point,
                link.parent_reference,
                &parent_by_record,
                &primary_name_by_record,
            )
        };
        let Some(parent_path) = parent_path else {
            push_gap(
                &mut gaps,
                &volume.id,
                CoverageGapReason::InvalidMetadata,
                None,
                1,
            );
            continue;
        };
        let path = parent_path.join(&link.name);
        control.on_visited(1);
        control.on_location(&path);
        let disposition = inventory_disposition_for_path(&path);
        let parent_entry_id = entry_id_by_record
            .get(&link.parent_reference)
            .cloned()
            .or_else(|| (link.parent_reference == NTFS_ROOT_RECORD).then(|| root_entry_id.clone()));

        let entry = InventoryEntry {
            scan_session_id: session_id.to_string(),
            volume_id: volume.id.clone(),
            entry_id: link.entry_id.clone(),
            file_identity: Some(link.file_identity.clone()),
            parent_entry_id: parent_entry_id.clone(),
            name: link.name.clone(),
            object_type: link.object_type,
            logical_bytes: link.logical_bytes,
            allocated_bytes: link.allocated_bytes,
            attributes: link.attributes,
            reparse_tag: link.reparse_tag,
            disposition,
            allocation_owner: link.allocation_owner,
        };
        write_inventory_entry(sink, &mut sink_available, &mut coverage, &mut gaps, &entry);

        let accounted_allocated = if link.allocation_owner {
            link.allocated_bytes
        } else {
            0
        };
        control.on_scanned_bytes(accounted_allocated);
        stats_by_entry.insert(
            link.entry_id.clone(),
            AggregateNode {
                path: path.clone(),
                object_type: link.object_type,
                logical_bytes: link.logical_bytes,
                allocated_bytes: accounted_allocated,
                file_count: u64::from(link.object_type == InventoryObjectType::File),
                directory_count: u64::from(link.object_type == InventoryObjectType::Directory),
                analysis_only_count: u64::from(disposition == InventoryDisposition::AnalysisOnly),
                blocked_count: u64::from(disposition == InventoryDisposition::Blocked),
                candidate_children: 1,
            },
        );

        if let Some(parent_id) = parent_entry_id {
            children_by_parent
                .entry(parent_id)
                .or_default()
                .push(link.entry_id.clone());
        }

        if link.is_reparse {
            push_gap(
                &mut gaps,
                &volume.id,
                CoverageGapReason::ReparseNotFollowed,
                Some(&path),
                1,
            );
        } else if link.object_type == InventoryObjectType::File {
            if let Some(candidate) = full_file_candidate(&path, link.logical_bytes, volume) {
                control.on_candidate(candidate.size_bytes);
                candidates.push(candidate);
            }
        }

        let _ = (link.record_number, link.link_index);
    }

    let mut finished = HashSet::new();
    let mut stack = vec![(root_entry_id.clone(), false)];
    while let Some((entry_id, children_done)) = stack.pop() {
        if !children_done {
            stack.push((entry_id.clone(), true));
            if let Some(children) = children_by_parent.get(&entry_id) {
                for child in children.iter().rev() {
                    if !finished.contains(child) {
                        stack.push((child.clone(), false));
                    }
                }
            }
            continue;
        }
        if !finished.insert(entry_id.clone()) {
            continue;
        }

        let mut rolled = stats_by_entry
            .get(&entry_id)
            .cloned()
            .unwrap_or_else(AggregateNode::empty);
        if let Some(children) = children_by_parent.get(&entry_id) {
            for child in children {
                if let Some(child_stats) = stats_by_entry.get(child) {
                    rolled.add_child(child_stats);
                }
            }
        }

        let aggregate = DirectoryAggregate {
            scan_session_id: session_id.to_string(),
            entry_id: entry_id.clone(),
            subtree_logical_bytes: rolled.logical_bytes,
            subtree_allocated_bytes: rolled.allocated_bytes,
            file_count: rolled.file_count,
            directory_count: rolled.directory_count,
            analysis_only_count: rolled.analysis_only_count,
            blocked_count: rolled.blocked_count,
        };
        if sink_available && sink.write_directory_aggregate(&aggregate).is_err() {
            sink_available = false;
            push_gap(
                &mut gaps,
                &volume.id,
                CoverageGapReason::ResourceLimit,
                None,
                1,
            );
        }

        if entry_id != root_entry_id && rolled.object_type == InventoryObjectType::Directory {
            let candidate_stats = DirectoryStats {
                size_bytes: rolled.logical_bytes,
                children_count: rolled.candidate_children,
                truncated: false,
            };
            if let Some(candidate) = full_directory_candidate(&rolled.path, candidate_stats, volume)
            {
                control.on_candidate(candidate.size_bytes);
                candidates.push(candidate);
            }
        }

        stats_by_entry.insert(entry_id, rolled);
    }

    let root_stats = stats_by_entry
        .remove(&root_entry_id)
        .unwrap_or_else(AggregateNode::empty);
    coverage.gaps = gaps;
    coverage.logical_bytes = root_stats.logical_bytes;
    coverage.allocated_bytes = root_stats.allocated_bytes;
    let has_partial_gap = coverage.gaps.iter().any(|gap| {
        matches!(
            gap.reason,
            CoverageGapReason::AccessDenied
                | CoverageGapReason::Disappeared
                | CoverageGapReason::InvalidMetadata
                | CoverageGapReason::ResourceLimit
        )
    });
    if has_partial_gap {
        coverage.status = ScanCoverageStatus::Partial;
    }

    candidates.sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes));
    InventoryVolumeRun {
        candidates,
        summary: VolumeSpaceSummary {
            volume_id: volume.id.clone(),
            logical_bytes: root_stats.logical_bytes,
            allocated_bytes: root_stats.allocated_bytes,
            file_count: root_stats.file_count,
            directory_count: root_stats.directory_count,
            analysis_only_count: root_stats.analysis_only_count,
            blocked_count: root_stats.blocked_count,
        },
        coverage,
    }
}

fn push_gap(
    gaps: &mut Vec<CoverageGap>,
    volume_id: &str,
    reason: CoverageGapReason,
    path: Option<&Path>,
    count: u64,
) {
    if count == 0 {
        return;
    }
    let path_hint = path.map(|value| value.to_string_lossy().to_string());
    if let Some(existing) = gaps
        .iter_mut()
        .find(|gap| gap.reason == reason && gap.path_hint == path_hint)
    {
        existing.count = existing.count.saturating_add(count);
        return;
    }
    gaps.push(CoverageGap {
        volume_id: volume_id.to_string(),
        reason,
        path_hint,
        count,
    });
}

fn write_inventory_entry(
    sink: &mut dyn InventorySink,
    sink_available: &mut bool,
    coverage: &mut VolumeCoverage,
    gaps: &mut Vec<CoverageGap>,
    entry: &InventoryEntry,
) {
    coverage.visited_entries = coverage.visited_entries.saturating_add(1);
    if !*sink_available {
        return;
    }
    if sink.write_entry(entry).is_ok() {
        coverage.indexed_entries = coverage.indexed_entries.saturating_add(1);
    } else {
        *sink_available = false;
        push_gap(
            gaps,
            &coverage.volume_id,
            CoverageGapReason::ResourceLimit,
            None,
            1,
        );
    }
}

#[derive(Clone, Debug)]
struct AggregateNode {
    path: PathBuf,
    object_type: InventoryObjectType,
    logical_bytes: u64,
    allocated_bytes: u64,
    file_count: u64,
    directory_count: u64,
    analysis_only_count: u64,
    blocked_count: u64,
    candidate_children: u32,
}

impl AggregateNode {
    fn empty() -> Self {
        Self {
            path: PathBuf::new(),
            object_type: InventoryObjectType::Other,
            logical_bytes: 0,
            allocated_bytes: 0,
            file_count: 0,
            directory_count: 0,
            analysis_only_count: 0,
            blocked_count: 0,
            candidate_children: 0,
        }
    }

    fn add_child(&mut self, child: &Self) {
        self.logical_bytes = self.logical_bytes.saturating_add(child.logical_bytes);
        self.allocated_bytes = self.allocated_bytes.saturating_add(child.allocated_bytes);
        self.file_count = self.file_count.saturating_add(child.file_count);
        self.directory_count = self.directory_count.saturating_add(child.directory_count);
        self.analysis_only_count = self
            .analysis_only_count
            .saturating_add(child.analysis_only_count);
        self.blocked_count = self.blocked_count.saturating_add(child.blocked_count);
        self.candidate_children = self
            .candidate_children
            .saturating_add(child.candidate_children);
    }
}

fn volume_device_path(volume: &VolumeInfo) -> Result<String, MftScanError> {
    if volume.id.len() == 1 && volume.id.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Ok(format!("\\\\.\\{}:", volume.id.to_ascii_uppercase()));
    }
    Err(MftScanError::Unavailable(format!(
        "unsupported volume id for direct MFT open: {}",
        volume.id
    )))
}

#[cfg(windows)]
fn volume_open_error(device_path: &str, error: u32) -> MftScanError {
    if error == WINDOWS_ERROR_ACCESS_DENIED {
        MftScanError::AccessDenied(format!(
            "无法打开卷句柄 {device_path}：访问被拒绝（错误码 5）。直接解析 NTFS $MFT 需要以管理员身份运行"
        ))
    } else {
        MftScanError::Unavailable(format!("无法打开卷句柄 {device_path}，错误码 {error}"))
    }
}

#[cfg(windows)]
fn read_volume_exact(
    handle: windows_sys::Win32::Foundation::HANDLE,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), MftScanError> {
    use windows_sys::Win32::{
        Foundation::GetLastError,
        Storage::FileSystem::{ReadFile, SetFilePointerEx, FILE_BEGIN},
    };

    let ok = unsafe { SetFilePointerEx(handle, offset as i64, std::ptr::null_mut(), FILE_BEGIN) };
    if ok == 0 {
        return Err(MftScanError::Unavailable(format!(
            "SetFilePointerEx failed, 错误码 {}",
            unsafe { GetLastError() }
        )));
    }

    let mut read_total = 0usize;
    while read_total < buffer.len() {
        let mut bytes_read = 0_u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buffer[read_total..].as_mut_ptr() as *mut _,
                (buffer.len() - read_total) as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || bytes_read == 0 {
            return Err(MftScanError::Unavailable(format!(
                "ReadFile on volume failed at offset {offset}, 错误码 {}",
                unsafe { GetLastError() }
            )));
        }
        read_total += bytes_read as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn align8(buf: &mut Vec<u8>) {
        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
    }

    fn write_at(buf: &mut [u8], offset: usize, bytes: &[u8]) {
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    struct FileRecordFixture<'a> {
        record_number: u64,
        parent: u64,
        name: &'a str,
        is_directory: bool,
        logical: u64,
        allocated: u64,
        dos_attributes: u32,
        extra_names: &'a [(&'a str, u8)],
    }

    /// Build a post-fixup 1024-byte FILE record fixture for unit tests.
    fn build_file_record_fixture(spec: FileRecordFixture<'_>) -> Vec<u8> {
        let mut body = vec![0; 0x30];
        let FileRecordFixture {
            record_number,
            parent,
            name,
            is_directory,
            logical,
            allocated,
            dos_attributes,
            extra_names,
        } = spec;

        // $STANDARD_INFORMATION (resident)
        let std_info_offset = body.len();
        push_u32(&mut body, ATTR_STANDARD_INFORMATION);
        push_u32(&mut body, 0); // length placeholder
        body.push(0); // resident
        body.push(0); // name length
        push_u16(&mut body, 0); // name offset
        push_u16(&mut body, 0); // flags
        push_u16(&mut body, 0); // instance
        push_u32(&mut body, 0x48); // value length
        push_u16(&mut body, 0x18); // value offset
        body.push(0);
        body.push(0);
        // value: 4 timestamps + attributes
        for _ in 0..4 {
            push_u64(&mut body, 0);
        }
        push_u32(&mut body, dos_attributes);
        push_u32(&mut body, 0);
        push_u32(&mut body, 0);
        push_u32(&mut body, 0);
        push_u32(&mut body, 0);
        push_u32(&mut body, 0);
        align8(&mut body);
        let std_len = body.len() - std_info_offset;
        write_at(
            &mut body,
            std_info_offset + 4,
            &(std_len as u32).to_le_bytes(),
        );

        let mut names = vec![(name, NAME_NAMESPACE_WIN32)];
        names.extend(
            extra_names
                .iter()
                .map(|(value, namespace)| (*value, *namespace)),
        );
        for (link_name, namespace) in names {
            let name_units: Vec<u16> = link_name.encode_utf16().collect();
            let value_len = 0x42 + name_units.len() * 2;
            let attr_start = body.len();
            push_u32(&mut body, ATTR_FILE_NAME);
            push_u32(&mut body, 0);
            body.push(0);
            body.push(0);
            push_u16(&mut body, 0);
            push_u16(&mut body, 0);
            push_u16(&mut body, 0);
            push_u32(&mut body, value_len as u32);
            push_u16(&mut body, 0x18);
            body.push(1);
            body.push(0);
            push_u64(&mut body, parent);
            for _ in 0..4 {
                push_u64(&mut body, 0);
            }
            push_u64(&mut body, allocated);
            push_u64(&mut body, logical);
            push_u32(&mut body, dos_attributes);
            push_u32(&mut body, 0);
            body.push(name_units.len() as u8);
            body.push(namespace);
            for unit in name_units {
                push_u16(&mut body, unit);
            }
            align8(&mut body);
            let attr_len = body.len() - attr_start;
            write_at(&mut body, attr_start + 4, &(attr_len as u32).to_le_bytes());
        }

        if !is_directory {
            let attr_start = body.len();
            push_u32(&mut body, ATTR_DATA);
            push_u32(&mut body, 0x48);
            body.push(1); // non-resident
            body.push(0);
            push_u16(&mut body, 0);
            push_u16(&mut body, 0);
            push_u16(&mut body, 0);
            push_u64(&mut body, 0); // lowest vcn
            push_u64(&mut body, 0); // highest vcn
            push_u16(&mut body, 0x40); // mapping pairs offset
            body.push(0); // compression unit
            body.extend_from_slice(&[0; 5]);
            push_u64(&mut body, allocated);
            push_u64(&mut body, logical);
            push_u64(&mut body, logical);
            body.push(0); // empty runlist terminator
            align8(&mut body);
            let attr_len = body.len() - attr_start;
            write_at(&mut body, attr_start + 4, &(attr_len as u32).to_le_bytes());
        }

        push_u32(&mut body, ATTR_END);
        align8(&mut body);

        let used = body.len();
        let mut record = vec![0_u8; 1024];
        record[..used.min(1024)].copy_from_slice(&body[..used.min(1024)]);
        write_at(&mut record, 0, b"FILE");
        write_at(&mut record, 4, &48u16.to_le_bytes()); // usa offset
        write_at(&mut record, 6, &1u16.to_le_bytes()); // usa count (no sector replacements; post-fixup)
        write_at(&mut record, 0x10, &1u16.to_le_bytes()); // sequence
        write_at(
            &mut record,
            0x12,
            &(1u16 + extra_names.len() as u16).to_le_bytes(),
        );
        write_at(&mut record, 0x14, &0x30u16.to_le_bytes());
        let flags = FILE_RECORD_IN_USE
            | if is_directory {
                FILE_RECORD_IS_DIRECTORY
            } else {
                0
            };
        write_at(&mut record, 0x16, &flags.to_le_bytes());
        write_at(&mut record, 0x18, &(used as u32).to_le_bytes());
        write_at(&mut record, 0x1c, &1024u32.to_le_bytes());
        write_at(&mut record, 0x20, &0u64.to_le_bytes());
        write_at(&mut record, 0x2c, &(record_number as u32).to_le_bytes());
        record
    }

    #[test]
    fn parses_logical_and_allocated_sizes_from_data_attribute() {
        let record = build_file_record_fixture(FileRecordFixture {
            record_number: 42,
            parent: NTFS_ROOT_RECORD,
            name: "photo.bin",
            is_directory: false,
            logical: 1234,
            allocated: 4096,
            dos_attributes: 0x20,
            extra_names: &[],
        });
        let parsed = parse_file_record(&record, 42).expect("parse fixture");
        assert!(parsed.in_use);
        assert!(!parsed.is_directory);
        assert_eq!(parsed.logical_bytes, 1234);
        assert_eq!(parsed.allocated_bytes, 4096);
        assert_eq!(parsed.names[0].name, "photo.bin");
        assert_eq!(parsed.names[0].parent_reference, NTFS_ROOT_RECORD);
    }

    #[test]
    fn hard_link_names_are_all_selected_except_dos_short_name() {
        let record = build_file_record_fixture(FileRecordFixture {
            record_number: 7,
            parent: NTFS_ROOT_RECORD,
            name: "long-name.txt",
            is_directory: false,
            logical: 100,
            allocated: 512,
            dos_attributes: 0x20,
            extra_names: &[
                ("LONGNA~1.TXT", NAME_NAMESPACE_DOS),
                ("alias.txt", NAME_NAMESPACE_WIN32),
            ],
        });
        let parsed = parse_file_record(&record, 7).expect("parse fixture");
        let selected = selected_file_names(&parsed.names);
        let names: Vec<&str> = selected.iter().map(|name| name.name.as_str()).collect();
        assert!(names.contains(&"long-name.txt"));
        assert!(names.contains(&"alias.txt"));
        assert!(!names.contains(&"LONGNA~1.TXT"));
    }

    #[test]
    fn allocation_owner_is_deterministic_for_shared_file_identity() {
        let identity = file_identity_for_record("C", 99);
        let mut seen = HashSet::new();
        assert!(seen.insert(identity.clone()));
        assert!(!seen.insert(identity));
    }

    #[test]
    fn rebuild_path_walks_parent_chain_to_root() {
        let mut parents = HashMap::new();
        let mut names = HashMap::new();
        parents.insert(10, NTFS_ROOT_RECORD);
        names.insert(10, "Users".to_string());
        parents.insert(11, 10);
        names.insert(11, "docs".to_string());
        let path = rebuild_path("D:\\", 11, &parents, &names).expect("path");
        assert_eq!(path, PathBuf::from(r"D:\Users\docs"));
    }

    #[test]
    fn parse_data_runs_handles_sparse_and_relative_lcn() {
        // length=1 cluster at LCN 100, then sparse 2 clusters, then +3 -> LCN 103 for 1 cluster
        let runlist = [
            0x11, 0x01, 0x64, // 1 cluster @ 100
            0x01, 0x02, // sparse 2
            0x11, 0x01, 0x03, // 1 cluster @ 103
            0x00,
        ];
        let runs = parse_data_runs(&runlist).expect("runs");
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].lcn, Some(100));
        assert_eq!(runs[0].cluster_count, 1);
        assert_eq!(runs[1].lcn, None);
        assert_eq!(runs[1].cluster_count, 2);
        assert_eq!(runs[2].lcn, Some(103));
    }

    #[test]
    fn usa_fixup_restores_sector_end_words() {
        let mut record = vec![0_u8; 1024];
        write_at(&mut record, 0, b"FILE");
        write_at(&mut record, 4, &0x30u16.to_le_bytes());
        write_at(&mut record, 6, &3u16.to_le_bytes());
        // USA: USN=0xAAAA, replacements 0x1111 and 0x2222
        write_at(&mut record, 0x30, &0xAAAAu16.to_le_bytes());
        write_at(&mut record, 0x32, &0x1111u16.to_le_bytes());
        write_at(&mut record, 0x34, &0x2222u16.to_le_bytes());
        write_at(&mut record, 510, &0xAAAAu16.to_le_bytes());
        write_at(&mut record, 1022, &0xAAAAu16.to_le_bytes());
        apply_usa_fixup(&mut record, 512).expect("fixup");
        assert_eq!(u16::from_le_bytes([record[510], record[511]]), 0x1111);
        assert_eq!(u16::from_le_bytes([record[1022], record[1023]]), 0x2222);
    }

    #[test]
    fn mft_scan_error_maps_access_denied_gap() {
        let error = MftScanError::AccessDenied("denied".to_string());
        assert_eq!(error.gap_reason(), CoverageGapReason::AccessDenied);
        let unavailable = MftScanError::Unavailable("nope".to_string());
        assert_eq!(unavailable.gap_reason(), CoverageGapReason::BackendFallback);
    }

    #[test]
    fn merge_attribute_list_extensions_fills_missing_data_sizes() {
        let mut bases = HashMap::new();
        bases.insert(
            42,
            ParsedMftRecord {
                record_number: 42,
                in_use: true,
                has_attribute_list: true,
                names: vec![MftFileName {
                    parent_reference: NTFS_ROOT_RECORD,
                    name: "big.bin".to_string(),
                    namespace: NAME_NAMESPACE_WIN32,
                }],
                ..ParsedMftRecord::default()
            },
        );
        let extensions = vec![ParsedMftRecord {
            record_number: 99,
            in_use: true,
            base_record: 42,
            logical_bytes: 9_000,
            allocated_bytes: 12_288,
            has_unnamed_data: true,
            ..ParsedMftRecord::default()
        }];

        merge_attribute_list_extensions(&mut bases, &extensions);

        let merged = bases.get(&42).expect("base");
        assert!(merged.has_unnamed_data);
        assert_eq!(merged.logical_bytes, 9_000);
        assert_eq!(merged.allocated_bytes, 12_288);
    }

    #[test]
    fn extract_mft_data_runs_concatenates_multiple_data_extents() {
        // Minimal FILE record with two non-resident unnamed $DATA extents.
        let mut record = vec![0_u8; 512];
        write_at(&mut record, 0, b"FILE");
        write_at(&mut record, 0x14, &0x30u16.to_le_bytes());

        let mut body = Vec::new();
        // extent 0: LowestVcn=0, one cluster @ LCN 10
        {
            let start = body.len();
            push_u32(&mut body, ATTR_DATA);
            push_u32(&mut body, 0); // length placeholder
            body.push(1); // non-resident
            body.push(0); // name length
            push_u16(&mut body, 0);
            push_u16(&mut body, 0);
            push_u16(&mut body, 0);
            push_u64(&mut body, 0); // lowest vcn
            push_u64(&mut body, 0); // highest vcn
            push_u16(&mut body, 0x40);
            body.push(0);
            body.extend_from_slice(&[0; 5]);
            push_u64(&mut body, 4096);
            push_u64(&mut body, 4096);
            push_u64(&mut body, 4096);
            body.extend_from_slice(&[0x11, 0x01, 0x0A, 0x00]); // 1 cluster @ 10
            align8(&mut body);
            let len = body.len() - start;
            write_at(&mut body, start + 4, &(len as u32).to_le_bytes());
        }
        // extent 1: LowestVcn=1, one cluster @ LCN 20
        {
            let start = body.len();
            push_u32(&mut body, ATTR_DATA);
            push_u32(&mut body, 0);
            body.push(1);
            body.push(0);
            push_u16(&mut body, 0);
            push_u16(&mut body, 0);
            push_u16(&mut body, 0);
            push_u64(&mut body, 1); // lowest vcn
            push_u64(&mut body, 1);
            push_u16(&mut body, 0x40);
            body.push(0);
            body.extend_from_slice(&[0; 5]);
            push_u64(&mut body, 4096);
            push_u64(&mut body, 4096);
            push_u64(&mut body, 4096);
            body.extend_from_slice(&[0x11, 0x01, 0x14, 0x00]); // 1 cluster @ 20
            align8(&mut body);
            let len = body.len() - start;
            write_at(&mut body, start + 4, &(len as u32).to_le_bytes());
        }
        push_u32(&mut body, ATTR_END);
        let used = 0x30 + body.len();
        write_at(&mut record, 0x18, &(used as u32).to_le_bytes());
        record[0x30..0x30 + body.len()].copy_from_slice(&body);

        let runs = extract_mft_data_runs(&record).expect("runs");
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].lcn, Some(10));
        assert_eq!(runs[1].lcn, Some(20));
    }
}
