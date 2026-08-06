use crate::{
    full_directory_candidate, full_file_candidate, inventory_disposition_for_path,
    is_reparse_point_or_symlink, CleanupCandidate, DirectoryStats, ScanController, VolumeInfo,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanCoverageStatus {
    #[default]
    NotStarted,
    Complete,
    Partial,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CoverageGapReason {
    AccessDenied,
    Disappeared,
    InvalidMetadata,
    ReparseNotFollowed,
    IdentityFallback,
    BackendFallback,
    ResourceLimit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InventoryDisposition {
    #[default]
    Normal,
    AnalysisOnly,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InventoryObjectType {
    File,
    Directory,
    ReparsePoint,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryEntry {
    pub scan_session_id: String,
    pub volume_id: String,
    pub entry_id: String,
    pub file_identity: Option<String>,
    pub parent_entry_id: Option<String>,
    pub name: String,
    pub object_type: InventoryObjectType,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub attributes: u32,
    pub reparse_tag: Option<u32>,
    pub disposition: InventoryDisposition,
    pub allocation_owner: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryAggregate {
    pub scan_session_id: String,
    pub entry_id: String,
    pub subtree_logical_bytes: u64,
    pub subtree_allocated_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub analysis_only_count: u64,
    pub blocked_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageGap {
    pub volume_id: String,
    pub reason: CoverageGapReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_hint: Option<String>,
    pub count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeCoverage {
    pub volume_id: String,
    pub backend: String,
    pub status: ScanCoverageStatus,
    pub visited_entries: u64,
    pub indexed_entries: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub gaps: Vec<CoverageGap>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCoverage {
    pub status: ScanCoverageStatus,
    pub visited_entries: u64,
    pub indexed_entries: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub volumes: Vec<VolumeCoverage>,
    pub gaps: Vec<CoverageGap>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeSpaceSummary {
    pub volume_id: String,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub analysis_only_count: u64,
    pub blocked_count: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InventorySort {
    #[default]
    Name,
    LogicalBytes,
    AllocatedBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryQueryItem {
    pub entry_id: String,
    pub parent_entry_id: Option<String>,
    pub volume_id: String,
    pub name: String,
    pub path: String,
    pub object_type: InventoryObjectType,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub disposition: InventoryDisposition,
    pub allocation_owner: bool,
    pub has_children: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryPage {
    pub items: Vec<InventoryQueryItem>,
    pub next_cursor: Option<String>,
}

pub trait InventorySink {
    fn write_entry(&mut self, entry: &InventoryEntry) -> Result<(), String>;
    fn write_directory_aggregate(&mut self, aggregate: &DirectoryAggregate) -> Result<(), String>;
    fn write_gap(&mut self, gap: &CoverageGap) -> Result<(), String>;
}

#[derive(Default)]
pub struct NullInventorySink;

impl InventorySink for NullInventorySink {
    fn write_entry(&mut self, _entry: &InventoryEntry) -> Result<(), String> {
        Ok(())
    }

    fn write_directory_aggregate(&mut self, _aggregate: &DirectoryAggregate) -> Result<(), String> {
        Ok(())
    }

    fn write_gap(&mut self, _gap: &CoverageGap) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InventoryVolumeRun {
    pub candidates: Vec<CleanupCandidate>,
    pub coverage: VolumeCoverage,
    pub summary: VolumeSpaceSummary,
}

#[derive(Default)]
struct AggregateStats {
    logical_bytes: u64,
    allocated_bytes: u64,
    file_count: u64,
    directory_count: u64,
    analysis_only_count: u64,
    blocked_count: u64,
    candidate_children: u32,
}

impl AggregateStats {
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

struct DirectoryFrame {
    path: PathBuf,
    entry_id: String,
    entries: DirectoryReader,
    stats: AggregateStats,
    is_root: bool,
}

struct DirectoryItem {
    path: PathBuf,
    name: String,
    object_type: InventoryObjectType,
    is_reparse: bool,
    details: FileDetails,
}

enum DirectoryReader {
    #[cfg(windows)]
    FileId(WindowsDirectoryReader),
    Fallback(Box<fs::ReadDir>),
}

impl Iterator for DirectoryReader {
    type Item = std::io::Result<DirectoryItem>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            #[cfg(windows)]
            Self::FileId(reader) => reader.next(),
            Self::Fallback(entries) => entries.next().map(|result| {
                let entry = result?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                let file_type = metadata.file_type();
                let is_reparse = is_reparse_point_or_symlink(&metadata);
                let object_type = if is_reparse {
                    InventoryObjectType::ReparsePoint
                } else if file_type.is_dir() {
                    InventoryObjectType::Directory
                } else if file_type.is_file() {
                    InventoryObjectType::File
                } else {
                    InventoryObjectType::Other
                };
                Ok(DirectoryItem {
                    name: entry.file_name().to_string_lossy().to_string(),
                    details: file_details(&path, &metadata),
                    path,
                    object_type,
                    is_reparse,
                })
            }),
        }
    }
}

fn open_directory(path: &Path) -> std::io::Result<(DirectoryReader, bool)> {
    #[cfg(windows)]
    if let Ok(reader) = WindowsDirectoryReader::open(path) {
        return Ok((DirectoryReader::FileId(reader), false));
    }

    fs::read_dir(path).map(|entries| (DirectoryReader::Fallback(Box::new(entries)), cfg!(windows)))
}

struct ScanState<'a> {
    session_id: &'a str,
    volume: &'a VolumeInfo,
    sink: &'a mut dyn InventorySink,
    sink_available: bool,
    next_entry_id: u64,
    seen_file_identities: HashSet<String>,
    candidates: Vec<CleanupCandidate>,
    coverage: VolumeCoverage,
}

impl ScanState<'_> {
    fn entry_id(&mut self) -> String {
        let id = self.next_entry_id;
        self.next_entry_id = self.next_entry_id.saturating_add(1);
        format!("{}:{id}", self.volume.id)
    }

    fn record_gap(&mut self, reason: CoverageGapReason, path: Option<&Path>) {
        let path_hint = path.map(|value| value.to_string_lossy().to_string());
        if let Some(existing) = self
            .coverage
            .gaps
            .iter_mut()
            .find(|gap| gap.reason == reason && gap.path_hint == path_hint)
        {
            existing.count = existing.count.saturating_add(1);
            return;
        }

        let gap = CoverageGap {
            volume_id: self.volume.id.clone(),
            reason,
            path_hint,
            count: 1,
        };
        if self.sink_available && self.sink.write_gap(&gap).is_err() {
            self.sink_available = false;
        }
        self.coverage.gaps.push(gap);
    }

    fn write_entry(&mut self, entry: &InventoryEntry) {
        if self.sink_available {
            if self.sink.write_entry(entry).is_ok() {
                self.coverage.indexed_entries = self.coverage.indexed_entries.saturating_add(1);
            } else {
                self.sink_available = false;
                self.record_gap(CoverageGapReason::ResourceLimit, None);
            }
        }
    }

    fn write_aggregate(&mut self, aggregate: &DirectoryAggregate) {
        if self.sink_available && self.sink.write_directory_aggregate(aggregate).is_err() {
            self.sink_available = false;
            self.record_gap(CoverageGapReason::ResourceLimit, None);
        }
    }
}

pub(crate) fn scan_volume_inventory<C: ScanController + ?Sized>(
    session_id: &str,
    volume: &VolumeInfo,
    control: &C,
    sink: &mut dyn InventorySink,
) -> InventoryVolumeRun {
    let root = PathBuf::from(&volume.mount_point);
    let backend = if cfg!(windows) {
        "file-id-extd-directory-info"
    } else {
        "metadata-walk"
    };
    let mut state = ScanState {
        session_id,
        volume,
        sink,
        sink_available: true,
        next_entry_id: 1,
        seen_file_identities: HashSet::new(),
        candidates: Vec::new(),
        coverage: VolumeCoverage {
            volume_id: volume.id.clone(),
            backend: backend.to_string(),
            status: ScanCoverageStatus::Complete,
            ..VolumeCoverage::default()
        },
    };

    let root_id = state.entry_id();
    let root_name = root.to_string_lossy().to_string();
    state.write_entry(&InventoryEntry {
        scan_session_id: session_id.to_string(),
        volume_id: volume.id.clone(),
        entry_id: root_id.clone(),
        file_identity: None,
        parent_entry_id: None,
        name: root_name,
        object_type: InventoryObjectType::Directory,
        logical_bytes: 0,
        allocated_bytes: 0,
        attributes: 0,
        reparse_tag: None,
        disposition: InventoryDisposition::AnalysisOnly,
        allocation_owner: true,
    });

    let (root_entries, root_fallback) = match open_directory(&root) {
        Ok(result) => result,
        Err(error) => {
            state.record_gap(gap_reason_for_io(&error), Some(&root));
            state.coverage.status = ScanCoverageStatus::Failed;
            return finish_volume_run(state, AggregateStats::default());
        }
    };
    if root_fallback {
        state.record_gap(CoverageGapReason::BackendFallback, Some(&root));
    }

    let mut frames = vec![DirectoryFrame {
        path: root,
        entry_id: root_id,
        entries: root_entries,
        stats: AggregateStats {
            directory_count: 1,
            analysis_only_count: 1,
            ..AggregateStats::default()
        },
        is_root: true,
    }];

    while !frames.is_empty() {
        control.checkpoint();
        let next = frames
            .last_mut()
            .expect("frame exists while stack is non-empty")
            .entries
            .next();

        match next {
            Some(Ok(dir_entry)) => {
                let path = dir_entry.path;
                control.on_location(&path);
                control.on_visited(1);
                state.coverage.visited_entries = state.coverage.visited_entries.saturating_add(1);

                let object_type = dir_entry.object_type;
                let is_reparse = dir_entry.is_reparse;
                let details = dir_entry.details;
                let allocation_owner = details
                    .file_identity
                    .as_ref()
                    .is_none_or(|identity| state.seen_file_identities.insert(identity.clone()));
                if details.file_identity.is_none() {
                    state.record_gap(CoverageGapReason::IdentityFallback, None);
                }
                let accounted_allocated = if allocation_owner {
                    details.allocated_bytes
                } else {
                    0
                };
                let disposition = inventory_disposition_for_path(&path);
                let entry_id = state.entry_id();
                let parent_entry_id = frames
                    .last()
                    .map(|frame| frame.entry_id.clone())
                    .expect("child has a parent frame");
                let entry = InventoryEntry {
                    scan_session_id: state.session_id.to_string(),
                    volume_id: volume.id.clone(),
                    entry_id: entry_id.clone(),
                    file_identity: details.file_identity,
                    parent_entry_id: Some(parent_entry_id),
                    name: dir_entry.name,
                    object_type,
                    logical_bytes: details.logical_bytes,
                    allocated_bytes: details.allocated_bytes,
                    attributes: details.attributes,
                    reparse_tag: details.reparse_tag,
                    disposition,
                    allocation_owner,
                };
                state.write_entry(&entry);

                let direct_stats = AggregateStats {
                    logical_bytes: details.logical_bytes,
                    allocated_bytes: accounted_allocated,
                    file_count: u64::from(object_type == InventoryObjectType::File),
                    directory_count: u64::from(object_type == InventoryObjectType::Directory),
                    analysis_only_count: u64::from(
                        disposition == InventoryDisposition::AnalysisOnly,
                    ),
                    blocked_count: u64::from(disposition == InventoryDisposition::Blocked),
                    candidate_children: 1,
                };

                if is_reparse {
                    state.record_gap(CoverageGapReason::ReparseNotFollowed, Some(&path));
                    frames
                        .last_mut()
                        .expect("parent frame exists")
                        .stats
                        .add_child(&direct_stats);
                    continue;
                }

                if object_type == InventoryObjectType::Directory {
                    match open_directory(&path) {
                        Ok((entries, used_fallback)) => {
                            if used_fallback {
                                state.record_gap(CoverageGapReason::BackendFallback, Some(&path));
                            }
                            frames.push(DirectoryFrame {
                                path,
                                entry_id,
                                entries,
                                stats: direct_stats,
                                is_root: false,
                            })
                        }
                        Err(error) => {
                            state.record_gap(gap_reason_for_io(&error), Some(&path));
                            frames
                                .last_mut()
                                .expect("parent frame exists")
                                .stats
                                .add_child(&direct_stats);
                        }
                    }
                } else {
                    if object_type == InventoryObjectType::File {
                        if let Some(candidate) =
                            full_file_candidate(&path, details.logical_bytes, volume)
                        {
                            control.on_candidate(candidate.size_bytes);
                            state.candidates.push(candidate);
                        }
                    }
                    frames
                        .last_mut()
                        .expect("parent frame exists")
                        .stats
                        .add_child(&direct_stats);
                }
            }
            Some(Err(error)) => {
                let path = frames.last().map(|frame| frame.path.clone());
                state.record_gap(gap_reason_for_io(&error), path.as_deref());
            }
            None => {
                let frame = frames.pop().expect("completed frame exists");
                let aggregate = DirectoryAggregate {
                    scan_session_id: state.session_id.to_string(),
                    entry_id: frame.entry_id,
                    subtree_logical_bytes: frame.stats.logical_bytes,
                    subtree_allocated_bytes: frame.stats.allocated_bytes,
                    file_count: frame.stats.file_count,
                    directory_count: frame.stats.directory_count,
                    analysis_only_count: frame.stats.analysis_only_count,
                    blocked_count: frame.stats.blocked_count,
                };
                state.write_aggregate(&aggregate);

                if !frame.is_root {
                    let candidate_stats = DirectoryStats {
                        size_bytes: frame.stats.logical_bytes,
                        children_count: frame.stats.candidate_children,
                        truncated: false,
                    };
                    if let Some(candidate) =
                        full_directory_candidate(&frame.path, candidate_stats, volume)
                    {
                        control.on_candidate(candidate.size_bytes);
                        state.candidates.push(candidate);
                    }
                }

                if let Some(parent) = frames.last_mut() {
                    parent.stats.add_child(&frame.stats);
                } else {
                    return finish_volume_run(state, frame.stats);
                }
            }
        }
    }

    finish_volume_run(state, AggregateStats::default())
}

fn finish_volume_run(mut state: ScanState<'_>, stats: AggregateStats) -> InventoryVolumeRun {
    let has_partial_gap = state.coverage.gaps.iter().any(|gap| {
        matches!(
            gap.reason,
            CoverageGapReason::AccessDenied
                | CoverageGapReason::Disappeared
                | CoverageGapReason::InvalidMetadata
                | CoverageGapReason::ResourceLimit
        )
    });
    if state.coverage.status != ScanCoverageStatus::Failed && has_partial_gap {
        state.coverage.status = ScanCoverageStatus::Partial;
    }
    state.coverage.logical_bytes = stats.logical_bytes;
    state.coverage.allocated_bytes = stats.allocated_bytes;
    state
        .candidates
        .sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes));

    InventoryVolumeRun {
        candidates: state.candidates,
        summary: VolumeSpaceSummary {
            volume_id: state.volume.id.clone(),
            logical_bytes: stats.logical_bytes,
            allocated_bytes: stats.allocated_bytes,
            file_count: stats.file_count,
            directory_count: stats.directory_count,
            analysis_only_count: stats.analysis_only_count,
            blocked_count: stats.blocked_count,
        },
        coverage: state.coverage,
    }
}

fn gap_reason_for_io(error: &std::io::Error) -> CoverageGapReason {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => CoverageGapReason::AccessDenied,
        std::io::ErrorKind::NotFound => CoverageGapReason::Disappeared,
        _ => CoverageGapReason::InvalidMetadata,
    }
}

struct FileDetails {
    file_identity: Option<String>,
    logical_bytes: u64,
    allocated_bytes: u64,
    attributes: u32,
    reparse_tag: Option<u32>,
}

#[cfg(windows)]
struct WindowsDirectoryReader {
    handle: windows_sys::Win32::Foundation::HANDLE,
    directory: PathBuf,
    buffer: Vec<u8>,
    pending: VecDeque<DirectoryItem>,
    complete: bool,
}

#[cfg(windows)]
impl WindowsDirectoryReader {
    fn open(path: &Path) -> std::io::Result<Self> {
        use std::ptr::null_mut;
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            Storage::FileSystem::{
                CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE,
                FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            },
        };

        let wide = long_path(path)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            handle,
            directory: path.to_path_buf(),
            buffer: vec![0_u8; 64 * 1024],
            pending: VecDeque::new(),
            complete: false,
        })
    }

    fn read_batch(&mut self) -> std::io::Result<()> {
        use windows_sys::Win32::{
            Foundation::{GetLastError, ERROR_NO_MORE_FILES},
            Storage::FileSystem::{
                FileIdExtdDirectoryInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_DIRECTORY,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_EXTD_DIR_INFO,
            },
        };

        self.buffer.fill(0);
        let ok = unsafe {
            GetFileInformationByHandleEx(
                self.handle,
                FileIdExtdDirectoryInfo,
                self.buffer.as_mut_ptr() as *mut _,
                self.buffer.len() as u32,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_FILES {
                self.complete = true;
                return Ok(());
            }
            return Err(std::io::Error::from_raw_os_error(code as i32));
        }

        let mut offset = 0_usize;
        loop {
            if offset + std::mem::size_of::<FILE_ID_EXTD_DIR_INFO>() > self.buffer.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "FileIdExtdDirectoryInfo record exceeds buffer",
                ));
            }
            let record = unsafe {
                std::ptr::read_unaligned(
                    self.buffer.as_ptr().add(offset) as *const FILE_ID_EXTD_DIR_INFO
                )
            };
            let name_offset = offset + std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
            let name_units = record.FileNameLength as usize / 2;
            if name_offset + name_units * 2 > self.buffer.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "FileIdExtdDirectoryInfo name exceeds buffer",
                ));
            }
            let name = String::from_utf16_lossy(unsafe {
                std::slice::from_raw_parts(
                    self.buffer.as_ptr().add(name_offset) as *const u16,
                    name_units,
                )
            });
            if name != "." && name != ".." {
                let is_reparse = record.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
                let object_type = if is_reparse {
                    InventoryObjectType::ReparsePoint
                } else if record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    InventoryObjectType::Directory
                } else {
                    InventoryObjectType::File
                };
                let identity_bytes = record.FileId.Identifier;
                let identity = (!identity_bytes.iter().all(|byte| *byte == 0)).then(|| {
                    identity_bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect()
                });
                self.pending.push_back(DirectoryItem {
                    path: self.directory.join(&name),
                    name,
                    object_type,
                    is_reparse,
                    details: FileDetails {
                        file_identity: identity,
                        logical_bytes: record.EndOfFile.max(0) as u64,
                        allocated_bytes: record.AllocationSize.max(0) as u64,
                        attributes: record.FileAttributes,
                        reparse_tag: (record.ReparsePointTag != 0)
                            .then_some(record.ReparsePointTag),
                    },
                });
            }

            if record.NextEntryOffset == 0 {
                break;
            }
            offset = offset.saturating_add(record.NextEntryOffset as usize);
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Iterator for WindowsDirectoryReader {
    type Item = std::io::Result<DirectoryItem>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(entry) = self.pending.pop_front() {
                return Some(Ok(entry));
            }
            if self.complete {
                return None;
            }
            if let Err(error) = self.read_batch() {
                self.complete = true;
                return Some(Err(error));
            }
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsDirectoryReader {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn file_details(path: &Path, metadata: &fs::Metadata) -> FileDetails {
    use std::{mem::size_of, os::windows::fs::MetadataExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
            OPEN_EXISTING,
        },
    };

    let wide = long_path(path)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return FileDetails {
            file_identity: None,
            logical_bytes: metadata.file_size(),
            allocated_bytes: metadata.file_size(),
            attributes: metadata.file_attributes(),
            reparse_tag: None,
        };
    }

    let mut id = FILE_ID_INFO::default();
    let id_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            &mut id as *mut FILE_ID_INFO as *mut _,
            size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0;
    let mut standard = FILE_STANDARD_INFO::default();
    let standard_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            &mut standard as *mut FILE_STANDARD_INFO as *mut _,
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } != 0;
    unsafe { CloseHandle(handle) };

    let file_identity = id_ok.then(|| {
        let bytes = id.FileId.Identifier;
        format!(
            "{:016x}:{}",
            id.VolumeSerialNumber,
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    });
    let logical_bytes = if standard_ok {
        standard.EndOfFile.max(0) as u64
    } else {
        metadata.file_size()
    };
    let allocated_bytes = if standard_ok {
        standard.AllocationSize.max(0) as u64
    } else {
        logical_bytes
    };

    FileDetails {
        file_identity,
        logical_bytes,
        allocated_bytes,
        attributes: metadata.file_attributes(),
        reparse_tag: None,
    }
}

#[cfg(windows)]
fn long_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if value.starts_with(r"\\?\") {
        value.into_owned()
    } else if value.starts_with(r"\\") {
        format!(r"\\?\UNC\{}", value.trim_start_matches(r"\\"))
    } else {
        format!(r"\\?\{value}")
    }
}

#[cfg(unix)]
fn file_details(path: &Path, metadata: &fs::Metadata) -> FileDetails {
    use std::os::unix::fs::MetadataExt;
    FileDetails {
        file_identity: Some(format!("{:x}:{:x}", metadata.dev(), metadata.ino())),
        logical_bytes: metadata.len(),
        allocated_bytes: metadata.blocks().saturating_mul(512),
        attributes: 0,
        reparse_tag: None,
    }
}

#[cfg(not(any(windows, unix)))]
fn file_details(path: &Path, metadata: &fs::Metadata) -> FileDetails {
    FileDetails {
        file_identity: Some(crate::normalize_path_for_id(path)),
        logical_bytes: metadata.len(),
        allocated_bytes: metadata.len(),
        attributes: 0,
        reparse_tag: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingSink {
        entries: Vec<InventoryEntry>,
        aggregates: Vec<DirectoryAggregate>,
        gaps: Vec<CoverageGap>,
    }

    impl InventorySink for RecordingSink {
        fn write_entry(&mut self, entry: &InventoryEntry) -> Result<(), String> {
            self.entries.push(entry.clone());
            Ok(())
        }

        fn write_directory_aggregate(
            &mut self,
            aggregate: &DirectoryAggregate,
        ) -> Result<(), String> {
            self.aggregates.push(aggregate.clone());
            Ok(())
        }

        fn write_gap(&mut self, gap: &CoverageGap) -> Result<(), String> {
            self.gaps.push(gap.clone());
            Ok(())
        }
    }

    #[test]
    fn inventory_counts_protected_and_ordinary_files_without_making_them_candidates() {
        let root = temp_root("protected-accounting");
        let protected = root.join("Program Files").join("App");
        fs::create_dir_all(&protected).expect("create protected fixture");
        fs::write(protected.join("runtime.bin"), vec![1_u8; 17]).expect("write fixture");
        fs::write(root.join("ordinary.dat"), vec![2_u8; 23]).expect("write fixture");
        let volume = test_volume(&root);
        let mut sink = RecordingSink::default();

        let run = scan_volume_inventory("session", &volume, &crate::NoopScanController, &mut sink);

        assert_eq!(run.coverage.status, ScanCoverageStatus::Complete);
        assert!(run.summary.logical_bytes >= 40);
        assert!(sink.entries.iter().any(|entry| {
            entry.name == "runtime.bin" && entry.disposition == InventoryDisposition::Blocked
        }));
        assert!(!run
            .candidates
            .iter()
            .any(|candidate| candidate.path.ends_with("ordinary.dat")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hard_links_keep_both_entries_but_allocate_space_once() {
        let root = temp_root("hard-links");
        fs::create_dir_all(&root).expect("create fixture");
        let first = root.join("first.bin");
        let second = root.join("second.bin");
        fs::write(&first, vec![7_u8; 4096]).expect("write fixture");
        if fs::hard_link(&first, &second).is_err() {
            let _ = fs::remove_dir_all(root);
            return;
        }
        let volume = test_volume(&root);
        let mut sink = RecordingSink::default();

        let run = scan_volume_inventory("session", &volume, &crate::NoopScanController, &mut sink);

        let files = sink
            .entries
            .iter()
            .filter(|entry| entry.object_type == InventoryObjectType::File)
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 2);
        assert_eq!(
            files.iter().filter(|entry| entry.allocation_owner).count(),
            1
        );
        assert_eq!(run.summary.logical_bytes, 8192);
        assert!(run.summary.allocated_bytes <= files[0].allocated_bytes.max(4096));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reparse_directory_is_indexed_but_not_followed() {
        let root = temp_root("reparse-root");
        let target = temp_root("reparse-target");
        fs::create_dir_all(&root).expect("create root");
        fs::create_dir_all(&target).expect("create target");
        fs::write(target.join("outside.bin"), vec![3_u8; 31]).expect("write target");
        let link = root.join("linked");
        if create_directory_link(&target, &link).is_err() {
            let _ = fs::remove_dir_all(root);
            let _ = fs::remove_dir_all(target);
            return;
        }
        let volume = test_volume(&root);
        let mut sink = RecordingSink::default();

        let run = scan_volume_inventory("session", &volume, &crate::NoopScanController, &mut sink);

        assert!(sink.entries.iter().any(|entry| {
            entry.name == "linked" && entry.object_type == InventoryObjectType::ReparsePoint
        }));
        assert!(run
            .coverage
            .gaps
            .iter()
            .any(|gap| { gap.reason == CoverageGapReason::ReparseNotFollowed && gap.count == 1 }));
        assert!(!sink.entries.iter().any(|entry| entry.name == "outside.bin"));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(target);
    }

    #[test]
    fn logical_and_allocated_bytes_are_reported_separately() {
        let root = temp_root("allocation");
        fs::create_dir_all(&root).expect("create root");
        let file = fs::File::create(root.join("reserved.bin")).expect("create file");
        file.set_len(1024 * 1024).expect("set logical length");
        let volume = test_volume(&root);
        let mut sink = RecordingSink::default();

        let run = scan_volume_inventory("session", &volume, &crate::NoopScanController, &mut sink);

        let entry = sink
            .entries
            .iter()
            .find(|entry| entry.name == "reserved.bin")
            .expect("file is indexed");
        assert_eq!(entry.logical_bytes, 1024 * 1024);
        assert!(entry.allocated_bytes <= entry.logical_bytes);
        assert_eq!(run.summary.logical_bytes, 1024 * 1024);
        let _ = fs::remove_dir_all(root);
    }

    fn test_volume(root: &Path) -> VolumeInfo {
        VolumeInfo {
            id: "TEST".to_string(),
            label: "Test".to_string(),
            mount_point: root.to_string_lossy().to_string(),
            filesystem: "test".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: false,
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cleandeck-inventory-{name}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }
}
