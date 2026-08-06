use cleaner_core::{
    CoverageGap, DirectoryAggregate, InventoryDisposition, InventoryEntry, InventoryObjectType,
    InventoryPage, InventoryQueryItem, InventorySink, InventorySort, ScanCoverageStatus,
};
use rusqlite::{params, Connection, OptionalExtension, Row};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

const SCHEMA_VERSION: u32 = 1;
const MAX_PAGE_SIZE: usize = 200;
const WRITE_BATCH_SIZE: usize = 512;

#[derive(Clone, Default)]
pub struct InventoryRepository {
    inner: Arc<Mutex<RepositoryState>>,
}

#[derive(Default)]
struct RepositoryState {
    root: Option<PathBuf>,
    session_id: Option<String>,
    path: Option<PathBuf>,
    connection: Option<Connection>,
}

pub struct InventorySessionWriter<'a> {
    state: MutexGuard<'a, RepositoryState>,
    pending_writes: usize,
    transaction_open: bool,
}

impl InventoryRepository {
    pub fn initialize(&self, root: PathBuf) -> Result<(), String> {
        fs::create_dir_all(&root)
            .map_err(|error| format!("创建临时 inventory 目录失败：{error}"))?;
        remove_stale_files(&root)?;
        let mut state = self.lock();
        state.root = Some(root);
        Ok(())
    }

    pub fn start_session(
        &self,
        session_id: &str,
        selected_volumes: &[String],
    ) -> Result<InventorySessionWriter<'_>, String> {
        let mut state = self.lock();
        close_state(&mut state, true)?;
        let root = state
            .root
            .clone()
            .ok_or_else(|| "inventory repository 尚未初始化".to_string())?;
        if !is_valid_session_id(session_id) {
            return Err("inventory session id 无效".to_string());
        }
        let path = root.join(format!("{session_id}.sqlite3"));
        let connection =
            Connection::open(&path).map_err(|error| format!("创建临时 inventory 失败：{error}"))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|error| format!("配置 inventory busy timeout 失败：{error}"))?;
        create_schema(&connection)?;
        connection
            .execute(
                "INSERT INTO scan_session(id, schema_version, created_at, status, selected_volumes) VALUES(?1, ?2, unixepoch(), 'running', ?3)",
                params![session_id, SCHEMA_VERSION, selected_volumes.join(",")],
            )
            .map_err(db_error("创建 inventory session"))?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(db_error("开始 inventory transaction"))?;
        state.session_id = Some(session_id.to_string());
        state.path = Some(path);
        state.connection = Some(connection);
        Ok(InventorySessionWriter {
            state,
            pending_writes: 0,
            transaction_open: true,
        })
    }

    pub fn list_children(
        &self,
        session_id: &str,
        parent_entry_id: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
        sort: InventorySort,
    ) -> Result<InventoryPage, String> {
        let scope = parent_entry_id.unwrap_or("root");
        let offset = decode_cursor(cursor, session_id, "children", scope, sort)?;
        let state = self.lock();
        let connection = active_connection(&state, session_id)?;
        let order = sort_sql(sort);
        let parent_clause = if parent_entry_id.is_some() {
            "e.parent_entry_id = ?1"
        } else {
            "e.parent_entry_id IS NULL"
        };
        let sql = format!(
            "SELECT e.entry_id, e.parent_entry_id, e.volume_id, e.name, e.object_type, e.logical_bytes, e.allocated_bytes, e.disposition, e.allocation_owner, EXISTS(SELECT 1 FROM entry child WHERE child.parent_entry_id = e.entry_id) FROM entry e WHERE {parent_clause} ORDER BY {order} LIMIT ?2 OFFSET ?3"
        );
        query_page(
            connection,
            &sql,
            parent_entry_id.unwrap_or(""),
            PageQuery {
                session_id,
                kind: "children",
                scope,
                sort,
                offset,
                requested_limit: limit,
            },
        )
    }

    pub fn search(
        &self,
        session_id: &str,
        query: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<InventoryPage, String> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(InventoryPage::default());
        }
        let scope = short_hash(query);
        let sort = InventorySort::Name;
        let offset = decode_cursor(cursor, session_id, "search", &scope, sort)?;
        let state = self.lock();
        let connection = active_connection(&state, session_id)?;
        let pattern = format!("%{}%", escape_like(query));
        query_page(
            connection,
            "SELECT e.entry_id, e.parent_entry_id, e.volume_id, e.name, e.object_type, e.logical_bytes, e.allocated_bytes, e.disposition, e.allocation_owner, EXISTS(SELECT 1 FROM entry child WHERE child.parent_entry_id = e.entry_id) FROM entry e WHERE e.name LIKE ?1 ESCAPE '\\' COLLATE NOCASE ORDER BY e.name COLLATE NOCASE, e.entry_id LIMIT ?2 OFFSET ?3",
            &pattern,
            PageQuery {
                session_id,
                kind: "search",
                scope: &scope,
                sort,
                offset,
                requested_limit: limit,
            },
        )
    }

    pub fn list_largest(
        &self,
        session_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<InventoryPage, String> {
        let sort = InventorySort::AllocatedBytes;
        let offset = decode_cursor(cursor, session_id, "largest", "all", sort)?;
        let state = self.lock();
        let connection = active_connection(&state, session_id)?;
        query_page(
            connection,
            "SELECT e.entry_id, e.parent_entry_id, e.volume_id, e.name, e.object_type, e.logical_bytes, e.allocated_bytes, e.disposition, e.allocation_owner, EXISTS(SELECT 1 FROM entry child WHERE child.parent_entry_id = e.entry_id) FROM entry e WHERE e.object_type = 'file' ORDER BY e.allocated_bytes DESC, e.entry_id LIMIT ?2 OFFSET ?3",
            "",
            PageQuery {
                session_id,
                kind: "largest",
                scope: "all",
                sort,
                offset,
                requested_limit: limit,
            },
        )
    }

    pub fn close_session(&self, session_id: &str) -> Result<(), String> {
        let mut state = self.lock();
        if state.session_id.as_deref() != Some(session_id) {
            return Err("staleScanSession".to_string());
        }
        close_state(&mut state, true)
    }

    pub fn close_active(&self) -> Result<(), String> {
        close_state(&mut self.lock(), true)
    }

    fn lock(&self) -> MutexGuard<'_, RepositoryState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl InventorySessionWriter<'_> {
    pub fn finish(mut self, status: ScanCoverageStatus) -> Result<(), String> {
        self.commit_batch(false)?;
        let status = coverage_status_sql(status);
        let connection = self.connection()?;
        connection
            .execute(
                "UPDATE scan_session SET status = ?1 WHERE id = ?2",
                params![status, self.state.session_id.as_deref()],
            )
            .map_err(db_error("完成 inventory session"))?;
        connection
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_entry_parent ON entry(parent_entry_id);\
                 CREATE INDEX IF NOT EXISTS idx_entry_allocated ON entry(allocated_bytes DESC);\
                 CREATE INDEX IF NOT EXISTS idx_entry_name ON entry(name COLLATE NOCASE);\
                 CREATE INDEX IF NOT EXISTS idx_entry_identity ON entry(file_identity);",
            )
            .map_err(db_error("创建 inventory 查询索引"))
    }

    fn connection(&self) -> Result<&Connection, String> {
        self.state
            .connection
            .as_ref()
            .ok_or_else(|| "inventory connection 已关闭".to_string())
    }

    fn written(&mut self) -> Result<(), String> {
        self.pending_writes += 1;
        if self.pending_writes >= WRITE_BATCH_SIZE {
            self.commit_batch(true)?;
        }
        Ok(())
    }

    fn commit_batch(&mut self, reopen: bool) -> Result<(), String> {
        if self.transaction_open {
            self.connection()?
                .execute_batch("COMMIT")
                .map_err(db_error("提交 inventory transaction"))?;
            self.transaction_open = false;
        }
        self.pending_writes = 0;
        if reopen {
            self.connection()?
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(db_error("继续 inventory transaction"))?;
            self.transaction_open = true;
        }
        Ok(())
    }
}

impl InventorySink for InventorySessionWriter<'_> {
    fn write_entry(&mut self, entry: &InventoryEntry) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO entry(session_id, entry_id, volume_id, parent_entry_id, name, file_identity, object_type, logical_bytes, allocated_bytes, attributes, reparse_tag, disposition, allocation_owner) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    entry.scan_session_id,
                    entry.entry_id,
                    entry.volume_id,
                    entry.parent_entry_id,
                    entry.name,
                    entry.file_identity,
                    object_type_sql(entry.object_type),
                    to_i64(entry.logical_bytes),
                    to_i64(entry.allocated_bytes),
                    entry.attributes,
                    entry.reparse_tag,
                    disposition_sql(entry.disposition),
                    entry.allocation_owner,
                ],
            )
            .map_err(db_error("写入 inventory entry"))?;
        self.written()
    }

    fn write_directory_aggregate(&mut self, aggregate: &DirectoryAggregate) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT OR REPLACE INTO directory_aggregate(session_id, entry_id, subtree_logical_bytes, subtree_allocated_bytes, file_count, directory_count, analysis_only_count, blocked_count) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    aggregate.scan_session_id,
                    aggregate.entry_id,
                    to_i64(aggregate.subtree_logical_bytes),
                    to_i64(aggregate.subtree_allocated_bytes),
                    to_i64(aggregate.file_count),
                    to_i64(aggregate.directory_count),
                    to_i64(aggregate.analysis_only_count),
                    to_i64(aggregate.blocked_count),
                ],
            )
            .map_err(db_error("写入 directory aggregate"))?;
        self.written()
    }

    fn write_gap(&mut self, gap: &CoverageGap) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO coverage_gap(session_id, volume_id, reason, path_hint, count) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    self.state.session_id.as_deref(),
                    gap.volume_id,
                    format!("{:?}", gap.reason),
                    gap.path_hint,
                    to_i64(gap.count),
                ],
            )
            .map_err(db_error("写入 coverage gap"))?;
        self.written()
    }
}

impl Drop for InventorySessionWriter<'_> {
    fn drop(&mut self) {
        let _ = self.commit_batch(false);
    }
}

fn create_schema(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE;\
             PRAGMA synchronous=NORMAL;\
             PRAGMA temp_store=MEMORY;\
             CREATE TABLE scan_session(id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL, selected_volumes TEXT NOT NULL);\
             CREATE TABLE entry(session_id TEXT NOT NULL, entry_id TEXT PRIMARY KEY, volume_id TEXT NOT NULL, parent_entry_id TEXT, name TEXT NOT NULL, file_identity TEXT, object_type TEXT NOT NULL, logical_bytes INTEGER NOT NULL, allocated_bytes INTEGER NOT NULL, attributes INTEGER NOT NULL, reparse_tag INTEGER, disposition TEXT NOT NULL, allocation_owner INTEGER NOT NULL);\
             CREATE TABLE directory_aggregate(session_id TEXT NOT NULL, entry_id TEXT PRIMARY KEY, subtree_logical_bytes INTEGER NOT NULL, subtree_allocated_bytes INTEGER NOT NULL, file_count INTEGER NOT NULL, directory_count INTEGER NOT NULL, analysis_only_count INTEGER NOT NULL, blocked_count INTEGER NOT NULL);\
             CREATE TABLE coverage_gap(session_id TEXT NOT NULL, volume_id TEXT NOT NULL, reason TEXT NOT NULL, path_hint TEXT, count INTEGER NOT NULL);",
        )
        .map_err(db_error("创建 inventory schema"))
}

struct PageQuery<'a> {
    session_id: &'a str,
    kind: &'a str,
    scope: &'a str,
    sort: InventorySort,
    offset: usize,
    requested_limit: usize,
}

fn query_page(
    connection: &Connection,
    sql: &str,
    first_param: &str,
    query: PageQuery<'_>,
) -> Result<InventoryPage, String> {
    let limit = query.requested_limit.clamp(1, MAX_PAGE_SIZE);
    let mut statement = connection
        .prepare(sql)
        .map_err(db_error("准备 inventory 查询"))?;
    let rows = statement
        .query_map(
            params![first_param, (limit + 1) as i64, query.offset as i64],
            query_item_from_row,
        )
        .map_err(db_error("执行 inventory 查询"))?;
    let mut items = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error("读取 inventory 查询结果"))?;
    let has_more = items.len() > limit;
    items.truncate(limit);
    for item in &mut items {
        item.path = reconstruct_path(connection, &item.entry_id)?;
    }
    Ok(InventoryPage {
        next_cursor: has_more.then(|| {
            encode_cursor(
                query.session_id,
                query.kind,
                query.scope,
                query.sort,
                query.offset.saturating_add(limit),
            )
        }),
        items,
    })
}

fn query_item_from_row(row: &Row<'_>) -> rusqlite::Result<InventoryQueryItem> {
    let object_type: String = row.get(4)?;
    let disposition: String = row.get(7)?;
    Ok(InventoryQueryItem {
        entry_id: row.get(0)?,
        parent_entry_id: row.get(1)?,
        volume_id: row.get(2)?,
        name: row.get(3)?,
        path: String::new(),
        object_type: parse_object_type(&object_type),
        logical_bytes: from_i64(row.get(5)?),
        allocated_bytes: from_i64(row.get(6)?),
        disposition: parse_disposition(&disposition),
        allocation_owner: row.get(8)?,
        has_children: row.get(9)?,
    })
}

fn reconstruct_path(connection: &Connection, entry_id: &str) -> Result<String, String> {
    let mut parts = Vec::new();
    let mut current = Some(entry_id.to_string());
    let mut visited = std::collections::HashSet::new();
    while let Some(id) = current {
        if !visited.insert(id.clone()) {
            return Err("inventoryPathCycle".to_string());
        }
        let row = connection
            .query_row(
                "SELECT parent_entry_id, name FROM entry WHERE entry_id = ?1",
                params![id],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(db_error("重建 inventory 路径"))?;
        let Some((parent, name)) = row else { break };
        parts.push(name);
        current = parent;
    }
    parts.reverse();
    let mut path = PathBuf::new();
    for part in parts {
        path.push(part);
    }
    Ok(path.to_string_lossy().to_string())
}

fn active_connection<'a>(
    state: &'a RepositoryState,
    session_id: &str,
) -> Result<&'a Connection, String> {
    if state.session_id.as_deref() != Some(session_id) {
        return Err("staleScanSession".to_string());
    }
    state
        .connection
        .as_ref()
        .ok_or_else(|| "staleScanSession".to_string())
}

fn close_state(state: &mut RepositoryState, remove: bool) -> Result<(), String> {
    state.connection.take();
    state.session_id.take();
    let path = state.path.take();
    if remove {
        if let Some(path) = path {
            if path.exists() {
                fs::remove_file(&path)
                    .map_err(|error| format!("删除临时 inventory 失败：{error}"))?;
            }
        }
    }
    Ok(())
}

fn remove_stale_files(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|error| format!("读取 inventory 目录失败：{error}"))?
    {
        let entry = entry.map_err(|error| format!("读取 inventory 文件失败：{error}"))?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "sqlite3")
        {
            fs::remove_file(path).map_err(|error| format!("清理陈旧 inventory 失败：{error}"))?;
        }
    }
    Ok(())
}

fn encode_cursor(
    session_id: &str,
    kind: &str,
    scope: &str,
    sort: InventorySort,
    offset: usize,
) -> String {
    format!(
        "v1:{session_id}:{kind}:{}:{sort:?}:{offset}",
        short_hash(scope)
    )
}

fn decode_cursor(
    cursor: Option<&str>,
    session_id: &str,
    kind: &str,
    scope: &str,
    sort: InventorySort,
) -> Result<usize, String> {
    let Some(cursor) = cursor else { return Ok(0) };
    let prefix = format!("v1:{session_id}:{kind}:{}:{sort:?}:", short_hash(scope));
    cursor
        .strip_prefix(&prefix)
        .and_then(|offset| offset.parse().ok())
        .ok_or_else(|| "invalidInventoryCursor".to_string())
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sort_sql(sort: InventorySort) -> &'static str {
    match sort {
        InventorySort::Name => "e.name COLLATE NOCASE, e.entry_id",
        InventorySort::LogicalBytes => "e.logical_bytes DESC, e.entry_id",
        InventorySort::AllocatedBytes => "e.allocated_bytes DESC, e.entry_id",
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn is_valid_session_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

fn object_type_sql(value: InventoryObjectType) -> &'static str {
    match value {
        InventoryObjectType::File => "file",
        InventoryObjectType::Directory => "directory",
        InventoryObjectType::ReparsePoint => "reparsePoint",
        InventoryObjectType::Other => "other",
    }
}

fn parse_object_type(value: &str) -> InventoryObjectType {
    match value {
        "file" => InventoryObjectType::File,
        "directory" => InventoryObjectType::Directory,
        "reparsePoint" => InventoryObjectType::ReparsePoint,
        _ => InventoryObjectType::Other,
    }
}

fn disposition_sql(value: InventoryDisposition) -> &'static str {
    match value {
        InventoryDisposition::Normal => "normal",
        InventoryDisposition::AnalysisOnly => "analysisOnly",
        InventoryDisposition::Blocked => "blocked",
    }
}

fn parse_disposition(value: &str) -> InventoryDisposition {
    match value {
        "normal" => InventoryDisposition::Normal,
        "analysisOnly" => InventoryDisposition::AnalysisOnly,
        _ => InventoryDisposition::Blocked,
    }
}

fn coverage_status_sql(value: ScanCoverageStatus) -> &'static str {
    match value {
        ScanCoverageStatus::NotStarted => "notStarted",
        ScanCoverageStatus::Complete => "complete",
        ScanCoverageStatus::Partial => "partial",
        ScanCoverageStatus::Cancelled => "cancelled",
        ScanCoverageStatus::Failed => "failed",
    }
}

fn to_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn from_i64(value: i64) -> u64 {
    value.max(0) as u64
}

fn db_error(context: &'static str) -> impl FnOnce(rusqlite::Error) -> String {
    move |error| format!("{context}失败：{error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_bounded_and_cursor_is_bound_to_query_shape() {
        let root = test_root("pages");
        let repository = InventoryRepository::default();
        repository.initialize(root.clone()).expect("initialize");
        let session_id = uuid::Uuid::new_v4().to_string();
        let mut writer = repository
            .start_session(&session_id, &["TEST".to_string()])
            .expect("start session");
        writer
            .write_entry(&entry(&session_id, "1", None, "root", 0))
            .expect("root");
        for index in 0..5 {
            writer
                .write_entry(&entry(
                    &session_id,
                    &(index + 2).to_string(),
                    Some("1"),
                    &format!("file-{index}"),
                    index,
                ))
                .expect("entry");
        }
        writer.finish(ScanCoverageStatus::Complete).expect("finish");

        let first = repository
            .list_children(&session_id, Some("1"), None, 2, InventorySort::Name)
            .expect("first page");
        assert_eq!(first.items.len(), 2);
        let cursor = first.next_cursor.expect("next cursor");
        let second = repository
            .list_children(
                &session_id,
                Some("1"),
                Some(&cursor),
                2,
                InventorySort::Name,
            )
            .expect("second page");
        assert_eq!(second.items.len(), 2);
        assert_eq!(
            repository.list_largest(&session_id, Some(&cursor), 2),
            Err("invalidInventoryCursor".to_string())
        );
        repository.close_session(&session_id).expect("close");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn closing_session_makes_queries_stale_and_deletes_file() {
        let root = test_root("stale");
        let repository = InventoryRepository::default();
        repository.initialize(root.clone()).expect("initialize");
        let session_id = uuid::Uuid::new_v4().to_string();
        repository
            .start_session(&session_id, &[])
            .expect("start")
            .finish(ScanCoverageStatus::Complete)
            .expect("finish");
        repository.close_session(&session_id).expect("close");
        assert_eq!(
            repository.list_largest(&session_id, None, 20),
            Err("staleScanSession".to_string())
        );
        assert!(fs::read_dir(&root).expect("read root").next().is_none());
        let _ = fs::remove_dir_all(root);
    }

    fn entry(
        session_id: &str,
        entry_id: &str,
        parent_entry_id: Option<&str>,
        name: &str,
        allocated_bytes: u64,
    ) -> InventoryEntry {
        InventoryEntry {
            scan_session_id: session_id.to_string(),
            volume_id: "TEST".to_string(),
            entry_id: entry_id.to_string(),
            file_identity: Some(entry_id.to_string()),
            parent_entry_id: parent_entry_id.map(str::to_string),
            name: name.to_string(),
            object_type: if parent_entry_id.is_some() {
                InventoryObjectType::File
            } else {
                InventoryObjectType::Directory
            },
            logical_bytes: allocated_bytes,
            allocated_bytes,
            attributes: 0,
            reparse_tag: None,
            disposition: InventoryDisposition::Normal,
            allocation_owner: true,
        }
    }

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cleandeck-repository-{name}-{}",
            uuid::Uuid::new_v4()
        ))
    }
}
