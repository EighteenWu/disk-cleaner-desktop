import type {
  CleanupCandidate,
  CleanupPlan,
  CleanupReport,
  InventoryQueryItem,
  ScanSnapshot,
  SourceInfo
} from "./types";

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

function source(label: string, kind: SourceInfo["kind"], confidence = 90, evidence = "mock backend source"): SourceInfo {
  return { label, kind, confidence, evidence };
}

function defaultCleanupPolicy(): CleanupCandidate["cleanupPolicy"] {
  return {
    ruleId: null,
    method: "contents",
    keepDays: 0,
    excludePatterns: []
  };
}

export const mockSnapshot: ScanSnapshot = {
  volumes: [
    {
      id: "C",
      label: "System",
      mountPoint: "C:\\",
      filesystem: "NTFS",
      totalBytes: 476 * GiB,
      availableBytes: 142 * GiB,
      selected: true,
      supportsFastIndex: true
    },
    {
      id: "D",
      label: "Work",
      mountPoint: "D:\\",
      filesystem: "NTFS",
      totalBytes: 1800 * GiB,
      availableBytes: 628 * GiB,
      selected: true,
      supportsFastIndex: true
    },
    {
      id: "E",
      label: "Portable",
      mountPoint: "E:\\",
      filesystem: "exFAT",
      totalBytes: 512 * GiB,
      availableBytes: 218 * GiB,
      selected: false,
      supportsFastIndex: false
    }
  ],
  candidates: [
    {
      id: "chrome-cache",
      parentId: null,
      displayName: "Chrome Cache",
      path: "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache",
      volumeId: "C",
      objectType: "directory",
      category: "浏览器缓存",
      sizeBytes: 842 * MiB,
      childrenCount: 1842,
      riskLevel: "safeRecommended",
      defaultSelected: true,
      selected: true,
      deleteStrategy: "moveToRecycleBin",
      reason: "浏览器缓存，超过 7 天",
      confidence: 94,
      source: source("Google Chrome", "browser", 96),
      cleanupPolicy: defaultCleanupPolicy()
    },
    {
      id: "installer-rollback",
      parentId: null,
      displayName: "installer_unpack_rollback",
      path: "C:\\Users\\979\\AppData\\Local\\Temp\\setup-cache",
      volumeId: "C",
      objectType: "directory",
      category: "安装残留",
      sizeBytes: 1270 * MiB,
      childrenCount: 88,
      riskLevel: "safeRecommended",
      defaultSelected: true,
      selected: true,
      deleteStrategy: "moveToRecycleBin",
      reason: "临时安装缓存，超过 14 天",
      confidence: 88,
      source: source("未知来源", "unknown", 0),
      cleanupPolicy: defaultCleanupPolicy()
    },
    {
      id: "video-editor-cache",
      parentId: null,
      displayName: "video-editor-cache",
      path: "D:\\Media\\Cache\\PreviewRender",
      volumeId: "D",
      objectType: "directory",
      category: "应用缓存",
      sizeBytes: 2060 * MiB,
      childrenCount: 411,
      riskLevel: "cautiousRecommended",
      defaultSelected: false,
      selected: false,
      deleteStrategy: "moveToRecycleBin",
      reason: "应用预览缓存，最近 2 天修改",
      confidence: 68,
      source: source("未知来源", "unknown", 0),
      cleanupPolicy: defaultCleanupPolicy()
    },
    {
      id: "project-build-cache",
      parentId: null,
      displayName: "project-build-cache",
      path: "D:\\Work\\xyzw-app\\build\\cache",
      volumeId: "D",
      objectType: "directory",
      category: "项目目录",
      sizeBytes: 618 * MiB,
      childrenCount: 202,
      riskLevel: "reviewRequired",
      defaultSelected: false,
      selected: false,
      deleteStrategy: "moveToRecycleBin",
      reason: "项目目录缓存，需要确认构建上下文",
      confidence: 62,
      source: source("项目：xyzw-app", "project", 88),
      cleanupPolicy: defaultCleanupPolicy()
    },
    {
      id: "app-session-db",
      parentId: null,
      displayName: "app-session.db",
      path: "C:\\Users\\979\\AppData\\Roaming\\SomeApp\\session.db",
      volumeId: "C",
      objectType: "file",
      category: "应用配置",
      sizeBytes: 128 * MiB,
      childrenCount: 0,
      riskLevel: "blocked",
      defaultSelected: false,
      selected: false,
      deleteStrategy: "skip",
      reason: "Roaming 配置和会话数据库不可清理",
      confidence: 98,
      source: source("SomeApp", "installedApp", 68),
      cleanupPolicy: defaultCleanupPolicy()
    }
  ],
  selectedCandidateId: "chrome-cache",
  summary: {
    estimatedReclaimBytes: 2112 * MiB,
    candidateCount: 5,
    lockedCount: 1,
    progressPercent: 72,
    selectedCount: 2,
    selectedBytes: 2112 * MiB
  },
  scanBackend: "mock",
  warnings: [],
  scanSessionId: null,
  coverage: {
    status: "notStarted",
    visitedEntries: 0,
    indexedEntries: 0,
    logicalBytes: 0,
    allocatedBytes: 0,
    volumes: [],
    gaps: []
  },
  spaceSummary: []
};

export const mockInventoryItems: InventoryQueryItem[] = [
  {
    entryId: "users",
    parentEntryId: null,
    volumeId: "C",
    name: "Users",
    path: "C:\\Users",
    objectType: "directory",
    logicalBytes: 86 * GiB,
    allocatedBytes: 88 * GiB,
    disposition: "analysisOnly",
    allocationOwner: true,
    hasChildren: true
  },
  {
    entryId: "windows",
    parentEntryId: null,
    volumeId: "C",
    name: "Windows",
    path: "C:\\Windows",
    objectType: "directory",
    logicalBytes: 42 * GiB,
    allocatedBytes: 48 * GiB,
    disposition: "blocked",
    allocationOwner: true,
    hasChildren: true
  },
  {
    entryId: "temp-file",
    parentEntryId: null,
    volumeId: "C",
    name: "setup.tmp",
    path: "C:\\Windows\\Temp\\setup.tmp",
    objectType: "file",
    logicalBytes: 512 * MiB,
    allocatedBytes: 512 * MiB,
    disposition: "normal",
    allocationOwner: true,
    hasChildren: false
  }
];

export const mockChildren: CleanupCandidate[] = [
  {
    id: "chrome-cache-data",
    parentId: "chrome-cache",
    displayName: "Cache_Data",
    path: "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data",
    volumeId: "C",
    objectType: "directory",
    category: "浏览器缓存",
    sizeBytes: 612 * MiB,
    childrenCount: 1203,
    riskLevel: "safeRecommended",
    defaultSelected: true,
    selected: true,
    deleteStrategy: "moveToRecycleBin",
    reason: "Chrome cache child directory",
    confidence: 92,
    source: source("Google Chrome", "browser", 96),
    cleanupPolicy: defaultCleanupPolicy()
  },
  {
    id: "chrome-code-cache",
    parentId: "chrome-cache",
    displayName: "Code Cache",
    path: "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\Code Cache",
    volumeId: "C",
    objectType: "directory",
    category: "浏览器缓存",
    sizeBytes: 148 * MiB,
    childrenCount: 331,
    riskLevel: "safeRecommended",
    defaultSelected: true,
    selected: true,
    deleteStrategy: "moveToRecycleBin",
    reason: "Chrome code cache",
    confidence: 92,
    source: source("Google Chrome", "browser", 96),
    cleanupPolicy: defaultCleanupPolicy()
  },
  {
    id: "chrome-index-dir",
    parentId: "chrome-cache",
    displayName: "index-dir",
    path: "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\index-dir",
    volumeId: "C",
    objectType: "directory",
    category: "浏览器缓存",
    sizeBytes: 82 * MiB,
    childrenCount: 44,
    riskLevel: "safeRecommended",
    defaultSelected: true,
    selected: true,
    deleteStrategy: "moveToRecycleBin",
    reason: "Chrome cache index",
    confidence: 92,
    source: source("Google Chrome", "browser", 96),
    cleanupPolicy: defaultCleanupPolicy()
  }
];

export const mockCleanupPlan: CleanupPlan = {
  selectedCount: 2,
  skippedLockedCount: 1,
  estimatedReclaimBytes: 2112 * MiB,
  deleteStrategy: "moveToRecycleBin",
  warnings: ["清理前会重新校验对象状态，目录会展开为具体子项执行。"]
};

export const mockCleanupReport: CleanupReport = {
  requestedCount: 2,
  cleanedCount: 2,
  skippedLockedCount: 0,
  failedCount: 0,
  cancelled: false,
  reclaimedBytes: 2112 * MiB,
  cleanedIds: ["chrome-cache", "installer-rollback"],
  skippedIds: [],
  failedIds: [],
  deleteStrategy: "moveToRecycleBin",
  warnings: ["浏览器预览模式下使用模拟结果；Tauri 桌面应用会移动到 Windows 回收站。"],
  itemResults: [
    {
      id: "chrome-cache",
      displayName: "Chrome Cache",
      path: "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache",
      source: source("Google Chrome", "browser", 96),
      status: "cleaned",
      reclaimedBytes: 842 * MiB,
      reason: "符合清理条件，已移动到 Windows 回收站。"
    },
    {
      id: "installer-rollback",
      displayName: "installer_unpack_rollback",
      path: "C:\\Users\\979\\AppData\\Local\\Temp\\setup-cache",
      source: source("未知来源", "unknown", 0),
      status: "cleaned",
      reclaimedBytes: 1270 * MiB,
      reason: "符合清理条件，已移动到 Windows 回收站。"
    }
  ]
};
