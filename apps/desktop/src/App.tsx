import {
  ExternalLink,
  File,
  FileText,
  Folder,
  Languages,
  Monitor,
  Moon,
  Pause,
  Play,
  RefreshCw,
  Search,
  Settings,
  Shield,
  Sun,
  Trash2,
  X
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getCurrentWindow, type Theme } from "@tauri-apps/api/window";
import appLogoUrl from "./assets/diskclean-logo.png";
import {
  cancelCleanup,
  clearRuleSubscriptionCache,
  compileRuleSubscriptionContent,
  executeCleanupPlan,
  getAdminStatus,
  getScanSnapshot,
  importWinapp2Rules,
  loadRuleSubscriptionWithContent,
  listenCleanupProgress,
  listCandidateChildren,
  notifyScanComplete,
  pauseCleanup,
  pauseScan,
  readAppLogs,
  readRuleSubscriptionCache,
  restartAsAdmin,
  revealPath,
  resumeCleanup,
  resumeScan,
  runScan,
  validateRulesYaml,
  writeAppLogs,
  writeRuleSubscriptionCache
} from "./api";
import {
  allCleanableSelected,
  canOpenChildren,
  cleanupPreviewSummary,
  cleanupStatusClass,
  filterCandidates,
  formatBytes,
  isCleanupSelectable,
  mergeRefreshedVolumes,
  removeCandidates,
  riskClass,
  scanControlForStatus,
  scopeCandidatesToVolumes,
  selectedCandidateCategories,
  selectedCandidateIds,
  selectedSummary,
  selectedVolumeIds,
  setCandidateSelection,
  toggleCandidate,
  toggleVolume,
  visibleWindowForList
} from "./state";
import {
  createTranslator,
  languageOptions,
  localizedCleanupStatusLabel,
  localizedDeleteStrategy,
  localizedLogKindLabel,
  localizedObjectType,
  localizedProgressStatus,
  localizedRiskLabel,
  localizedScanControlLabel,
  localizedScanStatusLabel,
  localizeSourceLabel,
  readStoredLanguage,
  storeLanguage,
  translate,
  translateCategory,
  translateReason,
  type LanguageCode
} from "./i18n";
import {
  createStoredRuleSubscription,
  readStoredRuleSubscription
} from "./ruleSubscriptionStorage";
import type {
  AppLogEntry,
  AppLogKind,
  AdminStatus,
  CleanupCandidate,
  CleanupReportItem,
  CleanupProgress,
  CleanupReport,
  CleanupStatus,
  DeleteStrategy,
  LogFilter,
  RuleCompilation,
  RuleValidationReport,
  RiskFilter,
  ScanMode,
  ScanSnapshot,
  ScanStatus
} from "./types";

const LOG_STORAGE_KEY = "diskclean.logs.v1";
const THEME_STORAGE_KEY = "diskclean.theme.v1";
const MAX_LOG_ENTRIES = 500;
const CANDIDATE_ROW_HEIGHT = 68;
const CANDIDATE_ROW_OVERSCAN = 8;
const RULE_SUBSCRIPTION_REFRESH_INTERVAL_MS = 12 * 60 * 60 * 1000;
const RULE_SUBSCRIPTION_STARTUP_REFRESH_DELAY_MS = 3000;
const DEFAULT_RULE_SUBSCRIPTION_URL = "https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini";
type ThemeMode = "system" | "light" | "dark";
type RuleSubscriptionRefreshReason = "manual" | "startup" | "scheduled";
const THEME_SEQUENCE: ThemeMode[] = ["system", "light", "dark"];
const EMPTY_CLEANUP_PROGRESS: CleanupProgress = {
  processedCount: 0,
  totalCount: 0,
  percent: 0,
  currentId: "",
  currentPath: "",
  status: "preparing"
};
const DEFAULT_RULE_YAML = `version: 1
name: DiskClean conservative default rules
publisher: DiskClean
rules:
  - id: user.temp
    name: 用户临时目录
    app: Windows
    category: 临时文件
    level: 推荐清理
    default: true
    paths:
      - "%TEMP%"
    clean: contents
    keep_days: 3
    note: 仅作为规则示例。运行态仍会跳过系统保护路径、状态数据和应用运行依赖。

  - id: chrome.cache
    name: Chrome 缓存
    app: Google Chrome
    category: 浏览器缓存
    level: 推荐清理
    default: true
    paths:
      - "%LOCALAPPDATA%\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Cache"
    clean: contents
    keep_days: 3
    close:
      - chrome.exe
    note: 浏览器缓存可重新生成；浏览器运行中或命中 profile/数据库数据时会跳过。

  - id: npm.cache.review
    name: npm 下载缓存
    app: npm
    category: 开发依赖缓存
    level: 需要确认
    default: false
    paths:
      - "%LOCALAPPDATA%\\\\npm-cache"
    clean: contents
    keep_days: 14
    close:
      - node.exe
      - npm.exe
    note: 依赖缓存删除后可重新下载，但会影响离线构建和下次安装速度，默认不勾选。`;

export function App() {
  const [language, setLanguage] = useState<LanguageCode>(() => readStoredLanguage());
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => readStoredThemeMode());
  const t = useMemo(() => createTranslator(language), [language]);
  const [snapshot, setSnapshot] = useState<ScanSnapshot | null>(null);
  const [selectedId, setSelectedId] = useState<string>("chrome-cache");
  const [children, setChildren] = useState<CleanupCandidate[]>([]);
  const [childrenLoading, setChildrenLoading] = useState(false);
  const [cleanupDialogOpen, setCleanupDialogOpen] = useState(false);
  const [cleanupStatus, setCleanupStatus] = useState<CleanupStatus>("idle");
  const [cleanupProgress, setCleanupProgress] = useState<CleanupProgress>(EMPTY_CLEANUP_PROGRESS);
  const [driveDialogOpen, setDriveDialogOpen] = useState(false);
  const [logsDialogOpen, setLogsDialogOpen] = useState(false);
  const [rulesDialogOpen, setRulesDialogOpen] = useState(false);
  const [logFilter, setLogFilter] = useState<LogFilter>("all");
  const [logs, setLogs] = useState<AppLogEntry[]>(() => [
    createLogEntry("operation", "应用启动", "DiskClean 已加载。")
  ]);
  const [logsHydrated, setLogsHydrated] = useState(false);
  const [adminStatus, setAdminStatus] = useState<AdminStatus | null>(null);
  const [lastReport, setLastReport] = useState<CleanupReport | null>(null);
  const [focusedCandidate, setFocusedCandidate] = useState<CleanupCandidate | null>(null);
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [scanMode, setScanMode] = useState<ScanMode>("quick");
  const [scanStatus, setScanStatus] = useState<ScanStatus>("idle");
  const [scanProgress, setScanProgress] = useState(72);
  const [scanStartedAt, setScanStartedAt] = useState<number | null>(null);
  const [scanElapsedMs, setScanElapsedMs] = useState(0);
  const [permanentDelete, setPermanentDelete] = useState(false);
  const [cleanupStartedAt, setCleanupStartedAt] = useState<number | null>(null);
  const [cleanupElapsedMs, setCleanupElapsedMs] = useState(0);
  const [volumesRefreshing, setVolumesRefreshing] = useState(false);
  const [tableScrollTop, setTableScrollTop] = useState(0);
  const [tableViewportHeight, setTableViewportHeight] = useState(420);
  const [showSelectedOnly, setShowSelectedOnly] = useState(false);
  const [notice, setNotice] = useState(() => t("app.ready"));
  const [toastVisible, setToastVisible] = useState(false);
  const [ruleYaml, setRuleYaml] = useState(DEFAULT_RULE_YAML);
  const [ruleCompilation, setRuleCompilation] = useState<RuleCompilation | null>(null);
  const [subscriptionLoadedFromCache, setSubscriptionLoadedFromCache] = useState(false);
  const [subscriptionUrl, setSubscriptionUrl] = useState(DEFAULT_RULE_SUBSCRIPTION_URL);
  const [subscriptionReport, setSubscriptionReport] = useState<RuleValidationReport | null>(null);
  const [subscriptionCompilation, setSubscriptionCompilation] = useState<RuleCompilation | null>(null);
  const initialSnapshotLoaded = useRef(false);
  const subscriptionRefreshInFlight = useRef(false);
  const subscriptionStartupRefreshQueued = useRef(false);
  const tableAreaRef = useRef<HTMLDivElement | null>(null);

  const appendLog = useCallback((kind: AppLogKind, title: string, message: string, detail?: string) => {
    setLogs((currentLogs) =>
      [createLogEntry(kind, title, message, detail), ...currentLogs].slice(0, MAX_LOG_ENTRIES)
    );
  }, []);

  function clearLogs() {
    setLogs([createLogEntry("operation", "清空日志", "已清空历史日志。")]);
  }

  const refreshSubscriptionRules = useCallback(
    async (reason: RuleSubscriptionRefreshReason) => {
      const trimmedUrl = subscriptionUrl.trim();
      const currentValidCompilation = subscriptionCompilation?.report.valid ? subscriptionCompilation : null;

      if (!trimmedUrl) {
        if (reason === "manual") {
          await clearRuleSubscriptionCache();
          setSubscriptionCompilation(null);
          setSubscriptionReport(null);
          setSubscriptionLoadedFromCache(false);
          setNotice("订阅规则已停用。");
          appendLog("operation", "停用规则订阅", "已清空订阅链接和本地缓存。");
        }
        return;
      }

      if (subscriptionRefreshInFlight.current) {
        return;
      }

      subscriptionRefreshInFlight.current = true;
      if (reason === "manual") {
        setNotice("正在加载订阅规则。");
      }

      try {
        const result = await loadRuleSubscriptionWithContent(trimmedUrl);
        setSubscriptionReport(result.compilation.report);

        if (!result.compilation.report.valid || result.content === null) {
          if (!currentValidCompilation) {
            setSubscriptionCompilation(null);
          }

          const message =
            reason === "manual" ? "订阅规则加载失败。" : "订阅规则自动检查失败，继续使用上一次有效规则。";
          if (reason === "manual") {
            setNotice(message);
          }
          appendLog("operation", ruleSubscriptionLogTitle(reason, false), message, trimmedUrl);
          return;
        }

        const changed = ruleCompilationChanged(currentValidCompilation, result.compilation);
        const stored = createStoredRuleSubscription(trimmedUrl, result.content);
        const saved = await writeRuleSubscriptionCache(stored);
        const message =
          reason === "manual"
            ? `订阅规则已加载：${result.compilation.report.ruleCount} 条。`
            : changed
              ? `订阅规则已更新：${result.compilation.report.ruleCount} 条。`
              : `订阅规则已检查，无变化：${result.compilation.report.ruleCount} 条。`;

        setSubscriptionCompilation(result.compilation);
        setSubscriptionLoadedFromCache(false);
        setSubscriptionUrl(trimmedUrl);
        if (reason === "manual" || changed) {
          setNotice(saved ? message : `${message} 本地缓存保存失败。`);
        }
        appendLog(
          "operation",
          ruleSubscriptionLogTitle(reason, true),
          saved ? message : `${message} 本地缓存保存失败。`,
          trimmedUrl
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (!currentValidCompilation) {
          setSubscriptionCompilation(null);
        }
        setSubscriptionReport({
          valid: false,
          ruleCount: 0,
          errors: [{ ruleId: null, field: "url", message }],
          warnings: []
        });
        if (reason === "manual") {
          setNotice(`订阅规则加载失败：${message}`);
        }
        appendLog("operation", ruleSubscriptionLogTitle(reason, false), message, trimmedUrl);
      } finally {
        subscriptionRefreshInFlight.current = false;
      }
    },
    [appendLog, subscriptionCompilation, subscriptionUrl]
  );

  useEffect(() => {
    storeLanguage(language);
    document.documentElement.lang = language;
    document.title = t("app.name");
    setNotice(t("app.ready"));
  }, [language, t]);

  useEffect(() => {
    storeThemeMode(themeMode);
    document.documentElement.dataset.theme = themeMode;
    void syncNativeWindowTheme(themeMode);
  }, [themeMode]);

  useEffect(() => {
    let disposed = false;

    async function restoreRuleSubscription() {
      const persistedSubscription = await readRuleSubscriptionCache();
      const legacySubscription = persistedSubscription ?? readStoredRuleSubscription();
      if (!legacySubscription) {
        return;
      }

      if (!persistedSubscription) {
        await writeRuleSubscriptionCache(legacySubscription);
      }

      const compilation = await compileRuleSubscriptionContent(
        legacySubscription.url,
        legacySubscription.content
      );

      if (disposed) {
        return;
      }

      setSubscriptionUrl(legacySubscription.url);
      setSubscriptionReport(compilation.report);
      if (compilation.report.valid) {
        setSubscriptionCompilation(compilation);
        setSubscriptionLoadedFromCache(true);
        appendLog(
          "operation",
          "恢复规则订阅",
          `已恢复 ${compilation.report.ruleCount} 条订阅规则。`,
          legacySubscription.url
        );
        return;
      }

      await clearRuleSubscriptionCache();
      setSubscriptionCompilation(null);
      setSubscriptionLoadedFromCache(false);
      appendLog("operation", "恢复规则订阅失败", "缓存规则已失效，已停用。", legacySubscription.url);
    }

    void restoreRuleSubscription().catch((error) => {
      if (disposed) {
        return;
      }

      const message = error instanceof Error ? error.message : String(error);
      setSubscriptionCompilation(null);
      setSubscriptionLoadedFromCache(false);
      setSubscriptionReport({
        valid: false,
        ruleCount: 0,
        errors: [{ ruleId: null, field: "content", message }],
        warnings: []
      });
      appendLog("operation", "恢复规则订阅失败", message);
    });

    return () => {
      disposed = true;
    };
  }, [appendLog]);

  useEffect(() => {
    if (!subscriptionCompilation?.report.valid || subscriptionUrl.trim().length === 0) {
      return;
    }

    let startupTimerId: number | undefined;
    if (subscriptionLoadedFromCache && !subscriptionStartupRefreshQueued.current) {
      subscriptionStartupRefreshQueued.current = true;
      startupTimerId = window.setTimeout(() => {
        void refreshSubscriptionRules("startup");
      }, RULE_SUBSCRIPTION_STARTUP_REFRESH_DELAY_MS);
    }

    const intervalId = window.setInterval(() => {
      void refreshSubscriptionRules("scheduled");
    }, RULE_SUBSCRIPTION_REFRESH_INTERVAL_MS);

    return () => {
      if (startupTimerId !== undefined) {
        window.clearTimeout(startupTimerId);
      }
      window.clearInterval(intervalId);
    };
  }, [refreshSubscriptionRules, subscriptionCompilation?.report.valid, subscriptionLoadedFromCache, subscriptionUrl]);

  useEffect(() => {
    if (!notice || notice === t("app.ready")) {
      setToastVisible(false);
      return;
    }

    setToastVisible(true);
    const timeoutId = window.setTimeout(
      () => setToastVisible(false),
      notice.length > 72 ? 6500 : 4200
    );

    return () => window.clearTimeout(timeoutId);
  }, [notice, t]);

  useEffect(() => {
    if (initialSnapshotLoaded.current) {
      return;
    }

    initialSnapshotLoaded.current = true;
    void getScanSnapshot().then((nextSnapshot) => {
      setSnapshot(nextSnapshot);
      setSelectedId(nextSnapshot.selectedCandidateId);
      setScanProgress(nextSnapshot.summary.progressPercent);
      appendLog(
        "scan",
        "加载盘符信息",
        `已加载 ${nextSnapshot.volumes.length} 个盘符；未执行扫描。`,
        `后端：${nextSnapshot.scanBackend}`
      );
    });
  }, []);

  useEffect(() => {
    void getAdminStatus().then(setAdminStatus);
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;

    void listenCleanupProgress((progress) => {
      if (disposed) {
        return;
      }

      setCleanupProgress(progress);
      setCleanupStatus((currentStatus) => {
        if (currentStatus === "canceling" || currentStatus === "cancelled" || currentStatus === "complete") {
          return currentStatus;
        }

        if (progress.status === "paused") {
          return "paused";
        }

        if (progress.status === "canceled") {
          return "canceling";
        }

        if (progress.status === "preparing" || progress.status === "cleaning") {
          return "running";
        }

        return currentStatus;
      });
      if (progress.status !== "complete") {
        const total = progress.totalCount || 0;
        const currentPath = progress.currentPath ? ` · ${progress.currentPath}` : "";
        setNotice(`${localizedProgressStatus(language, progress.status)}：${progress.processedCount}/${total}${currentPath}`);
      }
    })
      .then((nextUnlisten) => {
        if (disposed) {
          nextUnlisten();
        } else {
          unlisten = nextUnlisten;
        }
      })
      .catch((error) => {
        if (disposed) {
          return;
        }

        const message = error instanceof Error ? error.message : String(error);
        setNotice(`清理进度监听失败：${message}`);
        appendLog("cleanup", "清理进度监听失败", message);
      });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [language]);

  useEffect(() => {
    let disposed = false;

    void readAppLogs()
      .then((storedLogs) => {
        if (disposed) {
          return;
        }

        const legacyLogs = storedLogs.length > 0 ? [] : readStoredLogs();
        const persistedLogs = storedLogs.length > 0 ? storedLogs : legacyLogs;
        setLogs((currentLogs) => mergeLogEntries(currentLogs, persistedLogs));
        setLogsHydrated(true);
      })
      .catch((error) => {
        if (disposed) {
          return;
        }

        const message = error instanceof Error ? error.message : String(error);
        setLogs((currentLogs) =>
          mergeLogEntries(currentLogs, [
            createLogEntry("operation", "加载日志失败", message)
          ])
        );
        setLogsHydrated(true);
      });

    return () => {
      disposed = true;
    };
  }, []);

  useEffect(() => {
    if (!logsHydrated) {
      return;
    }

    void writeAppLogs(logs.slice(0, MAX_LOG_ENTRIES)).then((saved) => {
      if (saved) {
        clearStoredLogs();
      }
    });
  }, [logs, logsHydrated]);

  useEffect(() => {
    if (scanStatus !== "scanning") {
      return;
    }

    setScanProgress((currentProgress) => (currentProgress <= 0 ? 8 : currentProgress));
    const timerId = window.setInterval(() => {
      setScanProgress((currentProgress) => Math.min(95, currentProgress + (currentProgress < 60 ? 7 : 2)));
    }, 600);

    return () => window.clearInterval(timerId);
  }, [scanStatus]);

  useEffect(() => {
    if (scanStatus !== "scanning" || scanStartedAt === null) {
      return;
    }

    const timerId = window.setInterval(() => {
      setScanElapsedMs(Date.now() - scanStartedAt);
    }, 250);

    return () => window.clearInterval(timerId);
  }, [scanStartedAt, scanStatus]);

  useEffect(() => {
    if (
      (cleanupStatus !== "running" && cleanupStatus !== "paused" && cleanupStatus !== "canceling") ||
      cleanupStartedAt === null
    ) {
      return;
    }

    const timerId = window.setInterval(() => {
      setCleanupElapsedMs(Date.now() - cleanupStartedAt);
    }, 250);

    return () => window.clearInterval(timerId);
  }, [cleanupStartedAt, cleanupStatus]);

  useEffect(() => {
    const tableArea = tableAreaRef.current;
    if (!tableArea) {
      return;
    }

    const updateTableHeight = () => setTableViewportHeight(tableArea.clientHeight || 420);
    updateTableHeight();

    const resizeObserver = new ResizeObserver(updateTableHeight);
    resizeObserver.observe(tableArea);

    return () => resizeObserver.disconnect();
  }, []);

  const candidates = snapshot?.candidates ?? [];
  const volumes = snapshot?.volumes ?? [];
  const selectedVolumeSet = useMemo(() => selectedVolumeIds(volumes), [volumes]);
  const activeCandidates = useMemo(
    () => scopeCandidatesToVolumes(candidates, selectedVolumeSet),
    [candidates, selectedVolumeSet]
  );
  const current =
    focusedCandidate ?? activeCandidates.find((candidate) => candidate.id === selectedId) ?? activeCandidates[0] ?? candidates[0];
  const summary = useMemo(() => selectedSummary(activeCandidates), [activeCandidates]);
  const selectedCategoryNames = useMemo(() => selectedCandidateCategories(activeCandidates), [activeCandidates]);
  const visibleCandidates = useMemo(
    () => (showSelectedOnly ? activeCandidates.filter((candidate) => candidate.selected) : activeCandidates),
    [activeCandidates, showSelectedOnly]
  );
  const filteredCandidates = useMemo(
    () => filterCandidates(visibleCandidates, query, riskFilter, selectedCategoryNames),
    [query, riskFilter, selectedCategoryNames, visibleCandidates]
  );
  const virtualWindow = useMemo(
    () =>
      visibleWindowForList(
        filteredCandidates.length,
        tableScrollTop,
        tableViewportHeight,
        CANDIDATE_ROW_HEIGHT,
        CANDIDATE_ROW_OVERSCAN
      ),
    [filteredCandidates.length, tableScrollTop, tableViewportHeight]
  );
  const renderedCandidates = useMemo(
    () => filteredCandidates.slice(virtualWindow.startIndex, virtualWindow.endIndex),
    [filteredCandidates, virtualWindow.endIndex, virtualWindow.startIndex]
  );
  const selectedDrives = volumes.filter((volume) => volume.selected).map((volume) => `${volume.id}:`);
  const currentSelectedIds = useMemo(() => selectedCandidateIds(activeCandidates), [activeCandidates]);
  const cleanupDeleteStrategy: Exclude<DeleteStrategy, "skip"> = permanentDelete ? "permanentDelete" : "moveToRecycleBin";
  const cleanupPlan = useMemo(
    () => cleanupPreviewSummary(activeCandidates, cleanupDeleteStrategy),
    [activeCandidates, cleanupDeleteStrategy]
  );
  const cleanupDeleteMethodLabel = localizedDeleteStrategy(language, cleanupDeleteStrategy);
  const cleanupInProgress = cleanupStatus === "running" || cleanupStatus === "paused" || cleanupStatus === "canceling";
  const scanInProgress = scanStatus === "scanning" || scanStatus === "paused";
  const visibleAllSelected = useMemo(() => allCleanableSelected(filteredCandidates), [filteredCandidates]);
  const backendLabel = snapshot?.scanBackend ?? "unknown";
  const scanStatusLabel = localizedScanStatusLabel(language, scanStatus);
  const scanProgressLabel = scanStatus === "scanning" ? scanStatusLabel : `${scanProgress}%`;
  const scanControl = scanControlForStatus(scanStatus);
  const scanControlLabel = localizedScanControlLabel(language, scanControl.action);
  const themeLabel = t(themeLabelKey(themeMode));
  const ThemeIcon = themeMode === "dark" ? Moon : themeMode === "light" ? Sun : Monitor;
  const scanWarnings = snapshot?.warnings ?? [];
  const currentPathLabel = current?.path ?? "-";
  const filteredLogs = useMemo(
    () => (logFilter === "all" ? logs : logs.filter((log) => log.kind === logFilter)),
    [logFilter, logs]
  );

  useEffect(() => {
    if (!current || !canOpenChildren(current)) {
      setChildren([]);
      setChildrenLoading(false);
      return;
    }

    let disposed = false;
    setChildrenLoading(true);
    void listCandidateChildren(current)
      .then((nextChildren) => {
        if (!disposed) {
          setChildren(nextChildren);
        }
      })
      .catch((error) => {
        if (disposed) {
          return;
        }

        setChildren([]);
        appendLog(
          "operation",
          "读取目录失败",
          current.path,
          error instanceof Error ? error.message : String(error)
        );
      })
      .finally(() => {
        if (!disposed) {
          setChildrenLoading(false);
        }
      });

    return () => {
      disposed = true;
    };
  }, [
    appendLog,
    current?.category,
    current?.cleanupPolicy.excludePatterns,
    current?.cleanupPolicy.keepDays,
    current?.cleanupPolicy.method,
    current?.cleanupPolicy.ruleId,
    current?.deleteStrategy,
    current?.id,
    current?.objectType,
    current?.path,
    current?.reason,
    current?.riskLevel
  ]);

  useEffect(() => {
    if (focusedCandidate) {
      return;
    }

    if (!snapshot || activeCandidates.length === 0) {
      return;
    }

    if (!activeCandidates.some((candidate) => candidate.id === selectedId)) {
      setSelectedId(activeCandidates[0].id);
    }
  }, [activeCandidates, focusedCandidate, selectedId, snapshot]);

  useEffect(() => {
    setTableScrollTop(0);
    if (tableAreaRef.current) {
      tableAreaRef.current.scrollTop = 0;
    }
  }, [activeCandidates.length, query, riskFilter, selectedCategoryNames, showSelectedOnly]);

  function updateCandidateSelection(candidateId: string) {
    if (!snapshot) {
      return;
    }

    const candidate = snapshot.candidates.find((item) => item.id === candidateId);
    setSnapshot({
      ...snapshot,
      candidates: toggleCandidate(snapshot.candidates, candidateId)
    });
    if (candidate) {
      appendLog("operation", "切换候选勾选", candidate.displayName, candidate.path);
    }
  }

  function updateVisibleSelection() {
    if (!snapshot || filteredCandidates.length === 0) {
      return;
    }

    const candidateIds = filteredCandidates.map((candidate) => candidate.id);
    const shouldSelect = !visibleAllSelected;

    setSnapshot({
      ...snapshot,
      candidates: setCandidateSelection(snapshot.candidates, candidateIds, shouldSelect)
    });
    setNotice(shouldSelect ? "已选择当前结果中的可清理项。" : "已取消当前结果中的可清理项。");
    appendLog(
      "operation",
      shouldSelect ? "全选当前结果" : "取消当前结果",
      `${filteredCandidates.length} 个可见候选已更新。`
    );
  }

  function updateCategorySelection(category: string) {
    if (!snapshot) {
      return;
    }

    const categoryCandidates: CleanupCandidate[] = [];
    const categoryCandidateIds: string[] = [];
    let cleanableCount = 0;
    let hasSelectedCleanable = false;

    for (const candidate of activeCandidates) {
      if (candidate.category !== category) {
        continue;
      }

      categoryCandidates.push(candidate);
      categoryCandidateIds.push(candidate.id);
      if (isCleanupSelectable(candidate)) {
        cleanableCount += 1;
        hasSelectedCleanable = hasSelectedCleanable || candidate.selected;
      }
    }

    if (cleanableCount === 0) {
      setNotice("该分类没有可选择的清理项。");
      return;
    }

    const shouldSelect = !hasSelectedCleanable;

    setSnapshot({
      ...snapshot,
      candidates: setCandidateSelection(snapshot.candidates, categoryCandidateIds, shouldSelect)
    });
    setNotice(`${shouldSelect ? "已选择" : "已取消"}「${category}」分类中的可清理项。`);
    appendLog(
      "operation",
      shouldSelect ? "选择分类" : "取消分类",
      `${category}：${categoryCandidates.length} 个候选。`
    );
  }

  function updateVolumeSelection(volumeId: string) {
    if (!snapshot) {
      return;
    }

    setSnapshot({
      ...snapshot,
      volumes: toggleVolume(snapshot.volumes, volumeId)
    });
    setFocusedCandidate(null);
    appendLog("operation", "切换盘符", `${volumeId}: 已切换选择状态。`);
  }

  async function refreshVolumes() {
    if (scanInProgress) {
      setNotice("扫描正在运行，完成后再刷新。");
      return;
    }

    try {
      setVolumesRefreshing(true);
      setNotice("正在刷新盘符...");
      await waitForNextPaint();

      const nextSnapshot = await getScanSnapshot();
      const refreshedVolumes = snapshot
        ? mergeRefreshedVolumes(snapshot.volumes, nextSnapshot.volumes)
        : nextSnapshot.volumes;
      const nextSelectedId =
        snapshot?.candidates.some((candidate) => candidate.id === selectedId) ? selectedId : nextSnapshot.selectedCandidateId;

      setSnapshot(
        snapshot
          ? {
              ...snapshot,
              volumes: refreshedVolumes,
              warnings: nextSnapshot.warnings
            }
          : {
              ...nextSnapshot,
              volumes: refreshedVolumes
            }
      );
      setSelectedId(nextSelectedId);
      setFocusedCandidate(null);
      setNotice(`盘符已刷新：${refreshedVolumes.length} 个。`);
      appendLog(
        "scan",
        "刷新盘符",
        `已刷新 ${refreshedVolumes.length} 个盘符。`,
        nextSnapshot.warnings.join("\n") || undefined
      );
    } catch (error) {
      setNotice(`刷新盘符失败：${error instanceof Error ? error.message : String(error)}`);
      appendLog("scan", "刷新失败", error instanceof Error ? error.message : String(error));
    } finally {
      setVolumesRefreshing(false);
    }
  }

  async function startScan() {
    if (scanInProgress) {
      setNotice("已有扫描任务正在运行。");
      return;
    }

    const volumeIds = snapshot ? Array.from(selectedVolumeIds(snapshot.volumes)) : [];
    const activeRules = [
      ...(ruleCompilation?.report.valid ? ruleCompilation.rules : []),
      ...(subscriptionCompilation?.report.valid ? subscriptionCompilation.rules : [])
    ];
    const request = { mode: scanMode, volumeIds, rules: activeRules };
    const startedAt = Date.now();
    const scanModeLabel = scanMode === "quick" ? "快速扫描" : "全盘分析";

    setChildren([]);
    setFocusedCandidate(null);
    setCleanupDialogOpen(false);
    setLastReport(null);
    setScanProgress(0);
    setScanStartedAt(startedAt);
    setScanElapsedMs(0);
    setScanStatus("scanning");
    setNotice(`${scanModeLabel}正在执行真实后端扫描。`);
    appendLog(
      "scan",
      scanMode === "quick" ? "开始快速扫描" : "开始全盘分析",
      `盘符：${volumeIds.length > 0 ? volumeIds.join(", ") : "默认"}；自定义规则：${activeRules.length} 条`
    );

    try {
      await waitForNextPaint();
      const nextSnapshot = await runScan(request);

      setSnapshot(nextSnapshot);
      setSelectedId(nextSnapshot.selectedCandidateId);
      setFocusedCandidate(null);
      setScanProgress(nextSnapshot.summary.progressPercent);
      setScanStatus("complete");
      setScanElapsedMs(Date.now() - startedAt);
      setScanStartedAt(null);
      setNotice(
        nextSnapshot.warnings.length > 0
          ? `${scanModeLabel}完成，有扫描提示，结果已回退可用。`
          : `${scanModeLabel}完成：${nextSnapshot.summary.candidateCount} 个候选，后端 ${nextSnapshot.scanBackend}。`
      );
      appendLog(
        "scan",
        "扫描完成",
        `${nextSnapshot.summary.candidateCount} 个候选，预计释放 ${formatBytes(nextSnapshot.summary.selectedBytes)}。`,
        `后端：${nextSnapshot.scanBackend}${nextSnapshot.warnings.length > 0 ? `\n${nextSnapshot.warnings.join("\n")}` : ""}`
      );
      void notifyScanComplete(
        `${scanModeLabel}完成`,
        `${nextSnapshot.summary.candidateCount} 个候选，预计释放 ${formatBytes(nextSnapshot.summary.selectedBytes)}。`
      );
    } catch (error) {
      setScanProgress(0);
      setScanStatus("failed");
      setScanElapsedMs(Date.now() - startedAt);
      setScanStartedAt(null);
      setNotice(`扫描失败：${error instanceof Error ? error.message : String(error)}`);
      appendLog("scan", "扫描失败", error instanceof Error ? error.message : String(error));
    }
  }

  async function togglePause() {
    if (scanStatus === "scanning") {
      try {
        await pauseScan();
        setScanStatus("paused");
        setNotice("扫描已暂停。");
        appendLog("operation", "暂停扫描", "扫描任务已在后端检查点暂停。");
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        setNotice(`暂停扫描失败：${message}`);
        appendLog("operation", "暂停扫描失败", message);
      }
      return;
    }

    if (scanStatus === "paused") {
      try {
        await resumeScan();
        setScanStatus("scanning");
        setNotice("扫描已继续。");
        appendLog("operation", "继续扫描", "扫描任务已恢复。");
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        setNotice(`继续扫描失败：${message}`);
        appendLog("operation", "继续扫描失败", message);
      }
      return;
    }

    setNotice("当前没有正在运行的扫描任务。");
    appendLog("operation", "请求暂停扫描", "没有正在运行的扫描任务。");
  }

  function runPrimaryScanControl() {
    if (scanControl.action === "pause" || scanControl.action === "resume") {
      void togglePause();
      return;
    }

    void startScan();
  }

  function openCleanupPreview() {
    if (currentSelectedIds.length === 0) {
      setNotice("请先选择至少一个可清理项。");
      return;
    }

    setLastReport(null);
    setCleanupStatus("idle");
    setCleanupProgress(EMPTY_CLEANUP_PROGRESS);
    setCleanupDialogOpen(true);
  }

  async function executeCleanup() {
    if (!snapshot || currentSelectedIds.length === 0) {
      setNotice("没有可执行的清理项。");
      return;
    }
    const startedAt = Date.now();

    try {
      if (currentSelectedIds.length === 0) {
        setNotice("没有可执行的清理项。");
        return;
      }

      setCleanupStatus("running");
      setCleanupProgress({
        ...EMPTY_CLEANUP_PROGRESS,
        totalCount: currentSelectedIds.length,
        percent: currentSelectedIds.length > 0 ? 1 : 0,
        currentPath: t("cleanup.preparing"),
        status: "cleaning"
      });
      setCleanupStartedAt(startedAt);
      setCleanupElapsedMs(0);
      setNotice(permanentDelete ? t("cleanup.runningPermanent") : t("cleanup.running"));
      await waitForNextPaint();

      const report = await executeCleanupPlan(activeCandidates, currentSelectedIds, cleanupDeleteStrategy);
      const cleanedPaths = report.itemResults
        .filter((item) => item.status === "cleaned")
        .map((item) => item.path);
      const nextCandidates = removeCandidates(snapshot.candidates, report.cleanedIds, cleanedPaths);
      const nextActiveCandidates = scopeCandidatesToVolumes(nextCandidates, selectedVolumeIds(snapshot.volumes));
      const nextSelectedCandidate = nextActiveCandidates[0] ?? nextCandidates[0] ?? null;
      const elapsedMs = Date.now() - startedAt;

      setCleanupStatus(report.cancelled ? "cancelled" : "complete");
      setCleanupElapsedMs(elapsedMs);
      setCleanupStartedAt(null);
      setCleanupProgress((currentProgress) => {
        const totalCount = currentProgress.totalCount || report.requestedCount;
        const processedCount = report.cancelled ? currentProgress.processedCount : totalCount;

        return {
          ...currentProgress,
          processedCount,
          totalCount,
          percent: report.cancelled ? currentProgress.percent : 100,
          status: report.cancelled ? "canceled" : "complete"
        };
      });
      setLastReport(report);
      setSnapshot({
        ...snapshot,
        candidates: nextCandidates
      });
      setFocusedCandidate(null);
      setSelectedId(nextSelectedCandidate?.id ?? "");
      setChildren([]);
      setNotice(
        report.cancelled
          ? t("cleanup.cancelledNotice", {
              count: report.cleanedCount,
              skipped: report.skippedLockedCount,
              size: formatBytes(report.reclaimedBytes)
            })
          : t("cleanup.completedNotice", {
              count: report.cleanedCount,
              failed: report.failedCount,
              size: formatBytes(report.reclaimedBytes)
            })
      );
      appendLog(
        "cleanup",
        report.cancelled ? "清理已取消" : "清理完成",
        `请求 ${report.requestedCount} 项，清理 ${report.cleanedCount} 项，跳过 ${report.skippedLockedCount} 项，失败 ${report.failedCount} 项，用时 ${formatDuration(elapsedMs)}。`,
        buildCleanupLogDetail(report, elapsedMs)
      );
    } catch (error) {
      setCleanupStatus("failed");
      setCleanupElapsedMs(Date.now() - startedAt);
      setCleanupStartedAt(null);
      setCleanupProgress({ ...EMPTY_CLEANUP_PROGRESS, status: "failed" });
      setNotice(`清理失败：${error instanceof Error ? error.message : String(error)}`);
      appendLog("cleanup", "清理失败", error instanceof Error ? error.message : String(error));
    }
  }

  async function pauseCleanupRun() {
    try {
      await pauseCleanup();
      setCleanupStatus("paused");
      setCleanupProgress((currentProgress) => ({ ...currentProgress, status: "paused" }));
      setNotice(t("cleanup.pauseRequested"));
      appendLog("cleanup", "暂停清理", "用户暂停了当前清理任务。");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setNotice(t("cleanup.pauseFailed", { message }));
      appendLog("cleanup", "暂停清理失败", message);
    }
  }

  async function resumeCleanupRun() {
    try {
      await resumeCleanup();
      setCleanupStatus("running");
      setCleanupProgress((currentProgress) => ({ ...currentProgress, status: "cleaning" }));
      setNotice(t("cleanup.resumeRequested"));
      appendLog("cleanup", "继续清理", "用户继续了当前清理任务。");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setNotice(t("cleanup.resumeFailed", { message }));
      appendLog("cleanup", "继续清理失败", message);
    }
  }

  async function cancelCleanupRun() {
    try {
      await cancelCleanup();
      setCleanupStatus("canceling");
      setCleanupProgress((currentProgress) => ({ ...currentProgress, status: "canceled" }));
      setNotice(t("cleanup.cancelRequested"));
      appendLog("cleanup", "取消清理", "用户请求取消当前清理任务。");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setNotice(t("cleanup.cancelFailed", { message }));
      appendLog("cleanup", "取消清理失败", message);
    }
  }

  async function elevateToAdmin() {
    try {
      await restartAsAdmin();
      setNotice(t("admin.restartRequested"));
      appendLog("operation", "管理员启动", "已触发 Windows UAC。");
    } catch (error) {
      setNotice(t("admin.restartFailed", { message: error instanceof Error ? error.message : String(error) }));
      appendLog("operation", "管理员启动失败", error instanceof Error ? error.message : String(error));
    }
  }

  async function validateCustomRules() {
    const result = await validateRulesYaml(ruleYaml, "user");
    setRuleCompilation(result);
    setNotice(result.report.valid ? `规则校验通过：${result.report.ruleCount} 条。` : "规则校验失败。");
  }

  async function importWinapp2CustomRules() {
    const result = await importWinapp2Rules(ruleYaml, "subscription");
    setRuleCompilation(result);
    setNotice(result.report.valid ? `Winapp2 导入完成：${result.report.ruleCount} 条规则。` : "Winapp2 导入失败。");
  }

  async function validateSubscription() {
    await refreshSubscriptionRules("manual");
  }

  async function refreshCurrentChildren() {
    if (!current) {
      return;
    }

    if (!canOpenChildren(current)) {
      setChildren([]);
      setNotice("当前对象是文件，没有可展开的目录内容。");
      appendLog("operation", "查看目录内容", `${current.displayName} 不是目录。`, current.path);
      return;
    }

    try {
      setChildrenLoading(true);
      const nextChildren = await listCandidateChildren(current);
      setChildren(nextChildren);
      setNotice(nextChildren.length > 0 ? "目录内容预览已刷新。" : "当前对象没有可预览子项。");
      appendLog("operation", "查看目录内容", `${current.displayName}：${nextChildren.length} 个子项。`, current.path);
    } catch (error) {
      setChildren([]);
      setNotice(`读取目录失败：${error instanceof Error ? error.message : String(error)}`);
      appendLog("operation", "读取目录失败", current.path, error instanceof Error ? error.message : String(error));
    } finally {
      setChildrenLoading(false);
    }
  }

  function inspectCandidate(candidate: CleanupCandidate) {
    setSelectedId(candidate.id);
    setFocusedCandidate(candidate);
    setNotice(canOpenChildren(candidate) ? `正在查看「${candidate.displayName}」的目录内容。` : `已选中「${candidate.displayName}」。`);
    appendLog("operation", "查看候选详情", candidate.displayName, candidate.path);
  }

  function selectTableCandidate(candidate: CleanupCandidate) {
    setSelectedId(candidate.id);
    setFocusedCandidate(null);
  }

  async function openCandidateLocation(candidate: CleanupCandidate) {
    try {
      await revealPath(candidate.path);
      setNotice(`已打开位置：${candidate.displayName}`);
      appendLog("operation", "打开所在位置", candidate.displayName, candidate.path);
    } catch (error) {
      setNotice(`打开位置失败，已尝试复制路径：${error instanceof Error ? error.message : String(error)}`);
      appendLog("operation", "打开位置失败", candidate.path, error instanceof Error ? error.message : String(error));
    }
  }

  function cycleThemeMode() {
    const currentIndex = THEME_SEQUENCE.indexOf(themeMode);
    const nextMode = THEME_SEQUENCE[(currentIndex + 1) % THEME_SEQUENCE.length] ?? "system";
    setThemeMode(nextMode);
    setNotice(t("theme.changed", { mode: t(themeLabelKey(nextMode)) }));
  }

  if (!snapshot) {
    return <div className="loading">{t("app.loading")}</div>;
  }

  return (
    <div className="window">
      <section className="commandbar">
        <div className="commandTitle">
          <img className="appLogo" src={appLogoUrl} alt="" aria-hidden="true" />
          <h1>{t("app.name")}</h1>
        </div>
        <div className="commandActions">
          <span className={`adminBadge ${adminStatus?.isAdmin ? "safe" : "warn"}`}>
            <Shield size={15} />
            {adminStatus ? (adminStatus.isAdmin ? t("admin.admin") : t("admin.notAdmin")) : t("admin.checking")}
          </span>
          {adminStatus && !adminStatus.isAdmin && adminStatus.canRestartElevated ? (
            <button className="button" onClick={elevateToAdmin}>
              <Shield size={15} />
              {t("admin.restart")}
            </button>
          ) : null}
          <label className="languageSelect" aria-label={t("language.label")}>
            <Languages size={15} />
            <select value={language} onChange={(event) => setLanguage(event.currentTarget.value as LanguageCode)}>
              {languageOptions.map((option) => (
                <option key={option.code} value={option.code}>
                  {option.nativeLabel}
                </option>
              ))}
            </select>
          </label>
          <button
            className="button themeButton"
            onClick={cycleThemeMode}
            title={t("theme.toggle", { mode: themeLabel })}
            aria-label={t("theme.toggle", { mode: themeLabel })}
          >
            <ThemeIcon size={16} />
            {themeLabel}
          </button>
          <button className="button" onClick={() => setRulesDialogOpen(true)}>
            <Settings size={16} />
            {t("nav.rules")}
          </button>
          <button className="button" onClick={() => setLogsDialogOpen(true)}>
            <FileText size={16} />
            {t("nav.logs")}
          </button>
          <button className="button primary" onClick={runPrimaryScanControl}>
            <ScanControlIcon action={scanControl.action} />
            {scanControlLabel}
          </button>
        </div>
      </section>

      <main className="workbench">
        <aside className="pane leftPane">
          <div className="paneHeader">
            <h2>{t("nav.settings")}</h2>
          </div>
          <div className="paneContent">
            <section className="section">
              <div className="sectionTitle">
                <span>{t("nav.drives")}</span>
                <button
                  className="ghostButton"
                  onClick={refreshVolumes}
                  disabled={scanInProgress || volumesRefreshing}
                >
                  {volumesRefreshing ? t("button.refreshing") : t("button.refresh")}
                </button>
              </div>
              <div className="driveList">
                {volumes.map((volume) => {
                  const usedPercent = Math.max(5, Math.round(((volume.totalBytes - volume.availableBytes) / volume.totalBytes) * 100));

                  return (
                    <button
                      key={volume.id}
                      className={`selectCard driveCard ${volume.selected ? "selected" : ""}`}
                      onClick={() => updateVolumeSelection(volume.id)}
                      disabled={scanInProgress}
                    >
                      <div className="rowTop">
                        <span className="rowLeft">
                          <span className="checkbox">{volume.selected ? "✓" : ""}</span>
                          <strong>{volume.id}:</strong>
                        </span>
                        <span className={`badge ${volume.supportsFastIndex ? "safe" : "info"}`}>{volume.filesystem}</span>
                      </div>
                      <div className="rowMeta">
                        {volume.label} · {t("drive.available", { available: formatBytes(volume.availableBytes), total: formatBytes(volume.totalBytes) })}
                      </div>
                      <div className="meter">
                        <span style={{ width: `${usedPercent}%` }} />
                      </div>
                    </button>
                  );
                })}
              </div>
            </section>

            <section className="section">
              <div className="sectionTitle">{t("scan.mode")}</div>
              <div className="modeList">
                <button
                  className={`selectCard ${scanMode === "quick" ? "selected" : ""}`}
                  onClick={() => {
                    setScanMode("quick");
                    setNotice("已切换到快速扫描。");
                    appendLog("operation", "切换扫描模式", "快速扫描");
                  }}
                  disabled={scanInProgress}
                >
                  <div className="rowTop">
                    <span className="rowLeft">
                      <span className="checkbox">{scanMode === "quick" ? "✓" : ""}</span>
                      <strong>{t("scan.quick")}</strong>
                    </span>
                  </div>
                </button>
                <button
                  className={`selectCard ${scanMode === "full" ? "selected" : ""}`}
                  onClick={() => {
                    setScanMode("full");
                    setNotice("已切换到全盘分析。NTFS 优先 USN/MFT，其他文件系统使用递归扫描。");
                    appendLog("operation", "切换扫描模式", "全盘分析");
                  }}
                  disabled={scanInProgress}
                >
                  <div className="rowTop">
                    <span className="rowLeft">
                      <span className="checkbox">{scanMode === "full" ? "✓" : ""}</span>
                      <strong>{t("scan.full")}</strong>
                    </span>
                  </div>
                </button>
              </div>
            </section>

            <section className="section">
              <div className="sectionTitle">{t("cleanup.deleteMethod")}</div>
              <button
                className={`selectCard optionCard dangerOption ${permanentDelete ? "selected" : ""}`}
                onClick={() => {
                  const nextValue = !permanentDelete;
                  setPermanentDelete(nextValue);
                  setNotice(nextValue ? t("cleanup.permanentDeleteEnabled") : t("cleanup.recycleBinEnabled"));
                  appendLog(
                    "operation",
                    "切换删除方式",
                    nextValue ? t("cleanup.permanentDelete") : t("cleanup.moveToRecycleBin")
                  );
                }}
                disabled={cleanupInProgress}
              >
                <div className="rowTop">
                  <span className="rowLeft">
                    <span className="checkbox">{permanentDelete ? "✓" : ""}</span>
                    <strong>{t("cleanup.permanentDelete")}</strong>
                  </span>
                </div>
                <div className="rowMeta">
                  {permanentDelete ? t("cleanup.permanentDeleteWarning") : t("cleanup.recycleBinHint")}
                </div>
              </button>
            </section>

            <section className="section">
              <div className="sectionTitle">{t("table.category")}</div>
              <CategoryRows
                candidates={activeCandidates}
                language={language}
                onToggleCategory={updateCategorySelection}
              />
            </section>
          </div>
        </aside>

        <section className="centerPane">
          <div className="summaryStrip">
            <Metric label={t("metric.estimated")} value={formatBytes(summary.selectedBytes)} />
            <Metric label={t("metric.candidates")} value={String(activeCandidates.length)} />
            <Metric label={t("metric.locked")} value={String(summary.lockedCount)} />
            <Metric label={t("metric.progress")} value={scanProgressLabel} />
          </div>

          {scanWarnings.length > 0 ? (
            <div className="scanWarningBar">
              <div>
                <strong>{t("scan.warning")}</strong>
                <span>{scanWarnings[0]}</span>
              </div>
              <button className="button compact" onClick={() => setLogsDialogOpen(true)}>
                {t("button.viewLogs")}
              </button>
            </div>
          ) : null}

          <div className="resultToolbar">
            <label className="searchBox">
              <Search size={16} />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("scan.searchPlaceholder")} />
            </label>
            <div className="tabs">
              <RiskTab value="all" label={t("filter.all")} current={riskFilter} onSelect={setRiskFilter} />
              <RiskTab value="recommended" label={t("filter.recommended")} current={riskFilter} onSelect={setRiskFilter} />
              <RiskTab value="caution" label={t("filter.caution")} current={riskFilter} onSelect={setRiskFilter} />
              <RiskTab value="dangerous" label={t("filter.dangerous")} current={riskFilter} onSelect={setRiskFilter} />
            </div>
            <button
              className={`button ${showSelectedOnly ? "active" : ""}`}
              onClick={() => setShowSelectedOnly((value) => !value)}
            >
              {t("filter.selectedOnly")}
            </button>
          </div>

          <div
            ref={tableAreaRef}
            className="tableArea"
            onScroll={(event) => setTableScrollTop(event.currentTarget.scrollTop)}
          >
            <table>
              <colgroup>
                <col style={{ width: 42 }} />
                <col style={{ width: 380 }} />
                <col style={{ width: 138 }} />
                <col style={{ width: 52 }} />
                <col style={{ width: 150 }} />
                <col style={{ width: 108 }} />
                <col style={{ width: 92 }} />
                <col style={{ width: 88 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>
                    <button
                      className={`checkboxButton ${visibleAllSelected ? "checked" : ""}`}
                      onClick={updateVisibleSelection}
                      aria-label={visibleAllSelected ? "取消选择当前结果" : "选择当前结果"}
                    >
                      {visibleAllSelected ? "✓" : ""}
                    </button>
                  </th>
                  <th>{t("table.object")}</th>
                  <th>{t("table.source")}</th>
                  <th>{t("table.drive")}</th>
                  <th>{t("table.category")}</th>
                  <th>{t("table.cleanup")}</th>
                  <th>{t("table.risk")}</th>
                  <th className="alignRight">{t("table.size")}</th>
                </tr>
              </thead>
              <tbody>
                {virtualWindow.topPadding > 0 ? (
                  <tr className="virtualSpacer" aria-hidden="true">
                    <td colSpan={8} style={{ height: virtualWindow.topPadding }} />
                  </tr>
                ) : null}
                {renderedCandidates.map((candidate) => {
                  const sourceLabel = candidateSourceLabel(candidate, language);

                  return (
                    <tr
                      key={candidate.id}
                      className={`candidateRow ${candidate.id === selectedId && !focusedCandidate ? "selectedRow" : ""}`}
                      onClick={() => selectTableCandidate(candidate)}
                      onDoubleClick={() => {
                        if (canOpenChildren(candidate)) {
                          inspectCandidate(candidate);
                        } else {
                          void openCandidateLocation(candidate);
                        }
                      }}
                      onContextMenu={(event) => {
                        event.preventDefault();
                        void openCandidateLocation(candidate);
                      }}
                    >
                      <td>
                        <button
                          className={`checkboxButton ${candidate.selected ? "checked" : ""}`}
                          onClick={(event) => {
                            event.stopPropagation();
                            updateCandidateSelection(candidate.id);
                          }}
                          disabled={!isCleanupSelectable(candidate)}
                          aria-label={`选择 ${candidate.displayName}`}
                        >
                          {candidate.selected ? "✓" : ""}
                        </button>
                      </td>
                      <td>
                        <div className="fileCell">
                          <span className="fileIcon">
                            {candidate.objectType === "file" ? <File size={16} /> : <Folder size={16} />}
                          </span>
                          <span>
                            <span className="fileName" title={candidate.displayName}>{candidate.displayName}</span>
                            <span className="filePath" title={candidate.path}>{candidate.path}</span>
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="sourceLabel" title={sourceLabel}>{sourceLabel}</span>
                      </td>
                      <td className="volumeCell">{candidate.volumeId}:</td>
                      <td className="categoryCell" title={candidate.category}>{translateCategory(language, candidate.category)}</td>
                      <td>
                        <span className={`badge ${cleanupStatusClass(candidate)}`}>{localizedCleanupStatusLabel(language, candidate)}</span>
                      </td>
                      <td>
                        <span className={`badge ${riskClass(candidate.riskLevel)}`}>{localizedRiskLabel(language, candidate.riskLevel)}</span>
                      </td>
                      <td className="size">{formatBytes(candidate.sizeBytes)}</td>
                    </tr>
                  );
                })}
                {virtualWindow.bottomPadding > 0 ? (
                  <tr className="virtualSpacer" aria-hidden="true">
                    <td colSpan={8} style={{ height: virtualWindow.bottomPadding }} />
                  </tr>
                ) : null}
                {filteredCandidates.length === 0 ? (
                  <tr>
                    <td className="emptyCell" colSpan={8}>
                      {t("scan.emptyTable")}
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="pane rightPane">
          <div className="paneHeader">
            <h2>{t("detail.current")}</h2>
          </div>
          <div className="paneContent">
            {current ? (
              <DetailBlock title={t("detail.current")}>
                <KeyValue label={t("detail.object")} value={current.displayName} />
                <KeyValue
                  label={t("detail.type")}
                  value={`${localizedObjectType(language, current.objectType)} · ${current.childrenCount} ${language === "zh-CN" ? "个子项" : "items"}`}
                />
                <KeyValue label={t("detail.location")} value={current.path} />
                <KeyValue label={t("detail.source")} value={candidateSourceLabel(current, language)} />
                <KeyValue label={t("cleanup.status")} value={localizedCleanupStatusLabel(language, current)} />
                <KeyValue label={t("detail.category")} value={translateCategory(language, current.category)} />
                <KeyValue label={t("table.risk")} value={localizedRiskLabel(language, current.riskLevel)} />
                <KeyValue label={t("detail.reason")} value={translateReason(language, current.reason)} />
                <KeyValue label={t("cleanup.strategy")} value={localizedDeleteStrategy(language, current.deleteStrategy)} />
                <div className="detailActions">
                  <button className="button fullWidth" onClick={refreshCurrentChildren} disabled={!canOpenChildren(current)}>
                    <Folder size={16} />
                    {childrenLoading ? t("detail.actions.reading") : t("detail.actions.viewChildren")}
                  </button>
                  <button className="button fullWidth" onClick={() => void openCandidateLocation(current)}>
                    <ExternalLink size={16} />
                    {t("detail.actions.openLocation")}
                  </button>
                </div>
              </DetailBlock>
            ) : (
              <DetailBlock title={t("detail.current")}>
                <p className="emptyText">{t("detail.noCandidate")}</p>
              </DetailBlock>
            )}

            <DetailBlock title={t("detail.preview")}>
              <div className="childList">
                {childrenLoading ? (
                  <p className="emptyText">{t("detail.actions.reading")}</p>
                ) : children.length === 0 ? (
                  <p className="emptyText">{t("detail.noChildren")}</p>
                ) : (
                  children.map((child) => (
                    <button
                      key={child.id}
                      className="childRow"
                      onClick={() => inspectCandidate(child)}
                      onDoubleClick={() => void openCandidateLocation(child)}
                      onContextMenu={(event) => {
                        event.preventDefault();
                        void openCandidateLocation(child);
                      }}
                    >
                      <span>
                        <strong>{child.displayName}</strong>
                        <small className="childPath">{child.path}</small>
                        <small>
                          {localizedObjectType(language, child.objectType)} · {child.childrenCount.toLocaleString()} ·{" "}
                          {candidateSourceLabel(child, language)}
                        </small>
                      </span>
                      <strong>{formatBytes(child.sizeBytes)}</strong>
                    </button>
                  ))
                )}
              </div>
            </DetailBlock>

            <DetailBlock title={t("cleanup.preview")}>
              <PlanRow label={t("cleanup.selected")} value={String(cleanupPlan?.selectedCount ?? summary.selectedCount)} />
              <PlanRow label={t("metric.estimated")} value={formatBytes(cleanupPlan?.estimatedReclaimBytes ?? summary.selectedBytes)} />
              <PlanRow label={t("plan.drives")} value={selectedDrives.join(", ") || t("plan.noDrives")} />
              <PlanRow label={t("cleanup.lockedSkipped")} value={String(cleanupPlan?.skippedLockedCount ?? summary.lockedCount)} />
              <PlanRow label={t("cleanup.deleteMethod")} value={cleanupDeleteMethodLabel} />
            </DetailBlock>

            <DetailBlock title={t("plan.safety")}>
              <PlanRow label={t("plan.systemDirs")} value={t("filter.locked")} />
              <PlanRow label={t("plan.roaming")} value={t("filter.locked")} />
              <PlanRow label={t("plan.userDocs")} value={t("cleanup.confirmAfterReview")} />
              <PlanRow label={t("plan.permanentDelete")} value={permanentDelete ? t("cleanup.enabled") : t("cleanup.disabled")} />
            </DetailBlock>
          </div>
          <div className="rightPaneFooter">
            <button
              className="button primary fullWidth"
              onClick={openCleanupPreview}
              disabled={currentSelectedIds.length === 0 || cleanupInProgress}
            >
              <Trash2 size={16} />
              {t("cleanup.previewAndRun")}
            </button>
          </div>
        </aside>
      </main>

      <footer className="statusbar">
        <div className="statusLeft">
          <span>
            {scanStatusLabel}
            {scanInProgress || scanElapsedMs > 0 ? ` · ${t("scan.elapsed")} ${formatDuration(scanElapsedMs)}` : ""}
          </span>
          <div className="statusProgress">
            <div className="progress">
              <span
                className={scanStatus === "scanning" ? "indeterminate" : ""}
                style={{ width: scanStatus === "scanning" ? "100%" : `${scanProgress}%` }}
              />
            </div>
            <strong>{scanProgressLabel}</strong>
          </div>
          <span>{t("scan.current")}: {currentPathLabel}</span>
        </div>
        <div className="statusRight">
          {cleanupInProgress || cleanupElapsedMs > 0 ? (
            <span>{t("cleanup.elapsed")} {formatDuration(cleanupElapsedMs)}</span>
          ) : null}
          <span>{t("status.candidates", { count: activeCandidates.length.toLocaleString() })}</span>
          <span>{t("status.estimated", { size: formatBytes(summary.selectedBytes) })}</span>
          <span>{t("scan.backend")} {backendLabel}</span>
          <button
            className="button primary compact statusCleanupButton"
            onClick={openCleanupPreview}
            disabled={currentSelectedIds.length === 0 || cleanupInProgress}
          >
            {t("cleanup.action")}
          </button>
        </div>
      </footer>

      {driveDialogOpen ? (
        <div className="dialogOverlay" role="dialog" aria-modal="true" aria-label={t("dialog.drive")}>
          <section className="dialog">
            <div className="dialogHeader">
              <div>
                <h2>{t("dialog.drive")}</h2>
              </div>
              <button className="iconButton" onClick={() => setDriveDialogOpen(false)} aria-label={t("button.close")}>
                <X size={16} />
              </button>
            </div>
            <div className="dialogBody driveDialogGrid">
              {volumes.map((volume) => (
                <button
                  key={volume.id}
                  className={`selectCard driveCard ${volume.selected ? "selected" : ""}`}
                  onClick={() => updateVolumeSelection(volume.id)}
                  disabled={scanInProgress}
                >
                  <div className="rowTop">
                    <span className="rowLeft">
                      <span className="checkbox">{volume.selected ? "✓" : ""}</span>
                      <strong>{volume.id}: {volume.label}</strong>
                    </span>
                    <span className={`badge ${volume.supportsFastIndex ? "safe" : "info"}`}>{volume.filesystem}</span>
                  </div>
                  <div className="rowMeta">
                    {t("drive.available", { available: formatBytes(volume.availableBytes), total: formatBytes(volume.totalBytes) })}
                  </div>
                </button>
              ))}
            </div>
            <div className="dialogFooter">
              <button className="button" onClick={() => setDriveDialogOpen(false)}>
                {t("button.done")}
              </button>
              <button className="button primary" onClick={startScan} disabled={scanInProgress}>
                {t("button.startScan")}
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {rulesDialogOpen ? (
        <div className="dialogOverlay" role="dialog" aria-modal="true" aria-label={t("dialog.rules")}>
          <section className="dialog ruleDialog">
            <div className="dialogHeader">
              <div>
                <h2>{t("dialog.rules")}</h2>
              </div>
              <button className="iconButton" onClick={() => setRulesDialogOpen(false)} aria-label={t("button.close")}>
                <X size={16} />
              </button>
            </div>
            <div className="dialogBody ruleDialogBody">
              <DetailBlock title={t("rule.custom")}>
                <textarea
                  className="ruleTextarea"
                  value={ruleYaml}
                  onChange={(event) => setRuleYaml(event.target.value)}
                  spellCheck={false}
                />
                <div className="ruleActions">
                  <button className="button" onClick={() => setRuleYaml(DEFAULT_RULE_YAML)}>
                    {t("rule.reset")}
                  </button>
                  <button className="button" onClick={importWinapp2CustomRules}>
                    {t("rule.importWinapp2")}
                  </button>
                  <button className="button primary" onClick={validateCustomRules}>
                    {t("rule.validate")}
                  </button>
                </div>
                {ruleCompilation ? <RuleReportView report={ruleCompilation.report} /> : null}
              </DetailBlock>

              <DetailBlock title={t("rule.subscription")}>
                <div className="ruleUrlRow">
                  <input
                    value={subscriptionUrl}
                    onChange={(event) => {
                      setSubscriptionUrl(event.target.value);
                      setSubscriptionCompilation(null);
                      setSubscriptionReport(null);
                    }}
                    placeholder={DEFAULT_RULE_SUBSCRIPTION_URL}
                  />
                  <button className="button primary" onClick={validateSubscription}>
                    {t("rule.loadSubscription")}
                  </button>
                </div>
                {subscriptionReport ? <RuleReportView report={subscriptionReport} /> : null}
              </DetailBlock>

              <DetailBlock title={t("rule.source")}>
                <PlanRow label={t("rule.builtIn")} value={t("rule.enabled")} />
                <PlanRow label={t("rule.custom")} value={ruleCompilation?.report.valid ? `${ruleCompilation.report.ruleCount}` : t("rule.notEnabled")} />
                <PlanRow label={t("rule.subscription")} value={subscriptionCompilation?.report.valid ? `${subscriptionCompilation.report.ruleCount}` : t("rule.notEnabled")} />
                <PlanRow label={t("rule.subscriptionRefresh")} value={subscriptionCompilation?.report.valid ? t("rule.every12Hours") : t("rule.notEnabled")} />
              </DetailBlock>
            </div>
            <div className="dialogFooter">
              <button className="button primary" onClick={() => setRulesDialogOpen(false)}>
                {t("button.done")}
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {logsDialogOpen ? (
        <div className="dialogOverlay" role="dialog" aria-modal="true" aria-label={t("dialog.logs")}>
          <section className="dialog logDialog">
            <div className="dialogHeader">
              <div>
                <h2>{t("dialog.logs")}</h2>
              </div>
              <button className="iconButton" onClick={() => setLogsDialogOpen(false)} aria-label={t("button.close")}>
                <X size={16} />
              </button>
            </div>
            <div className="dialogBody logDialogBody">
              <div className="tabs">
                <LogTab value="all" label={t("filter.all")} current={logFilter} onSelect={setLogFilter} />
                <LogTab value="scan" label={t("logs.scan")} current={logFilter} onSelect={setLogFilter} />
                <LogTab value="cleanup" label={t("logs.cleanup")} current={logFilter} onSelect={setLogFilter} />
                <LogTab value="operation" label={t("logs.operation")} current={logFilter} onSelect={setLogFilter} />
              </div>
              <div className="logList">
                {filteredLogs.length === 0 ? (
                  <p className="emptyText">{t("logs.empty")}</p>
                ) : (
                  filteredLogs.map((log) => (
                    <article key={log.id} className="logEntry">
                      <div className="logEntryHeader">
                        <span className={`badge ${logKindClass(log.kind)}`}>{localizedLogKindLabel(language, log.kind)}</span>
                        <time>{formatLogTime(log.time, language)}</time>
                      </div>
                      <strong>{log.title}</strong>
                      <p>{log.message}</p>
                      {log.detail ? <pre>{log.detail}</pre> : null}
                    </article>
                  ))
                )}
              </div>
            </div>
            <div className="dialogFooter">
              <button className="button" onClick={clearLogs}>
                {t("button.clearLogs")}
              </button>
              <button className="button primary" onClick={() => setLogsDialogOpen(false)}>
                {t("button.close")}
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {cleanupDialogOpen ? (
        <div className="dialogOverlay" role="dialog" aria-modal="true" aria-label={t("cleanup.preview")}>
          <section className="dialog">
            <div className="dialogHeader">
              <div>
                <h2>{lastReport ? t("cleanup.result") : t("cleanup.preview")}</h2>
              </div>
              <button className="iconButton" onClick={() => setCleanupDialogOpen(false)} aria-label={t("button.close")}>
                <X size={16} />
              </button>
            </div>
            <div className="dialogBody">
              {cleanupInProgress ? (
                <div className="reportGrid">
                  <PlanRow
                    label={t("cleanup.status")}
                    value={cleanupStatus === "canceling" ? t("cleanup.canceling") : localizedProgressStatus(language, cleanupProgress.status)}
                  />
                  <PlanRow label={t("cleanup.selected")} value={String(cleanupPlan?.selectedCount ?? summary.selectedCount)} />
                  <PlanRow label={t("metric.estimated")} value={formatBytes(cleanupPlan?.estimatedReclaimBytes ?? summary.selectedBytes)} />
                  <PlanRow label={t("cleanup.deleteMethod")} value={cleanupDeleteMethodLabel} />
                  <PlanRow label={t("cleanup.elapsed")} value={formatDuration(cleanupElapsedMs)} />
                  <PlanRow
                    label={t("cleanup.processed")}
                    value={`${cleanupProgress.processedCount} / ${cleanupProgress.totalCount || currentSelectedIds.length}`}
                  />
                  <PlanRow
                    label={t("cleanup.current")}
                    value={cleanupProgress.currentPath || t("cleanup.preparing")}
                  />
                  <div className="cleanupProgress">
                    <div className="progress">
                      <span style={{ width: `${cleanupProgress.percent}%` }} />
                    </div>
                    <strong>{cleanupProgress.percent}%</strong>
                  </div>
                </div>
              ) : lastReport ? (
                <div className="reportGrid">
                  <h3 className="reportSectionTitle">{t("cleanup.resultSummary")}</h3>
                  <PlanRow label={t("cleanup.selected")} value={String(lastReport.requestedCount)} />
                  <PlanRow label={t("cleanup.cleanedItems")} value={String(lastReport.cleanedCount)} />
                  <PlanRow label={t("cleanup.lockedSkipped")} value={String(lastReport.skippedLockedCount)} />
                  <PlanRow label={t("cleanup.failedItems")} value={String(lastReport.failedCount)} />
                  <PlanRow label={t("cleanup.releaseThisRun")} value={formatBytes(lastReport.reclaimedBytes)} />
                  <PlanRow label={t("cleanup.deleteMethod")} value={localizedDeleteStrategy(language, lastReport.deleteStrategy)} />
                  <PlanRow label={t("cleanup.elapsed")} value={formatDuration(cleanupElapsedMs)} />
                  <CleanupReportGroup
                    title={t("cleanup.cleanedItems")}
                    emptyText={t("cleanup.noItems")}
                    items={lastReport.itemResults.filter((item) => item.status === "cleaned")}
                    tone="safe"
                    rightValue={(item) => formatBytes(item.reclaimedBytes)}
                  />
                  <CleanupReportGroup
                    title={t("cleanup.notCleanedItems")}
                    emptyText={t("cleanup.noItems")}
                    items={lastReport.itemResults.filter((item) => item.status !== "cleaned")}
                    tone="warn"
                    rightValue={(item) => (item.status === "failed" ? t("cleanup.failedItems") : t("cleanup.skip"))}
                  />
                  {cleanupExtraWarnings(lastReport).length > 0 ? (
                    <div className="warningList">
                      <strong>{t("cleanup.extraNotes")}</strong>
                      {cleanupExtraWarnings(lastReport).map((warning) => (
                        <p key={warning}>{warning}</p>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="reportGrid">
                  <PlanRow label={t("cleanup.selected")} value={String(cleanupPlan?.selectedCount ?? summary.selectedCount)} />
                  <PlanRow label={t("metric.estimated")} value={formatBytes(cleanupPlan?.estimatedReclaimBytes ?? summary.selectedBytes)} />
                  <PlanRow label={t("cleanup.lockedSkipped")} value={String(cleanupPlan?.skippedLockedCount ?? 0)} />
                  <PlanRow label={t("cleanup.deleteMethod")} value={cleanupDeleteMethodLabel} />
                  <div className="previewList">
                    {activeCandidates
                      .filter((candidate) => candidate.selected)
                      .map((candidate) => (
                        <div key={candidate.id} className="previewRow">
                          <span>
                            <strong>{candidate.displayName}</strong>
                            <small>{candidate.path}</small>
                          </span>
                          <strong>{formatBytes(candidate.sizeBytes)}</strong>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
            <div className="dialogFooter">
              <button className="button" onClick={() => setCleanupDialogOpen(false)}>
                {t("button.close")}
              </button>
              {!lastReport ? (
                cleanupInProgress ? (
                  <>
                    <button
                      className="button"
                      onClick={cleanupStatus === "paused" ? resumeCleanupRun : pauseCleanupRun}
                      disabled={cleanupStatus === "canceling"}
                    >
                      {cleanupStatus === "paused" ? <Play size={15} /> : <Pause size={15} />}
                      {cleanupStatus === "paused" ? t("cleanup.resume") : t("cleanup.pause")}
                    </button>
                    <button className="button danger" onClick={cancelCleanupRun} disabled={cleanupStatus === "canceling"}>
                      <X size={15} />
                      {cleanupStatus === "canceling" ? t("cleanup.canceling") : t("cleanup.cancel")}
                    </button>
                  </>
                ) : (
                  <button
                    className="button primary"
                    onClick={executeCleanup}
                    disabled={currentSelectedIds.length === 0 || cleanupInProgress}
                  >
                    {permanentDelete ? t("cleanup.confirmPermanent") : t("cleanup.confirm")}
                  </button>
                )
              ) : null}
            </div>
          </section>
        </div>
      ) : null}

      {toastVisible ? (
        <div className={`toast ${toastToneForNotice(notice)}`} role="status" aria-live="polite">
          <span className="toastMarker" aria-hidden="true" />
          <p>{notice}</p>
          <button className="toastClose" onClick={() => setToastVisible(false)} aria-label={t("button.close")}>
            <X size={14} />
          </button>
        </div>
      ) : null}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <div className="metricLabel">{label}</div>
      <div className="metricValue">{value}</div>
    </div>
  );
}

function ScanControlIcon({ action }: { action: ReturnType<typeof scanControlForStatus>["action"] }) {
  if (action === "pause") {
    return <Pause size={16} />;
  }

  if (action === "resume" || action === "start") {
    return <Play size={16} />;
  }

  return <RefreshCw size={16} />;
}

function waitForNextPaint(): Promise<void> {
  return new Promise((resolve) => {
    window.requestAnimationFrame(() => resolve());
  });
}

function formatDuration(milliseconds: number): string {
  const safeMilliseconds = Math.max(0, Math.round(milliseconds));

  if (safeMilliseconds < 1000) {
    return `${(safeMilliseconds / 1000).toFixed(1)}s`;
  }

  const totalSeconds = Math.round(safeMilliseconds / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  if (minutes === 0) {
    return `${totalSeconds}s`;
  }

  return `${minutes}m ${seconds.toString().padStart(2, "0")}s`;
}

function candidateSourceLabel(candidate: CleanupCandidate, language: LanguageCode): string {
  return localizeSourceLabel(language, candidate.source.label);
}

function toastToneForNotice(notice: string): "safe" | "warn" | "danger" | "info" {
  const normalized = notice.toLocaleLowerCase();

  if (normalized.includes("失败") || normalized.includes("failed") || normalized.includes("error")) {
    return "danger";
  }

  if (
    normalized.includes("跳过") ||
    normalized.includes("不可") ||
    normalized.includes("未") ||
    normalized.includes("pause") ||
    normalized.includes("blocked")
  ) {
    return "warn";
  }

  if (
    normalized.includes("完成") ||
    normalized.includes("通过") ||
    normalized.includes("已") ||
    normalized.includes("complete") ||
    normalized.includes("done")
  ) {
    return "safe";
  }

  return "info";
}

function buildCleanupLogDetail(report: CleanupReport, elapsedMs: number): string {
  const cleaned = report.itemResults.filter((item) => item.status === "cleaned");
  const notCleaned = report.itemResults.filter((item) => item.status !== "cleaned");
  const sourceSummary = summarizeCleanupSources(report.itemResults);
  const lines = [
    `本次释放：${formatBytes(report.reclaimedBytes)}`,
    `清理耗时：${formatDuration(elapsedMs)}`,
    `已清理：${cleaned.length} 项`,
    "来源汇总：",
    ...sourceSummary.map((line) => `- ${line}`),
    ...cleaned.map((item) => `- ${item.displayName} (${formatBytes(item.reclaimedBytes)}) ${item.path}`),
    `未清理 / 需关注：${notCleaned.length} 项`,
    ...notCleaned.map((item) => `- ${item.displayName}: ${item.reason}`)
  ];
  const extraWarnings = cleanupExtraWarnings(report);

  if (extraWarnings.length > 0) {
    lines.push("补充原因：", ...extraWarnings.map((warning) => `- ${warning}`));
  }

  return lines.join("\n");
}

function summarizeCleanupSources(items: CleanupReportItem[]): string[] {
  const groups = new Map<string, { cleaned: number; notCleaned: number; bytes: number }>();

  for (const item of items) {
    const label = item.source.label || "未知来源";
    const group = groups.get(label) ?? { cleaned: 0, notCleaned: 0, bytes: 0 };

    if (item.status === "cleaned") {
      group.cleaned += 1;
      group.bytes += item.reclaimedBytes;
    } else {
      group.notCleaned += 1;
    }

    groups.set(label, group);
  }

  return [...groups.entries()]
    .sort((left, right) => right[1].bytes - left[1].bytes)
    .map(
      ([label, group]) =>
        `${label}：已清理 ${group.cleaned} 项，未清理 ${group.notCleaned} 项，释放 ${formatBytes(group.bytes)}`
    );
}

function cleanupExtraWarnings(report: CleanupReport): string[] {
  const itemReasons = new Set(report.itemResults.map((item) => item.reason));

  return report.warnings.filter(
    (warning) =>
      !warning.startsWith("已执行真实清理") &&
      !warning.startsWith("目录候选会清理") &&
      !itemReasons.has(warning)
  );
}

function RiskTab({
  value,
  label,
  current,
  onSelect
}: {
  value: RiskFilter;
  label: string;
  current: RiskFilter;
  onSelect: (value: RiskFilter) => void;
}) {
  return (
    <button className={`tab ${current === value ? "active" : ""}`} onClick={() => onSelect(value)}>
      {label}
    </button>
  );
}

function LogTab({
  value,
  label,
  current,
  onSelect
}: {
  value: LogFilter;
  label: string;
  current: LogFilter;
  onSelect: (value: LogFilter) => void;
}) {
  return (
    <button className={`tab ${current === value ? "active" : ""}`} onClick={() => onSelect(value)}>
      {label}
    </button>
  );
}

function RuleReportView({ report }: { report: RuleValidationReport }) {
  return (
    <div className={`ruleReport ${report.valid ? "valid" : "invalid"}`}>
      <strong>{report.valid ? `通过 · ${report.ruleCount} 条` : "未通过"}</strong>
      {[...report.errors, ...report.warnings].slice(0, 6).map((issue, index) => (
        <p key={`${issue.field}-${index}`}>
          {issue.ruleId ? `${issue.ruleId} · ` : ""}
          {issue.field}：{issue.message}
        </p>
      ))}
    </div>
  );
}

function CleanupReportGroup({
  title,
  emptyText,
  items,
  tone,
  rightValue
}: {
  title: string;
  emptyText: string;
  items: CleanupReportItem[];
  tone: "safe" | "warn";
  rightValue: (item: CleanupReportItem) => string;
}) {
  return (
    <section className={`cleanupReportGroup ${tone}`}>
      <h3>{title}</h3>
      {items.length === 0 ? (
        <p className="emptyText">{emptyText}</p>
      ) : (
        <div className="cleanupReportList">
          {items.slice(0, 24).map((item) => (
            <article key={`${item.id}-${item.status}`} className="cleanupReportItem">
              <div>
                <strong>{item.displayName}</strong>
                <small>{item.path}</small>
                <p>{item.reason}</p>
              </div>
              <span>{rightValue(item)}</span>
            </article>
          ))}
          {items.length > 24 ? <p className="emptyText">+ {items.length - 24}</p> : null}
        </div>
      )}
    </section>
  );
}

function logKindLabel(kind: AppLogKind): string {
  switch (kind) {
    case "scan":
      return "扫描";
    case "cleanup":
      return "清理";
    case "operation":
      return "操作";
  }
}

function logKindClass(kind: AppLogKind): string {
  switch (kind) {
    case "scan":
      return "info";
    case "cleanup":
      return "warn";
    case "operation":
      return "safe";
  }
}

function formatLogTime(value: string, language: LanguageCode): string {
  return new Intl.DateTimeFormat(language, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(value));
}

function ruleCompilationChanged(currentCompilation: RuleCompilation | null, nextCompilation: RuleCompilation): boolean {
  if (!currentCompilation) {
    return true;
  }

  return JSON.stringify(currentCompilation.rules) !== JSON.stringify(nextCompilation.rules);
}

function ruleSubscriptionLogTitle(reason: RuleSubscriptionRefreshReason, success: boolean): string {
  if (reason === "manual") {
    return success ? "加载规则订阅" : "加载规则订阅失败";
  }

  if (reason === "startup") {
    return success ? "启动检查规则订阅" : "启动检查规则订阅失败";
  }

  return success ? "定时检查规则订阅" : "定时检查规则订阅失败";
}

function createLogEntry(kind: AppLogKind, title: string, message: string, detail?: string): AppLogEntry {
  return {
    id: `${kind}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    kind,
    time: new Date().toISOString(),
    title,
    message,
    detail
  };
}

function mergeLogEntries(primaryLogs: AppLogEntry[], secondaryLogs: AppLogEntry[]): AppLogEntry[] {
  const seenIds = new Set<string>();
  const mergedLogs: AppLogEntry[] = [];

  for (const log of [...primaryLogs, ...secondaryLogs]) {
    if (seenIds.has(log.id) || !isStoredLogEntry(log)) {
      continue;
    }

    seenIds.add(log.id);
    mergedLogs.push(log);
  }

  return mergedLogs.slice(0, MAX_LOG_ENTRIES);
}

function readStoredLogs(): AppLogEntry[] {
  try {
    const rawLogs = window.localStorage.getItem(LOG_STORAGE_KEY);
    if (!rawLogs) {
      return [];
    }

    const parsedLogs = JSON.parse(rawLogs);
    if (!Array.isArray(parsedLogs)) {
      return [];
    }

    return parsedLogs.filter(isStoredLogEntry).slice(0, MAX_LOG_ENTRIES);
  } catch {
    return [];
  }
}

function clearStoredLogs() {
  try {
    window.localStorage.removeItem(LOG_STORAGE_KEY);
  } catch {
    // Legacy local storage cleanup is best-effort after file persistence succeeds.
  }
}

function readStoredThemeMode(): ThemeMode {
  try {
    const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isThemeMode(storedTheme) ? storedTheme : "system";
  } catch {
    return "system";
  }
}

function storeThemeMode(themeMode: ThemeMode) {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, themeMode);
  } catch {
    // Storage can be unavailable in restricted runtimes; visual theme still applies for this session.
  }
}

async function syncNativeWindowTheme(themeMode: ThemeMode): Promise<void> {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) {
    return;
  }

  const nativeTheme: Theme | null = themeMode === "system" ? null : themeMode;
  try {
    await getCurrentWindow().setTheme(nativeTheme);
  } catch {
    // Native title bar theming is platform/runtime dependent; keep the CSS theme applied.
  }
}

function isThemeMode(value: unknown): value is ThemeMode {
  return value === "system" || value === "light" || value === "dark";
}

function themeLabelKey(themeMode: ThemeMode): string {
  return `theme.${themeMode}`;
}

function isStoredLogEntry(value: unknown): value is AppLogEntry {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Partial<AppLogEntry>;

  return (
    isLogKind(candidate.kind) &&
    typeof candidate.id === "string" &&
    typeof candidate.time === "string" &&
    typeof candidate.title === "string" &&
    typeof candidate.message === "string" &&
    (candidate.detail === undefined || typeof candidate.detail === "string")
  );
}

function isLogKind(value: unknown): value is AppLogKind {
  return value === "scan" || value === "cleanup" || value === "operation";
}

function CategoryRows({
  candidates,
  language,
  onToggleCategory
}: {
  candidates: CleanupCandidate[];
  language: LanguageCode;
  onToggleCategory: (category: string) => void;
}) {
  const categories = useMemo(() => {
    const categoryMap = candidates.reduce<
      Record<string, { name: string; size: number; childCount: number; cleanableCount: number; selected: boolean }>
    >((nextCategories, candidate) => {
      const category = nextCategories[candidate.category] ?? {
        name: candidate.category,
        size: 0,
        childCount: 0,
        cleanableCount: 0,
        selected: false
      };

      category.size += candidate.sizeBytes;
      category.childCount += candidate.childrenCount;
      if (isCleanupSelectable(candidate)) {
        category.cleanableCount += 1;
        category.selected = category.selected || candidate.selected;
      }
      nextCategories[candidate.category] = category;
      return nextCategories;
    }, {});
    const itemText = language === "zh-CN" ? "项" : "items";

    return Object.values(categoryMap).map((category) => {
      const statusText =
        category.cleanableCount === 0
          ? translate(language, "cleanup.unsupported")
          : category.selected
            ? translate(language, "filter.selectedOnly")
            : translate(language, "cleanup.ready");

      return {
        name: category.name,
        size: category.size,
        meta: `${category.childCount.toLocaleString()} ${itemText} · ${statusText}`,
        selected: category.selected
      };
    });
  }, [candidates, language]);

  return (
    <div className="categoryList">
      {categories.map((category) => (
        <button
          key={category.name}
          className={`selectCard categoryCard ${category.selected ? "selected" : ""}`}
          onClick={() => onToggleCategory(category.name)}
        >
          <div className="rowTop">
            <span className="rowLeft">
              <span className="checkbox">{category.selected ? "✓" : ""}</span>
              <strong>{translateCategory(language, category.name)}</strong>
            </span>
            <strong>{formatBytes(category.size)}</strong>
          </div>
          <div className="rowMeta">{category.meta}</div>
        </button>
      ))}
      {categories.length === 0 ? <p className="emptyText">{translate(language, "scan.emptyTable")}</p> : null}
    </div>
  );
}

function DetailBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="detailBlock">
      <h3>{title}</h3>
      <div className="detailBody">{children}</div>
    </section>
  );
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="keyValue">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PlanRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="planRow">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
