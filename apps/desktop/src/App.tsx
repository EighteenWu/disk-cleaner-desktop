import {
  FileText,
  HardDrive,
  CalendarClock,
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
  Trash2
} from "lucide-react";
import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { getCurrentWindow, type Theme } from "@tauri-apps/api/window";
import appLogoUrl from "./assets/diskclean-logo.png";
import {
  cancelCleanup,
  executeCleanupPlan,
  getAdminStatus,
  getScanSnapshot,
  listCandidateChildren,
  listInventoryLargest,
  listenCleanupProgress,
  listenScanProgress,
  notifyScanComplete,
  pauseCleanup,
  pauseScan,
  previewCleanupPlan,
  restartAsAdmin,
  resumeCleanup,
  resumeScan,
  revealPath,
  runScan,
  searchInventory
} from "./api";
import { AutomationDialog } from "./components/AutomationDialog";
import { Checkbox } from "./components/Checkbox";
import { CleanupDialog } from "./components/CleanupDialog";
import { DetailPanel } from "./components/DetailPanel";
import { DriveDialog } from "./components/DriveDialog";
import { GroupList } from "./components/GroupList";
import { LogsDialog } from "./components/LogsDialog";
import { RulesDialog } from "./components/RulesDialog";
import { ScanPanel } from "./components/ScanPanel";
import { SpaceAnalysisPanel } from "./components/SpaceAnalysisPanel";
import { StatusBar } from "./components/StatusBar";
import {
  applyRecommendedSelection,
  buildCandidateGroups,
  groupsSelectedSummary,
  setGroupSelection
} from "./groups";
import {
  createTranslator,
  languageOptions,
  localizedPrimaryActionLabel,
  localizedScanModeLabel,
  readStoredLanguage,
  storeLanguage,
  type LanguageCode
} from "./i18n";
import { mergeInventoryItems } from "./inventory";
import {
  aiRuleGenerationReady,
  formatDuration,
  INITIAL_SESSION,
  isBusy,
  isScanBusy,
  primaryAction,
  sessionReducer,
  truncatePathMiddle
} from "./session";
import {
  cleanupBatches,
  cleanupPreviewSummary,
  filterCandidates,
  formatBytes,
  isCleanupSelectable,
  mergeCleanupReports,
  mergeRefreshedVolumes,
  removeCandidates,
  scopeCandidatesToVolumes,
  selectedCandidateIds,
  selectedVolumeIds,
  setCandidateSelection,
  toggleCandidate,
  toggleVolume
} from "./state";
import { useAppLogs } from "./useAppLogs";
import { useAiRuleGeneration } from "./useAiRuleGeneration";
import { useRuleSources } from "./useRuleSources";
import type {
  CleanupCandidate,
  InventoryQueryItem,
  LogFilter,
  RiskFilter,
  ScanMode,
  SourceKind
} from "./types";

const THEME_STORAGE_KEY = "diskclean.theme.v1";
const CLEANUP_BATCH_SIZE = 40;

type ThemeMode = "system" | "light" | "dark";
type DialogKind = "drive" | "rules" | "automation" | "logs" | "cleanup";

const THEME_SEQUENCE: ThemeMode[] = ["system", "light", "dark"];

export function App() {
  const [language, setLanguage] = useState<LanguageCode>(() => readStoredLanguage());
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => readStoredThemeMode());
  const t = useMemo(() => createTranslator(language), [language]);

  const [session, dispatch] = useReducer(sessionReducer, INITIAL_SESSION);
  const [candidates, setCandidates] = useState<CleanupCandidate[]>([]);
  const [expandedKinds, setExpandedKinds] = useState<ReadonlySet<SourceKind>>(new Set());
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [children, setChildren] = useState<CleanupCandidate[]>([]);
  const [childrenLoading, setChildrenLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [showSelectedOnly, setShowSelectedOnly] = useState(false);
  const [openDialog, setOpenDialog] = useState<DialogKind | null>(null);
  const [logFilter, setLogFilter] = useState<LogFilter>("all");
  const [permanentDelete, setPermanentDelete] = useState(false);
  const [adminStatus, setAdminStatus] = useState<{ isAdmin: boolean; canRestartElevated: boolean } | null>(null);
  const [volumesRefreshing, setVolumesRefreshing] = useState(false);
  const [notice, setNotice] = useState(() => t("app.ready"));
  const [inventoryItems, setInventoryItems] = useState<InventoryQueryItem[]>([]);
  const [inventoryQuery, setInventoryQuery] = useState("");
  const [inventoryMode, setInventoryMode] = useState<"largest" | "search">("largest");
  const [inventoryCursor, setInventoryCursor] = useState<string | null>(null);
  const [inventoryLoading, setInventoryLoading] = useState(false);
  const [inventoryError, setInventoryError] = useState<string | null>(null);

  const snapshotLoaded = useRef(false);
  const inventoryRequestId = useRef(0);
  const { logs, appendLog, replaceLogs } = useAppLogs();

  const logOperation = useCallback(
    (title: string, message: string, detail?: string) => appendLog("operation", title, message, detail),
    [appendLog]
  );

  const rules = useRuleSources({ onNotice: setNotice, onLog: logOperation, translate: t });
  const aiRules = useAiRuleGeneration(rules, t);

  const clearLogs = useCallback(() => {
    replaceLogs([]);
    appendLog("operation", t("button.clearLogs"), t("logs.empty"));
  }, [appendLog, replaceLogs, t]);

  const volumes = session.snapshot?.volumes ?? [];
  const busy = isBusy(session);
  const scanBusy = isScanBusy(session);
  const action = primaryAction(session);

  const selectedVolumeSet = useMemo(() => selectedVolumeIds(volumes), [volumes]);
  const activeCandidates = useMemo(
    () => scopeCandidatesToVolumes(candidates, selectedVolumeSet),
    [candidates, selectedVolumeSet]
  );
  const searchedCandidates = useMemo(
    () => filterCandidates(activeCandidates, query, riskFilter),
    [activeCandidates, query, riskFilter]
  );
  const filteredCandidates = useMemo(
    () => (showSelectedOnly ? searchedCandidates.filter((candidate) => candidate.selected) : searchedCandidates),
    [searchedCandidates, showSelectedOnly]
  );
  const groups = useMemo(() => buildCandidateGroups(filteredCandidates), [filteredCandidates]);
  const summary = useMemo(() => groupsSelectedSummary(buildCandidateGroups(activeCandidates)), [activeCandidates]);
  const currentSelectedIds = useMemo(() => selectedCandidateIds(activeCandidates), [activeCandidates]);
  const cleanupPlan = useMemo(
    () =>
      cleanupPreviewSummary(
        activeCandidates,
        permanentDelete ? "permanentDelete" : "moveToRecycleBin"
      ),
    [activeCandidates, permanentDelete]
  );
  const focusedCandidate = useMemo(
    () => activeCandidates.find((candidate) => candidate.id === focusedId) ?? null,
    [activeCandidates, focusedId]
  );

  const formatCount = useCallback(
    (value: number) => new Intl.NumberFormat(language).format(value),
    [language]
  );

  useEffect(() => {
    const sessionId = session.snapshot?.scanSessionId;
    if (!sessionId) {
      setInventoryItems([]);
      setInventoryCursor(null);
      setInventoryError(null);
      return;
    }
    void loadInventoryPage("largest", null, false, "");
  }, [session.snapshot?.scanSessionId]);

  async function loadInventoryPage(
    mode: "largest" | "search",
    cursor: string | null,
    append: boolean,
    searchQuery: string
  ) {
    const sessionId = session.snapshot?.scanSessionId;
    if (!sessionId) {
      return;
    }
    const requestId = ++inventoryRequestId.current;
    setInventoryLoading(true);
    setInventoryError(null);
    try {
      const page =
        mode === "largest"
          ? await listInventoryLargest(sessionId, cursor, 50)
          : await searchInventory(sessionId, searchQuery, cursor, 50);
      if (requestId !== inventoryRequestId.current) {
        return;
      }
      setInventoryMode(mode);
      setInventoryItems((current) => mergeInventoryItems(current, page.items, append));
      setInventoryCursor(page.nextCursor);
    } catch (error) {
      if (requestId === inventoryRequestId.current) {
        setInventoryError(t("inventory.queryFailed", { message: errorMessage(error) }));
      }
    } finally {
      if (requestId === inventoryRequestId.current) {
        setInventoryLoading(false);
      }
    }
  }

  useEffect(() => {
    storeLanguage(language);
    document.documentElement.lang = language;
    document.title = t("app.name");
  }, [language, t]);

  useEffect(() => {
    storeThemeMode(themeMode);
    document.documentElement.dataset.theme = themeMode;
    void syncNativeWindowTheme(themeMode);
  }, [themeMode]);

  useEffect(() => {
    if (snapshotLoaded.current) {
      return;
    }

    snapshotLoaded.current = true;
    void getScanSnapshot().then((snapshot) => {
      dispatch({ type: "snapshotLoaded", snapshot });
      appendLog(
        "scan",
        t("scan.volumesLoadedLog"),
        t("scan.volumesLoaded", { count: snapshot.volumes.length }),
        t("scan.doneBackend", { backend: snapshot.scanBackend })
      );
    });
    void getAdminStatus().then(setAdminStatus);
    // Mount-only bootstrap; re-running on translator identity would refetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;

    void listenScanProgress((progress) => {
      if (!disposed) {
        dispatch({ type: "scanProgress", progress });
      }
    })
      .then((dispose) => {
        if (disposed) {
          dispose();
          return;
        }

        unlisten = dispose;
      })
      .catch((error) => {
        appendLog("scan", t("scan.progressListenFailedLog"), errorMessage(error));
      });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [appendLog, t]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;

    void listenCleanupProgress((progress) => {
      if (!disposed) {
        dispatch({ type: "cleanupProgress", progress });
      }
    })
      .then((dispose) => {
        if (disposed) {
          dispose();
          return;
        }

        unlisten = dispose;
      })
      .catch((error) => {
        appendLog("cleanup", t("cleanup.progressListenFailedLog"), errorMessage(error));
      });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [appendLog, t]);

  useEffect(() => {
    if (session.scan.startedAt === null && session.cleanup.startedAt === null) {
      return;
    }

    const timerId = window.setInterval(() => dispatch({ type: "tick", at: Date.now() }), 500);

    return () => window.clearInterval(timerId);
  }, [session.cleanup.startedAt, session.scan.startedAt]);

  // Only the path identifies which directory to expand. The previous version
  // depended on twelve candidate fields, one of which was a fresh array on every
  // render, so this effect re-fired a backend call on each keystroke.
  const focusedPath = focusedCandidate?.path ?? null;
  const focusedIsDirectory = focusedCandidate?.objectType === "directory";

  useEffect(() => {
    if (focusedPath === null || !focusedIsDirectory || !focusedCandidate) {
      setChildren([]);
      setChildrenLoading(false);
      return;
    }

    let disposed = false;
    setChildrenLoading(true);

    void listCandidateChildren(focusedCandidate)
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
        appendLog("operation", t("candidate.readDirFailedLog"), focusedPath, errorMessage(error));
      })
      .finally(() => {
        if (!disposed) {
          setChildrenLoading(false);
        }
      });

    return () => {
      disposed = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appendLog, focusedIsDirectory, focusedPath, t]);

  async function startScan() {
    if (scanBusy) {
      setNotice(t("scan.alreadyRunning"));
      return;
    }

    const volumeIds = Array.from(selectedVolumeSet);
    const modeLabel = localizedScanModeLabel(language, session.mode);
    const startedAt = Date.now();

    setChildren([]);
    setInventoryItems([]);
    setInventoryCursor(null);
    setInventoryError(null);
    setFocusedId(null);
    setExpandedKinds(new Set());
    dispatch({ type: "scanStarted", at: startedAt });
    setNotice(t("scan.running", { mode: modeLabel }));
    appendLog(
      "scan",
      t("scan.startedLog", { mode: modeLabel }),
      t("scan.startedDetail", {
        volumes: volumeIds.length > 0 ? volumeIds.join(", ") : t("scan.defaultVolumes"),
        rules: rules.activeRules.length
      })
    );

    try {
      const snapshot = await runScan({
        mode: session.mode,
        volumeIds,
        rules: rules.activeRules
      });

      dispatch({ type: "scanSucceeded", snapshot, at: Date.now() });
      // Default to the safe subset so the one-click path is ready immediately.
      setCandidates(applyRecommendedSelection(snapshot.candidates));
      setNotice(
        session.mode === "full" && snapshot.coverage.status !== "complete"
          ? t("scan.incompleteNotice", {
              status: t(`inventory.status.${snapshot.coverage.status}`)
            })
          : snapshot.warnings.length > 0
          ? t("scan.doneWithWarnings", { mode: modeLabel })
          : t("scan.doneNotice", {
              mode: modeLabel,
              count: snapshot.summary.candidateCount,
              backend: snapshot.scanBackend
            })
      );
      appendLog(
        "scan",
        t("scan.doneLog"),
        t("scan.doneDetail", {
          count: snapshot.summary.candidateCount,
          size: formatBytes(snapshot.summary.estimatedReclaimBytes)
        }),
        t("scan.doneBackend", { backend: snapshot.scanBackend })
      );
      void notifyScanComplete(
        t("scan.doneLog"),
        t("scan.doneDetail", {
          count: snapshot.summary.candidateCount,
          size: formatBytes(snapshot.summary.estimatedReclaimBytes)
        })
      );
    } catch (error) {
      const message = errorMessage(error);
      dispatch({ type: "scanFailed", error: message, at: Date.now() });
      setNotice(t("scan.failedNotice", { message }));
      appendLog("scan", t("scan.failedLog"), message);
    }
  }

  async function toggleScanPause() {
    if (session.phase === "scanning") {
      try {
        await pauseScan();
        dispatch({ type: "scanPaused" });
        setNotice(t("scan.pausedNotice"));
        appendLog("operation", t("scan.pausedLog"), t("scan.pausedDetail"));
      } catch (error) {
        const message = errorMessage(error);
        setNotice(t("scan.pauseFailedNotice", { message }));
        appendLog("operation", t("scan.pauseFailedLog"), message);
      }
      return;
    }

    if (session.phase === "scanPaused") {
      try {
        await resumeScan();
        dispatch({ type: "scanResumed" });
        setNotice(t("scan.resumedNotice"));
        appendLog("operation", t("scan.resumedLog"), t("scan.resumedDetail"));
      } catch (error) {
        const message = errorMessage(error);
        setNotice(t("scan.resumeFailedNotice", { message }));
        appendLog("operation", t("scan.resumeFailedLog"), message);
      }
      return;
    }

    setNotice(t("scan.noneRunning"));
  }

  function runPrimaryAction() {
    if (action === "pause" || action === "resume") {
      void toggleScanPause();
      return;
    }

    void startScan();
  }

  async function refreshVolumes() {
    if (scanBusy) {
      setNotice(t("volume.refreshBusy"));
      return;
    }

    setVolumesRefreshing(true);
    setNotice(t("volume.refreshing"));

    try {
      const snapshot = await getScanSnapshot();

      if (session.snapshot) {
        dispatch({
          type: "snapshotReplaced",
          snapshot: {
            ...session.snapshot,
            volumes: mergeRefreshedVolumes(session.snapshot.volumes, snapshot.volumes)
          }
        });
      } else {
        dispatch({ type: "snapshotLoaded", snapshot });
      }
    } catch (error) {
      appendLog("scan", t("volume.refreshFailedLog"), errorMessage(error));
    } finally {
      setVolumesRefreshing(false);
    }
  }

  function updateVolumeSelection(volumeId: string) {
    if (!session.snapshot) {
      return;
    }

    dispatch({
      type: "snapshotReplaced",
      snapshot: { ...session.snapshot, volumes: toggleVolume(session.snapshot.volumes, volumeId) }
    });
    appendLog("operation", t("volume.toggleLog"), t("volume.toggleDetail", { volume: volumeId }));
  }

  function toggleGroupExpanded(kind: SourceKind) {
    setExpandedKinds((current) => {
      const next = new Set(current);

      if (next.has(kind)) {
        next.delete(kind);
      } else {
        next.add(kind);
      }

      return next;
    });
  }

  function toggleGroup(kind: SourceKind, selected: boolean) {
    setCandidates((current) => setGroupSelection(current, kind, selected));
  }

  function selectRecommended() {
    setCandidates(applyRecommendedSelection);
    setNotice(t("select.recommendedHint"));
  }

  function selectVisible() {
    const visibleIds = filteredCandidates
      .filter(isCleanupSelectable)
      .map((candidate) => candidate.id);
    setCandidates((current) => setCandidateSelection(current, visibleIds, true));
  }

  function clearSelection() {
    setCandidates((current) =>
      setCandidateSelection(
        current,
        current.filter(isCleanupSelectable).map((candidate) => candidate.id),
        false
      )
    );
  }

  async function runCleanup() {
    if (currentSelectedIds.length === 0) {
      setNotice(t("candidate.needSelection"));
      return;
    }

    const batches = cleanupBatches(activeCandidates, currentSelectedIds, CLEANUP_BATCH_SIZE);

    if (batches.length === 0) {
      setNotice(t("candidate.nothingToClean"));
      return;
    }

    const totalCount = batches.reduce((total, batch) => total + batch.selectedIds.length, 0);
    dispatch({ type: "cleanupStarted", totalCount, at: Date.now() });

    try {
      const reports = [];

      const deleteStrategy = permanentDelete ? "permanentDelete" : "moveToRecycleBin";

      for (const batch of batches) {
        reports.push(
          await executeCleanupPlan(batch.candidates, batch.selectedIds, deleteStrategy)
        );
      }

      const report = mergeCleanupReports(reports);
      const remaining = removeCandidates(candidates, report.cleanedIds);
      setCandidates(remaining);

      if (session.snapshot) {
        dispatch({
          type: "cleanupSettled",
          report,
          snapshot: { ...session.snapshot, candidates: remaining },
          at: Date.now()
        });
      }

      setNotice(
        t("cleanup.completedNotice", {
          count: report.cleanedCount,
          failed: report.failedCount,
          size: formatBytes(report.reclaimedBytes)
        })
      );
      appendLog(
        "cleanup",
        t("cleanup.done"),
        t("cleanup.completedNotice", {
          count: report.cleanedCount,
          failed: report.failedCount,
          size: formatBytes(report.reclaimedBytes)
        })
      );
    } catch (error) {
      const message = errorMessage(error);
      dispatch({ type: "cleanupFailed", error: message, at: Date.now() });
      appendLog("cleanup", t("cleanup.failedLog"), message);
    }
  }

  async function pauseCleanupRun() {
    try {
      await pauseCleanup();
      dispatch({ type: "cleanupPaused" });
      appendLog("cleanup", t("cleanup.pauseLog"), t("cleanup.pauseDetail"));
    } catch (error) {
      appendLog("cleanup", t("cleanup.pauseFailedLog"), errorMessage(error));
    }
  }

  async function resumeCleanupRun() {
    try {
      await resumeCleanup();
      dispatch({ type: "cleanupResumed" });
      appendLog("cleanup", t("cleanup.resumeLog"), t("cleanup.resumeDetail"));
    } catch (error) {
      appendLog("cleanup", t("cleanup.resumeFailedLog"), errorMessage(error));
    }
  }

  async function cancelCleanupRun() {
    try {
      dispatch({ type: "cleanupCanceling" });
      await cancelCleanup();
      appendLog("cleanup", t("cleanup.cancelLog"), t("cleanup.cancelDetail"));
    } catch (error) {
      appendLog("cleanup", t("cleanup.cancelFailedLog"), errorMessage(error));
    }
  }

  async function openCleanupDialog() {
    if (currentSelectedIds.length === 0) {
      setNotice(t("candidate.needSelection"));
      return;
    }

    setOpenDialog("cleanup");
    // Warm the backend plan so warnings appear before the user confirms.
    void previewCleanupPlan(activeCandidates, currentSelectedIds).catch(() => undefined);
  }

  async function elevate() {
    try {
      await restartAsAdmin();
      appendLog("operation", t("admin.elevateLog"), t("admin.elevateDetail"));
    } catch (error) {
      appendLog("operation", t("admin.elevateFailedLog"), errorMessage(error));
    }
  }

  function cycleTheme() {
    const nextMode =
      THEME_SEQUENCE[(THEME_SEQUENCE.indexOf(themeMode) + 1) % THEME_SEQUENCE.length] ?? "system";
    setThemeMode(nextMode);
  }

  if (!session.snapshot) {
    return <div className="loading">{t("app.loading")}</div>;
  }

  const ThemeIcon = themeMode === "dark" ? Moon : themeMode === "light" ? Sun : Monitor;
  const PrimaryIcon =
    action === "pause" ? Pause : action === "resume" ? Play : action === "rescan" ? RefreshCw : Search;

  return (
    <div className="window">
      <header className="commandbar">
        <div className="commandTitle">
          <img className="appLogo" src={appLogoUrl} alt="" aria-hidden="true" />
          <h1>{t("app.name")}</h1>
        </div>

        <div className="commandActions">
          <span
            className={`adminBadge ${adminStatus?.isAdmin ? "safe" : "warn"}`}
            title={adminStatus?.isAdmin ? t("admin.elevatedHint") : t("admin.limitedHint")}
          >
            <Shield size={14} />
            {adminStatus
              ? adminStatus.isAdmin
                ? t("admin.admin")
                : t("admin.notAdmin")
              : t("admin.checking")}
          </span>

          {adminStatus && !adminStatus.isAdmin && adminStatus.canRestartElevated ? (
            <button className="button" onClick={() => void elevate()}>
              <Shield size={14} />
              {t("admin.restart")}
            </button>
          ) : null}

          <label className="languageSelect" aria-label={t("language.label")}>
            <Languages size={14} />
            <select
              value={language}
              onChange={(event) => setLanguage(event.currentTarget.value as LanguageCode)}
            >
              {languageOptions.map((option) => (
                <option key={option.code} value={option.code}>
                  {option.nativeLabel}
                </option>
              ))}
            </select>
          </label>

          <button className="iconButton" onClick={cycleTheme} title={t(themeLabelKey(themeMode))}>
            <ThemeIcon size={16} />
          </button>
          <button className="iconButton" onClick={() => setOpenDialog("rules")} title={t("nav.rules")}>
            <Settings size={16} />
          </button>
          <button
            className="iconButton"
            onClick={() => setOpenDialog("automation")}
            title={language.startsWith("zh") ? "自动扫描与清理" : "Automation"}
          >
            <CalendarClock size={16} />
          </button>
          <button className="iconButton" onClick={() => setOpenDialog("logs")} title={t("nav.logs")}>
            <FileText size={16} />
          </button>
        </div>
      </header>

      <main className="workbench">
        <aside className="pane leftPane">
          <div className="paneHeader">
            <h2>{t("nav.drives")}</h2>
            <button
              className="ghostButton"
              onClick={() => void refreshVolumes()}
              disabled={scanBusy || volumesRefreshing}
            >
              {volumesRefreshing ? t("button.refreshing") : t("button.refresh")}
            </button>
          </div>

          <div className="paneContent">
            <ul className="driveList">
              {volumes.map((volume) => {
                const usedPercent = Math.max(
                  2,
                  Math.round(((volume.totalBytes - volume.availableBytes) / volume.totalBytes) * 100)
                );

                return (
                  <li key={volume.id} className={`driveCard ${volume.selected ? "selected" : ""}`}>
                    <div className="driveCardTop">
                      <Checkbox
                        state={volume.selected ? "all" : "none"}
                        label={volume.id}
                        disabled={scanBusy}
                        onChange={() => updateVolumeSelection(volume.id)}
                      />
                      <strong>{volume.id}:</strong>
                      <span className={`badge ${volume.supportsFastIndex ? "safe" : "info"}`}>
                        {volume.filesystem}
                      </span>
                    </div>
                    <p className="driveCardMeta">
                      {t("drive.available", {
                        available: formatBytes(volume.availableBytes),
                        total: formatBytes(volume.totalBytes)
                      })}
                    </p>
                    <div className="meter">
                      <span style={{ width: `${usedPercent}%` }} />
                    </div>
                  </li>
                );
              })}
            </ul>

            <section className="section">
              <h3 className="sectionTitle">{t("scan.mode")}</h3>
              <div className="modeList" role="radiogroup" aria-label={t("scan.mode")}>
                {(["quick", "full"] as ScanMode[]).map((mode) => (
                  <button
                    key={mode}
                    role="radio"
                    aria-checked={session.mode === mode}
                    className={`modeCard ${session.mode === mode ? "selected" : ""}`}
                    disabled={scanBusy}
                    onClick={() => {
                      dispatch({ type: "modeChanged", mode });
                      const label = localizedScanModeLabel(language, mode);
                      setNotice(t("scan.modeSwitched", { mode: label }));
                      appendLog("operation", t("scan.modeSwitchedLog"), label);
                    }}
                  >
                    {localizedScanModeLabel(language, mode)}
                  </button>
                ))}
              </div>
            </section>

            <button className="ghostButton wide" onClick={() => setOpenDialog("drive")}>
              <HardDrive size={14} />
              {t("dialog.drive")}
            </button>
          </div>
        </aside>

        <section className="pane centerPane">
          <div className="scanBar">
            <button className="button primary large" onClick={runPrimaryAction}>
              <PrimaryIcon size={16} />
              {localizedPrimaryActionLabel(language, action)}
            </button>
            <button
              className="button danger large"
              onClick={() => void openCleanupDialog()}
              disabled={busy || summary.selectedCount === 0}
            >
              <Trash2 size={16} />
              {t("cleanup.previewAndRun")}
            </button>
            <span className="scanBarSummary">
              {t("status.selected", {
                count: summary.selectedCount,
                size: formatBytes(summary.selectedBytes)
              })}
            </span>
          </div>

          <ScanPanel
            session={session}
            language={language}
            formatCount={formatCount}
            formatDuration={formatDuration}
            truncatePath={truncatePathMiddle}
            translate={t}
          />

          {session.snapshot ? (
            <SpaceAnalysisPanel
              snapshot={session.snapshot}
              items={inventoryItems}
              query={inventoryQuery}
              mode={inventoryMode}
              loading={inventoryLoading}
              error={inventoryError}
              hasMore={inventoryCursor !== null}
              onQueryChange={setInventoryQuery}
              onSearch={() =>
                void loadInventoryPage("search", null, false, inventoryQuery.trim())
              }
              onShowLargest={() => void loadInventoryPage("largest", null, false, "")}
              onLoadMore={() =>
                void loadInventoryPage(
                  inventoryMode,
                  inventoryCursor,
                  true,
                  inventoryQuery.trim()
                )
              }
              onReveal={(path) => {
                void revealPath(path).catch((error) =>
                  setInventoryError(
                    t("inventory.revealFailed", { message: errorMessage(error) })
                  )
                );
              }}
              translate={t}
            />
          ) : null}

          <div className="filterBar">
            <label className="searchField">
              <Search size={14} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={t("scan.searchPlaceholder")}
              />
            </label>
            <div className="riskTabs" role="tablist">
              {(["all", "recommended", "caution", "dangerous"] as RiskFilter[]).map((filter) => (
                <button
                  key={filter}
                  role="tab"
                  aria-selected={riskFilter === filter}
                  className={`tab ${riskFilter === filter ? "active" : ""}`}
                  onClick={() => setRiskFilter(filter)}
                >
                  {t(`filter.${filter}`)}
                </button>
              ))}
            </div>
            <button
              className={`ghostButton ${showSelectedOnly ? "active" : ""}`}
              onClick={() => setShowSelectedOnly((value) => !value)}
            >
              {t("filter.selectedOnly")}
            </button>
          </div>

          <div className="selectionBar">
            <button
              className="ghostButton"
              onClick={selectVisible}
              disabled={busy || !filteredCandidates.some(isCleanupSelectable)}
            >
              {t("select.allVisible")}
            </button>
            <button className="ghostButton" onClick={selectRecommended} disabled={busy}>
              {t("select.recommended")}
            </button>
            <button className="ghostButton" onClick={clearSelection} disabled={busy}>
              {t("select.none")}
            </button>
          </div>

          <div className="groupArea">
            <GroupList
              groups={groups}
              expandedKinds={expandedKinds}
              selectedCandidateId={focusedId ?? ""}
              language={language}
              busy={busy}
              emptyLabel={t("group.empty")}
              onToggleExpanded={toggleGroupExpanded}
              onToggleGroup={toggleGroup}
              onToggleCandidate={(candidateId) =>
                setCandidates((current) => toggleCandidate(current, candidateId))
              }
              onFocusCandidate={(candidate) => setFocusedId(candidate.id)}
              translate={t}
            />
          </div>
        </section>

        <aside className="pane rightPane">
          <div className="paneHeader">
            <h2>{t("detail.current")}</h2>
          </div>
          <div className="paneContent">
            <DetailPanel
              candidate={focusedCandidate}
              children={children}
              childrenLoading={childrenLoading}
              language={language}
              onReveal={(candidate) => {
                void revealPath(candidate.path).catch((error) =>
                  appendLog("operation", t("candidate.revealFailedLog"), errorMessage(error))
                );
              }}
              translate={t}
            />
          </div>
        </aside>
      </main>

      <StatusBar
        session={session}
        selectedCount={summary.selectedCount}
        selectedBytes={summary.selectedBytes}
        notice={notice}
        formatCount={formatCount}
        translate={t}
      />

      {openDialog === "drive" ? (
        <DriveDialog
          volumes={volumes}
          busy={scanBusy}
          onToggleVolume={updateVolumeSelection}
          onClose={() => setOpenDialog(null)}
          translate={t}
        />
      ) : null}

      {openDialog === "rules" ? (
        <RulesDialog
          rules={rules}
          ai={aiRules}
          snapshot={session.snapshot}
          aiGenerationReady={aiRuleGenerationReady(session)}
          onClose={() => setOpenDialog(null)}
          translate={t}
        />
      ) : null}

      {openDialog === "automation" ? (
        <AutomationDialog
          language={language}
          onClose={() => setOpenDialog(null)}
          onNotice={setNotice}
        />
      ) : null}

      {openDialog === "logs" ? (
        <LogsDialog
          logs={logs}
          filter={logFilter}
          language={language}
          onFilterChange={setLogFilter}
          onClear={clearLogs}
          onClose={() => setOpenDialog(null)}
          translate={t}
        />
      ) : null}

      {openDialog === "cleanup" ? (
        <CleanupDialog
          session={session}
          plan={cleanupPlan}
          permanentDelete={permanentDelete}
          language={language}
          onPermanentDeleteChange={setPermanentDelete}
          onConfirm={() => void runCleanup()}
          onPause={() => void pauseCleanupRun()}
          onResume={() => void resumeCleanupRun()}
          onCancel={() => void cancelCleanupRun()}
          onClose={() => setOpenDialog(null)}
          formatDuration={formatDuration}
          translate={t}
        />
      ) : null}
    </div>
  );
}

function themeLabelKey(themeMode: ThemeMode): string {
  return `theme.${themeMode}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}



function readStoredThemeMode(): ThemeMode {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);

    return stored === "light" || stored === "dark" || stored === "system" ? stored : "system";
  } catch {
    return "system";
  }
}

function storeThemeMode(themeMode: ThemeMode) {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, themeMode);
  } catch {
    // Storage can be unavailable; the in-memory value still applies.
  }
}

async function syncNativeWindowTheme(themeMode: ThemeMode) {
  try {
    const theme: Theme | null = themeMode === "system" ? null : themeMode;
    await getCurrentWindow().setTheme(theme);
  } catch {
    // Only available inside the Tauri shell.
  }
}
