import { useEffect, useState } from "react";
import { listAutomationReports } from "../api";
import { formatBytes } from "../state";
import { Dialog } from "./Dialog";
import { localizedLogKindLabel, type LanguageCode } from "../i18n";
import type { AppLogEntry, AutomationRunReport, LogFilter } from "../types";

export interface LogsDialogProps {
  logs: AppLogEntry[];
  filter: LogFilter;
  language: LanguageCode;
  onFilterChange: (filter: LogFilter) => void;
  onClear: () => void;
  onClose: () => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

const FILTERS: LogFilter[] = ["all", "scan", "cleanup", "operation"];

export function LogsDialog({
  logs,
  filter,
  language,
  onFilterChange,
  onClear,
  onClose,
  translate
}: LogsDialogProps) {
  const visibleLogs = filter === "all" ? logs : logs.filter((log) => log.kind === filter);
  const [automationReports, setAutomationReports] = useState<AutomationRunReport[]>([]);

  useEffect(() => {
    let disposed = false;
    void listAutomationReports()
      .then((reports) => {
        if (!disposed) setAutomationReports(reports);
      })
      .catch(() => undefined);
    return () => { disposed = true; };
  }, []);

  return (
    <Dialog
      title={translate("dialog.logs")}
      closeLabel={translate("button.close")}
      onClose={onClose}
      className="logDialog"
      footer={
        <>
          <button className="button" onClick={onClear}>
            {translate("button.clearLogs")}
          </button>
          <button className="button primary" onClick={onClose}>
            {translate("button.done")}
          </button>
        </>
      }
    >
      <div className="logFilters" role="tablist">
        {FILTERS.map((option) => (
          <button
            key={option}
            role="tab"
            aria-selected={filter === option}
            className={`tab ${filter === option ? "active" : ""}`}
            onClick={() => onFilterChange(option)}
          >
            {option === "all" ? translate("logs.all") : localizedLogKindLabel(language, option)}
          </button>
        ))}
      </div>

      {automationReports.length > 0 ? (
        <section className="automationReportSection">
          <h3>{language.startsWith("zh") ? "后台自动化运行" : "Background automation runs"}</h3>
          <ul className="logList">
            {automationReports.map((report) => (
              <li key={report.runId} className="logRow automation">
                <div className="logRowHead">
                  <span className={`badge ${report.status === "completed" ? "safe" : report.status === "failed" ? "warn" : "info"}`}>
                    {automationStatusLabel(report, language.startsWith("zh"))}
                  </span>
                  <strong>{report.trigger === "startup" ? (language.startsWith("zh") ? "登录启动" : "Sign-in") : (language.startsWith("zh") ? "周期任务" : "Scheduled")}</strong>
                  <time dateTime={report.startedAt}>{formatLogTime(report.startedAt, language)}</time>
                </div>
                <p className="logMessage">
                  {language.startsWith("zh")
                    ? `扫描 ${report.scannedCount} 项，可处理 ${report.eligibleCount} 项，已清理 ${report.cleanedCount} 项，释放 ${formatBytes(report.reclaimedBytes)}。`
                    : `Scanned ${report.scannedCount}, eligible ${report.eligibleCount}, cleaned ${report.cleanedCount}, reclaimed ${formatBytes(report.reclaimedBytes)}.`}
                </p>
                {report.capped || report.warnings.length > 0 ? <pre className="logDetail">{[report.capped ? (language.startsWith("zh") ? "已达到预算上限" : "Budget cap reached") : "", ...report.warnings].filter(Boolean).join("\n")}</pre> : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <ul className="logList">
        {visibleLogs.map((log) => (
          <li key={log.id} className={`logRow ${log.kind}`}>
            <div className="logRowHead">
              <span className={`badge ${logKindClass(log.kind)}`}>
                {localizedLogKindLabel(language, log.kind)}
              </span>
              <strong>{log.title}</strong>
              <time dateTime={log.time}>{formatLogTime(log.time, language)}</time>
            </div>
            <p className="logMessage">{log.message}</p>
            {log.detail ? <pre className="logDetail">{log.detail}</pre> : null}
          </li>
        ))}
      </ul>
    </Dialog>
  );
}

function automationStatusLabel(report: AutomationRunReport, zh: boolean): string {
  if (report.status === "failed") return zh ? "失败" : "Failed";
  if (report.status === "partial") return zh ? "部分完成" : "Partial";
  if (report.status === "started") return zh ? "运行中" : "Running";
  return zh ? "完成" : "Completed";
}

function logKindClass(kind: AppLogEntry["kind"]): string {
  if (kind === "scan") return "info";
  if (kind === "cleanup") return "safe";
  return "warn";
}

function formatLogTime(value: string, language: LanguageCode): string {
  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleTimeString(language, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}
