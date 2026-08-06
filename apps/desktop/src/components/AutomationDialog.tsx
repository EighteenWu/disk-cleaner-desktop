import { useEffect, useState } from "react";
import { getAutomationConfig, getAutomationSchedulerStatus, saveAutomationConfig } from "../api";
import type { AutomationConfig, AutomationSchedulerStatus } from "../types";
import type { LanguageCode } from "../i18n";
import { formatBytes } from "../state";
import { Dialog } from "./Dialog";

interface AutomationDialogProps {
  language: LanguageCode;
  onClose: () => void;
  onNotice: (message: string) => void;
}

export function AutomationDialog({ language, onClose, onNotice }: AutomationDialogProps) {
  const zh = language.startsWith("zh");
  const [config, setConfig] = useState<AutomationConfig | null>(null);
  const [status, setStatus] = useState<AutomationSchedulerStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let disposed = false;
    void Promise.all([getAutomationConfig(), getAutomationSchedulerStatus()])
      .then(([nextConfig, nextStatus]) => {
        if (!disposed) {
          setConfig(nextConfig);
          setStatus(nextStatus);
        }
      })
      .catch((reason: unknown) => !disposed && setError(errorMessage(reason)));
    return () => { disposed = true; };
  }, []);

  async function save() {
    if (!config) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await saveAutomationConfig(config);
      const nextStatus = await getAutomationSchedulerStatus();
      setConfig(saved);
      setStatus(nextStatus);
      onNotice(zh ? "自动化设置已保存并同步到 Windows 任务计划程序。" : "Automation settings saved and synchronized with Windows Task Scheduler.");
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={zh ? "自动扫描与清理" : "Automated scanning and cleanup"}
      subtitle={zh ? "每次运行都会重新扫描；只有当前有效、已批准的轻度 AI 规则可自动清理。" : "Every run rescans. Only current, approved light AI rules are eligible for unattended cleanup."}
      closeLabel={zh ? "关闭" : "Close"}
      onClose={onClose}
      className="automationDialog"
      footer={<><button className="button" onClick={onClose}>{zh ? "取消" : "Cancel"}</button><button className="button primary" disabled={!config || busy} onClick={() => void save()}>{busy ? (zh ? "保存中…" : "Saving…") : (zh ? "保存并同步" : "Save and sync")}</button></>}
    >
      {!config ? <p>{error ?? (zh ? "正在读取自动化设置…" : "Loading automation settings…")}</p> : (
        <div className="automationSettings">
          <section className="ruleSection">
            <h3>{zh ? "触发方式" : "Triggers"}</h3>
            <label className="automationToggle"><input type="checkbox" checked={config.startupEnabled} onChange={(event) => setConfig({ ...config, startupEnabled: event.currentTarget.checked })} />{zh ? "登录 Windows 后运行" : "Run after Windows sign-in"}<span className={`badge ${status?.startupRegistered ? "safe" : "info"}`}>{status?.startupRegistered ? (zh ? "已注册" : "Registered") : (zh ? "未注册" : "Not registered")}</span></label>
            <label className="automationToggle"><input type="checkbox" checked={config.scheduleEnabled} onChange={(event) => setConfig({ ...config, scheduleEnabled: event.currentTarget.checked })} />{zh ? "启用周期任务" : "Enable scheduled task"}<span className={`badge ${status?.scheduleRegistered ? "safe" : "info"}`}>{status?.scheduleRegistered ? (zh ? "已注册" : "Registered") : (zh ? "未注册" : "Not registered")}</span></label>
            <div className="automationGrid">
              <label>{zh ? "周期" : "Cadence"}<select value={config.cadence} disabled={!config.scheduleEnabled} onChange={(event) => setConfig({ ...config, cadence: event.currentTarget.value as AutomationConfig["cadence"] })}><option value="daily">{zh ? "每天" : "Daily"}</option><option value="weekly">{zh ? "每周" : "Weekly"}</option></select></label>
              <label>{zh ? "本地时间" : "Local time"}<input type="time" value={config.localTime} disabled={!config.scheduleEnabled} onChange={(event) => setConfig({ ...config, localTime: event.currentTarget.value })} /></label>
              {config.cadence === "weekly" ? <label>{zh ? "星期" : "Weekday"}<select value={config.weekday ?? 1} disabled={!config.scheduleEnabled} onChange={(event) => setConfig({ ...config, weekday: Number(event.currentTarget.value) })}>{[1,2,3,4,5,6,7].map((day) => <option key={day} value={day}>{weekdayLabel(day, zh)}</option>)}</select></label> : null}
            </div>
          </section>

          <section className="ruleSection">
            <h3>{zh ? "运行策略" : "Run policy"}</h3>
            <label>{zh ? "模式" : "Mode"}<select value={config.mode} onChange={(event) => setConfig({ ...config, mode: event.currentTarget.value as AutomationConfig["mode"] })}><option value="scanOnly">{zh ? "仅扫描和报告" : "Scan and report only"}</option><option value="scanAndCleanup">{zh ? "扫描并清理已批准轻度规则" : "Scan and clean approved light rules"}</option></select></label>
            <p className="dialogSubtitle">{zh ? "清理始终使用 Windows 回收站；中度、重度、手工及订阅规则只会出现在报告中。" : "Cleanup always uses the Windows Recycle Bin. Medium, heavy, manual, and subscription rules remain report-only."}</p>
          </section>

          <section className="ruleSection">
            <h3>{zh ? "硬预算" : "Hard budgets"}</h3>
            <div className="automationGrid">
              <label>{zh ? "最多项目数" : "Maximum items"}<input type="number" min={1} max={1000} value={config.limits.maxWorkItems} onChange={(event) => setConfig({ ...config, limits: { ...config.limits, maxWorkItems: Number(event.currentTarget.value) } })} /></label>
              <label>{zh ? "容量上限（GiB）" : "Size cap (GiB)"}<input type="number" min={1} max={10} value={Math.round(config.limits.maxBytes / 1073741824)} onChange={(event) => setConfig({ ...config, limits: { ...config.limits, maxBytes: Number(event.currentTarget.value) * 1073741824 } })} /><span className="dialogSubtitle">{formatBytes(config.limits.maxBytes)}</span></label>
              <label>{zh ? "最长运行（分钟）" : "Runtime cap (minutes)"}<input type="number" min={1} max={15} value={Math.round(config.limits.maxRuntimeSeconds / 60)} onChange={(event) => setConfig({ ...config, limits: { ...config.limits, maxRuntimeSeconds: Number(event.currentTarget.value) * 60 } })} /></label>
            </div>
            <label className="automationToggle"><input type="checkbox" checked={config.notificationsEnabled} onChange={(event) => setConfig({ ...config, notificationsEnabled: event.currentTarget.checked })} />{zh ? "后台运行完成、失败或达到上限时通知" : "Notify when background runs finish, fail, or hit a cap"}</label>
          </section>
          {error ? <p className="formError">{error}</p> : null}
        </div>
      )}
    </Dialog>
  );
}

function weekdayLabel(day: number, zh: boolean): string {
  const zhDays = ["一", "二", "三", "四", "五", "六", "日"];
  const enDays = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  return zh ? `星期${zhDays[day - 1]}` : enDays[day - 1];
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}