import { AlertTriangle } from "lucide-react";
import { Dialog } from "./Dialog";
import { Checkbox } from "./Checkbox";
import { formatBytes } from "../state";
import { localizedDeleteStrategy, type LanguageCode } from "../i18n";
import { isCleanupBusy, type SessionState } from "../session";
import type { CleanupPlan, CleanupReport } from "../types";

/**
 * Confirmation keeps the destructive choice explicit: permanent delete is a
 * separate opt-in checkbox and the primary button text changes with it, so the
 * irreversible path can never be taken by muscle memory.
 */

export interface CleanupDialogProps {
  session: SessionState;
  plan: CleanupPlan;
  permanentDelete: boolean;
  language: LanguageCode;
  onPermanentDeleteChange: (value: boolean) => void;
  onConfirm: () => void;
  onPause: () => void;
  onResume: () => void;
  onCancel: () => void;
  onClose: () => void;
  formatDuration: (milliseconds: number) => string;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function CleanupDialog({
  session,
  plan,
  permanentDelete,
  language,
  onPermanentDeleteChange,
  onConfirm,
  onPause,
  onResume,
  onCancel,
  onClose,
  formatDuration,
  translate
}: CleanupDialogProps) {
  const busy = isCleanupBusy(session);
  const finished = session.phase === "cleanupDone" || session.phase === "cleanupFailed";

  return (
    <Dialog
      title={translate("cleanup.preview")}
      closeLabel={translate("button.close")}
      onClose={busy ? onCancel : onClose}
      footer={
        finished ? (
          <button className="button primary" onClick={onClose}>
            {translate("button.done")}
          </button>
        ) : busy ? (
          <>
            {session.phase === "cleanupPaused" ? (
              <button className="button" onClick={onResume}>
                {translate("cleanup.resume")}
              </button>
            ) : (
              <button
                className="button"
                onClick={onPause}
                disabled={session.phase === "cleanupCanceling"}
              >
                {translate("cleanup.pause")}
              </button>
            )}
            <button
              className="button danger"
              onClick={onCancel}
              disabled={session.phase === "cleanupCanceling"}
            >
              {translate("cleanup.cancel")}
            </button>
          </>
        ) : (
          <>
            <button className="button" onClick={onClose}>
              {translate("button.close")}
            </button>
            <button
              className={`button ${permanentDelete ? "danger" : "primary"}`}
              onClick={onConfirm}
              disabled={plan.selectedCount === 0}
            >
              {translate(permanentDelete ? "cleanup.confirmPermanent" : "cleanup.confirm")}
            </button>
          </>
        )
      }
    >
      {finished && session.report ? (
        <ReportView report={session.report} translate={translate} />
      ) : busy ? (
        <div className="cleanupProgress" aria-live="polite">
          <div className="scanMeter">
            <span style={{ width: `${session.cleanup.percent}%` }} />
          </div>
          <p className="cleanupProgressMeta">
            {translate("cleanup.progressCount", {
              processed: session.cleanup.processedCount,
              total: session.cleanup.totalCount
            })}
            {" · "}
            {formatDuration(session.cleanup.elapsedMs)}
          </p>
          {session.cleanup.currentPath ? (
            <p className="cleanupProgressPath" title={session.cleanup.currentPath}>
              {session.cleanup.currentPath}
            </p>
          ) : null}
        </div>
      ) : (
        <>
          <dl className="planSummary">
            <div className="planRow">
              <dt>{translate("cleanup.selected")}</dt>
              <dd>{plan.selectedCount}</dd>
            </div>
            <div className="planRow">
              <dt>{translate("cleanup.reclaimed")}</dt>
              <dd>{formatBytes(plan.estimatedReclaimBytes)}</dd>
            </div>
            <div className="planRow">
              <dt>{translate("cleanup.strategy")}</dt>
              <dd>{localizedDeleteStrategy(language, plan.deleteStrategy)}</dd>
            </div>
            {plan.skippedLockedCount > 0 ? (
              <div className="planRow">
                <dt>{translate("cleanup.lockedSkipped")}</dt>
                <dd>{plan.skippedLockedCount}</dd>
              </div>
            ) : null}
          </dl>

          <label className="permanentToggle">
            <Checkbox
              state={permanentDelete ? "all" : "none"}
              label={translate("cleanup.permanentDelete")}
              onChange={onPermanentDeleteChange}
            />
            <span>
              <strong>{translate("cleanup.permanentDelete")}</strong>
              <span className="permanentHint">{translate("cleanup.permanentDeleteWarning")}</span>
            </span>
          </label>

          {plan.warnings.length > 0 ? (
            <ul className="planWarnings">
              {plan.warnings.map((warning, index) => (
                <li key={`${warning}-${index}`}>
                  <AlertTriangle size={14} />
                  <span>{warning}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </>
      )}
    </Dialog>
  );
}

function ReportView({
  report,
  translate
}: {
  report: CleanupReport;
  translate: (key: string, values?: Record<string, string | number>) => string;
}) {
  return (
    <dl className="planSummary">
      <div className="planRow">
        <dt>{translate("cleanup.cleanedItems")}</dt>
        <dd>{report.cleanedCount}</dd>
      </div>
      <div className="planRow">
        <dt>{translate("cleanup.reclaimed")}</dt>
        <dd>{formatBytes(report.reclaimedBytes)}</dd>
      </div>
      {report.skippedLockedCount > 0 ? (
        <div className="planRow">
          <dt>{translate("cleanup.lockedSkipped")}</dt>
          <dd>{report.skippedLockedCount}</dd>
        </div>
      ) : null}
      {report.failedCount > 0 ? (
        <div className="planRow">
          <dt>{translate("cleanup.failedItems")}</dt>
          <dd>{report.failedCount}</dd>
        </div>
      ) : null}
    </dl>
  );
}
