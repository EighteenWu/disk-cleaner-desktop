import { formatBytes } from "../state";
import { localizedScanPhase, type LanguageCode } from "../i18n";
import { isScanBusy, scanStatsVisible, type SessionState } from "../session";

/**
 * Reads straight off the session machine. Because `scan.hasRun` never flips
 * back to false, the scanned-file count and elapsed time stay on screen after a
 * run finishes rather than blanking the moment the scan settles.
 */

export interface ScanPanelProps {
  session: SessionState;
  language: LanguageCode;
  formatCount: (value: number) => string;
  formatDuration: (milliseconds: number) => string;
  truncatePath: (path: string) => string;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function ScanPanel({
  session,
  language,
  formatCount,
  formatDuration,
  truncatePath,
  translate
}: ScanPanelProps) {
  if (!scanStatsVisible(session)) {
    return null;
  }

  const { scan } = session;
  const busy = isScanBusy(session);
  const determinate = scan.percent !== null;

  return (
    <section className="scanPanel" aria-live="polite">
      <div className="scanPanelHead">
        <div className="scanCount">
          <span className="scanCountLabel">{translate("scan.scannedFiles")}</span>
          <strong className="scanCountValue">{formatCount(scan.scannedFiles)}</strong>
        </div>
        <div className="scanPanelStats">
          <span>{localizedScanPhase(language, scan.phase)}</span>
          <span>{translate("scan.elapsedValue", { duration: formatDuration(scan.elapsedMs) })}</span>
          <span>{formatBytes(scan.reclaimableBytes)}</span>
        </div>
      </div>

      <div
        className={`scanMeter ${determinate ? "" : "indeterminate"}`}
        role="progressbar"
        aria-valuenow={determinate ? (scan.percent ?? undefined) : undefined}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <span style={determinate ? { width: `${scan.percent ?? 0}%` } : undefined} />
      </div>

      {busy && scan.currentPath ? (
        <p className="scanPath" title={scan.currentPath}>
          {truncatePath(scan.currentPath)}
        </p>
      ) : null}
    </section>
  );
}
