import { formatBytes } from "../state";
import { scanStatsVisible, type SessionState } from "../session";

/**
 * The scanned-file readout is driven by `scan.hasRun`, not by "is a scan
 * currently running". That is the fix for the count disappearing the instant a
 * scan completed.
 */

export interface StatusBarProps {
  session: SessionState;
  selectedCount: number;
  selectedBytes: number;
  notice: string;
  formatCount: (value: number) => string;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function StatusBar({
  session,
  selectedCount,
  selectedBytes,
  notice,
  formatCount,
  translate
}: StatusBarProps) {
  const backend = session.snapshot?.scanBackend ?? "-";

  return (
    <footer className="statusbar">
      <span className="statusNotice">{notice}</span>
      <span className="statusSpacer" />
      {scanStatsVisible(session) ? (
        <span className="statusItem">
          {translate("scan.scannedFiles")} {formatCount(session.scan.scannedFiles)}
        </span>
      ) : null}
      <span className="statusItem">
        {translate("status.selected", {
          count: selectedCount,
          size: formatBytes(selectedBytes)
        })}
      </span>
      <span className="statusItem statusBackend">{backend}</span>
    </footer>
  );
}
