import { Dialog } from "./Dialog";
import { Checkbox } from "./Checkbox";
import { formatBytes } from "../state";
import type { VolumeInfo } from "../types";

export interface DriveDialogProps {
  volumes: VolumeInfo[];
  busy: boolean;
  onToggleVolume: (volumeId: string) => void;
  onClose: () => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function DriveDialog({
  volumes,
  busy,
  onToggleVolume,
  onClose,
  translate
}: DriveDialogProps) {
  return (
    <Dialog
      title={translate("dialog.drive")}
      closeLabel={translate("button.close")}
      onClose={onClose}
      footer={
        <button className="button primary" onClick={onClose}>
          {translate("button.done")}
        </button>
      }
    >
      <ul className="driveDialogList">
        {volumes.map((volume) => (
          <li key={volume.id} className="driveDialogRow">
            <Checkbox
              state={volume.selected ? "all" : "none"}
              label={volume.id}
              disabled={busy}
              onChange={() => onToggleVolume(volume.id)}
            />
            <div className="driveDialogMain">
              <strong>
                {volume.id}: {volume.label}
              </strong>
              <span className="driveDialogMeta">
                {translate("drive.available", {
                  available: formatBytes(volume.availableBytes),
                  total: formatBytes(volume.totalBytes)
                })}
              </span>
            </div>
            <span className={`badge ${volume.supportsFastIndex ? "safe" : "info"}`}>
              {volume.filesystem}
            </span>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}
