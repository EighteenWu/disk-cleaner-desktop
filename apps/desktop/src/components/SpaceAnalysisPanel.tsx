import { ChevronRight, FolderOpen, HardDrive, Search, ShieldAlert } from "lucide-react";
import { isIncompleteCoverage, mergeActionableGaps, occupancyPercent } from "../inventory";
import { formatBytes } from "../state";
import type { InventoryQueryItem, ScanSnapshot, VolumeInfo, VolumeSpaceSummary } from "../types";

export interface SpaceCrumb {
  entryId: string | null;
  name: string;
}

export interface SpaceAnalysisPanelProps {
  snapshot: ScanSnapshot;
  items: InventoryQueryItem[];
  crumbs: SpaceCrumb[];
  query: string;
  mode: "largest" | "children" | "search";
  loading: boolean;
  error: string | null;
  hasMore: boolean;
  onQueryChange: (value: string) => void;
  onSearch: () => void;
  onShowLargest: () => void;
  onOpenRoot: () => void;
  onOpenCrumb: (index: number) => void;
  onOpenDirectory: (item: InventoryQueryItem) => void;
  onLoadMore: () => void;
  onReveal: (path: string) => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function SpaceAnalysisPanel({
  snapshot,
  items,
  crumbs,
  query,
  mode,
  loading,
  error,
  hasMore,
  onQueryChange,
  onSearch,
  onShowLargest,
  onOpenRoot,
  onOpenCrumb,
  onOpenDirectory,
  onLoadMore,
  onReveal,
  translate
}: SpaceAnalysisPanelProps) {
  const incomplete = isIncompleteCoverage(snapshot.coverage.status);
  const volumes = snapshot.volumes.filter((volume) => volume.selected);

  return (
    <section className="spaceWorkbench" aria-labelledby="space-analysis-title">
      <header className={`spaceBanner ${incomplete ? "incomplete" : "complete"}`}>
        <div>
          <h3 id="space-analysis-title">{translate("inventory.title")}</h3>
          <p>
            {translate("inventory.coverageSummary", {
              visited: snapshot.coverage.visitedEntries,
              indexed: snapshot.coverage.indexedEntries,
              allocated: formatBytes(snapshot.coverage.allocatedBytes)
            })}
          </p>
        </div>
        <span className={`badge ${incomplete ? "warn" : "safe"}`}>
          {incomplete ? <ShieldAlert size={12} /> : null}
          {translate(`inventory.status.${snapshot.coverage.status}`)}
        </span>
      </header>

      {incomplete && snapshot.coverage.gaps.length > 0 ? (
        <ul className="spaceGaps">
          {mergeActionableGaps(snapshot.coverage.gaps).slice(0, 6).map((gap) => (
            <li key={`${gap.volumeId}-${gap.reason}`}>
              {translate("inventory.gap", {
                volume: gap.volumeId,
                reason: translate(`inventory.gap.${gap.reason}`),
                count: gap.count
              })}
            </li>
          ))}
        </ul>
      ) : null}

      {snapshot.spaceSummary.length > 0 ? (
        <ul className="spaceVolumes">
          {snapshot.spaceSummary.map((summary) => {
            const volume = volumes.find((item) => item.id === summary.volumeId);
            return (
              <li key={summary.volumeId}>
                <VolumeOccupancy
                  summary={summary}
                  volume={volume}
                  translate={translate}
                />
              </li>
            );
          })}
        </ul>
      ) : null}

      <div className="spaceToolbar">
        <label className="searchField">
          <Search size={14} />
          <input
            value={query}
            onChange={(event) => onQueryChange(event.currentTarget.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                onSearch();
              }
            }}
            placeholder={translate("inventory.searchPlaceholder")}
          />
        </label>
        <button className="ghostButton" onClick={onSearch} disabled={loading || !query.trim()}>
          {translate("inventory.search")}
        </button>
        <button
          className={`ghostButton ${mode === "largest" ? "active" : ""}`}
          onClick={onShowLargest}
          disabled={loading}
        >
          {translate("inventory.largest")}
        </button>
      </div>

      <nav className="spaceCrumbs" aria-label={translate("inventory.breadcrumb")}>
        <button type="button" onClick={onOpenRoot} disabled={loading}>
          <HardDrive size={13} />
          {translate("inventory.root")}
        </button>
        {crumbs.map((crumb, index) => (
          <span key={`${crumb.entryId ?? "root"}-${crumb.name}`}>
            <ChevronRight size={12} />
            <button type="button" onClick={() => onOpenCrumb(index)} disabled={loading}>
              {crumb.name}
            </button>
          </span>
        ))}
      </nav>

      <div className="spaceResults" aria-busy={loading}>
        <div className="spaceResultsHead">
          <span>{translate(listTitleKey(mode))}</span>
          <span>{translate("inventory.sizeAllocated")}</span>
        </div>
        {error ? <p className="inventoryError">{error}</p> : null}
        {!loading && !error && items.length === 0 ? (
          <p className="inventoryEmpty">{translate("inventory.empty")}</p>
        ) : null}
        {items.map((item) => {
          const expandable = item.objectType === "directory" && item.hasChildren;
          return (
            <div className="spaceRow" key={item.entryId}>
              <button
                type="button"
                className="spaceRowMain"
                onClick={() => (expandable ? onOpenDirectory(item) : onReveal(item.path))}
                title={item.path}
              >
                <span className="inventoryName">{item.name}</span>
                <span className="spaceRowSize">{formatBytes(item.allocatedBytes)}</span>
                <span className={`badge ${dispositionBadge(item.disposition)}`}>
                  {translate(`inventory.disposition.${item.disposition}`)}
                </span>
              </button>
              <button
                type="button"
                className="ghostButton spaceReveal"
                onClick={() => onReveal(item.path)}
                title={translate("inventory.openLocation")}
              >
                <FolderOpen size={14} />
              </button>
            </div>
          );
        })}
        {hasMore ? (
          <button className="ghostButton inventoryMore" onClick={onLoadMore} disabled={loading}>
            {loading ? translate("inventory.loading") : translate("inventory.loadMore")}
          </button>
        ) : null}
      </div>
    </section>
  );
}

function VolumeOccupancy({
  summary,
  volume,
  translate
}: {
  summary: VolumeSpaceSummary;
  volume: VolumeInfo | undefined;
  translate: SpaceAnalysisPanelProps["translate"];
}) {
  const total = volume?.totalBytes ?? 0;
  const usedPercent = occupancyPercent(summary.allocatedBytes, total);

  return (
    <div className="spaceVolume">
      <div className="spaceVolumeTop">
        <strong>{summary.volumeId}:</strong>
        <span>
          {formatBytes(summary.allocatedBytes)}
          {total > 0 ? ` / ${formatBytes(total)}` : ""}
        </span>
      </div>
      <div className="meter" aria-hidden="true">
        <span style={{ width: `${usedPercent}%` }} />
      </div>
      <p className="spaceVolumeMeta">
        {translate("inventory.logical", { size: formatBytes(summary.logicalBytes) })}
        {" · "}
        {translate("inventory.objects", {
          files: summary.fileCount,
          directories: summary.directoryCount
        })}
        {" · "}
        {translate("inventory.protected", {
          count: summary.analysisOnlyCount + summary.blockedCount
        })}
      </p>
    </div>
  );
}

function listTitleKey(mode: SpaceAnalysisPanelProps["mode"]): string {
  if (mode === "search") {
    return "inventory.searchTitle";
  }
  if (mode === "children") {
    return "inventory.folderTitle";
  }
  return "inventory.largestTitle";
}

function dispositionBadge(disposition: InventoryQueryItem["disposition"]): string {
  if (disposition === "blocked") {
    return "danger";
  }
  if (disposition === "analysisOnly") {
    return "warn";
  }
  return "info";
}


