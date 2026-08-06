import { Database, Search, ShieldAlert } from "lucide-react";
import { formatBytes } from "../state";
import { isIncompleteCoverage } from "../inventory";
import type { InventoryQueryItem, ScanSnapshot } from "../types";

export interface SpaceAnalysisPanelProps {
  snapshot: ScanSnapshot;
  items: InventoryQueryItem[];
  query: string;
  mode: "largest" | "search";
  loading: boolean;
  error: string | null;
  hasMore: boolean;
  onQueryChange: (value: string) => void;
  onSearch: () => void;
  onShowLargest: () => void;
  onLoadMore: () => void;
  onReveal: (path: string) => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function SpaceAnalysisPanel({
  snapshot,
  items,
  query,
  mode,
  loading,
  error,
  hasMore,
  onQueryChange,
  onSearch,
  onShowLargest,
  onLoadMore,
  onReveal,
  translate
}: SpaceAnalysisPanelProps) {
  if (!snapshot.scanSessionId || snapshot.coverage.status === "notStarted") {
    return null;
  }

  const incomplete = isIncompleteCoverage(snapshot.coverage.status);

  return (
    <section className="spaceAnalysis" aria-labelledby="space-analysis-title">
      <div className="spaceAnalysisHeader">
        <div>
          <h3 id="space-analysis-title">
            <Database size={15} />
            {translate("inventory.title")}
          </h3>
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
      </div>

      <div className="volumeSummaryList">
        {snapshot.spaceSummary.map((volume) => (
          <div className="volumeSummaryRow" key={volume.volumeId}>
            <strong>{volume.volumeId}:</strong>
            <span>{formatBytes(volume.allocatedBytes)}</span>
            <span>
              {translate("inventory.logical", { size: formatBytes(volume.logicalBytes) })}
            </span>
            <span>
              {translate("inventory.objects", {
                files: volume.fileCount,
                directories: volume.directoryCount
              })}
            </span>
            <span>
              {translate("inventory.protected", {
                count: volume.analysisOnlyCount + volume.blockedCount
              })}
            </span>
          </div>
        ))}
      </div>

      {snapshot.coverage.gaps.length > 0 ? (
        <div className="coverageGaps" role="status">
          {snapshot.coverage.gaps.slice(0, 5).map((gap, index) => (
            <span key={`${gap.volumeId}-${gap.reason}-${index}`}>
              {translate("inventory.gap", {
                volume: gap.volumeId,
                reason: translate(`inventory.gap.${gap.reason}`),
                count: gap.count
              })}
            </span>
          ))}
        </div>
      ) : null}

      <div className="inventoryToolbar">
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
        <button className="ghostButton" onClick={onShowLargest} disabled={loading}>
          {translate("inventory.largest")}
        </button>
      </div>

      <div className="inventoryResults" aria-busy={loading}>
        <div className="inventoryResultsTitle">
          {translate(mode === "largest" ? "inventory.largestTitle" : "inventory.searchTitle")}
        </div>
        {error ? <p className="inventoryError">{error}</p> : null}
        {!loading && !error && items.length === 0 ? (
          <p className="inventoryEmpty">{translate("inventory.empty")}</p>
        ) : null}
        {items.map((item) => (
          <button
            className="inventoryRow"
            key={item.entryId}
            onClick={() => onReveal(item.path)}
            title={item.path}
          >
            <span className="inventoryName">{item.name}</span>
            <span>{formatBytes(item.allocatedBytes)}</span>
            <span className={`badge ${item.disposition === "normal" ? "info" : "warn"}`}>
              {translate(`inventory.disposition.${item.disposition}`)}
            </span>
          </button>
        ))}
        {hasMore ? (
          <button className="ghostButton inventoryMore" onClick={onLoadMore} disabled={loading}>
            {loading ? translate("inventory.loading") : translate("inventory.loadMore")}
          </button>
        ) : null}
      </div>
    </section>
  );
}
