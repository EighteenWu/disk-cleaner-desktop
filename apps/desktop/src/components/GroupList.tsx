import { ChevronDown, ChevronRight, Lock } from "lucide-react";
import { useState } from "react";
import { Checkbox } from "./Checkbox";
import type { CandidateGroup } from "../groups";
import { formatBytes, isCleanupSelectable, riskClass, visibleWindowForList } from "../state";
import { localizedGroupLabel, localizedRiskLabel, localizeSourceLabel, type LanguageCode } from "../i18n";
import type { CleanupCandidate, SourceKind } from "../types";

/**
 * The first screen shows one row per source group instead of one row per
 * candidate. A first-time user decides "clean my browser caches", not
 * "clean chrome-cache, edge-cache, firefox-cache". Individual candidates stay
 * reachable by expanding a group, which keeps the expert path intact.
 */

export interface GroupListProps {
  groups: CandidateGroup[];
  expandedKinds: ReadonlySet<SourceKind>;
  selectedCandidateId: string;
  language: LanguageCode;
  busy: boolean;
  emptyLabel: string;
  onToggleExpanded: (kind: SourceKind) => void;
  onToggleGroup: (kind: SourceKind, selected: boolean) => void;
  onToggleCandidate: (candidateId: string) => void;
  onFocusCandidate: (candidate: CleanupCandidate) => void;
  onRevealCandidate: (candidate: CleanupCandidate) => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

/** A rule group such as browser caches can hold hundreds of paths, so an
 * expanded group renders a windowed slice instead of every row. */
const CANDIDATE_ROW_HEIGHT = 34;
const CANDIDATE_OVERSCAN = 6;
const CANDIDATE_VIEWPORT_HEIGHT = 340;
const VIRTUALIZE_THRESHOLD = 60;

function ExpandedCandidates({
  group,
  selectedCandidateId,
  language,
  busy,
  onToggleCandidate,
  onFocusCandidate,
  onRevealCandidate,
  translate
}: {
  group: CandidateGroup;
  selectedCandidateId: string;
  language: LanguageCode;
  busy: boolean;
  onToggleCandidate: (candidateId: string) => void;
  onFocusCandidate: (candidate: CleanupCandidate) => void;
  onRevealCandidate: (candidate: CleanupCandidate) => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}) {
  const [scrollTop, setScrollTop] = useState(0);
  const virtualized = group.candidates.length > VIRTUALIZE_THRESHOLD;
  const window_ = virtualized
    ? visibleWindowForList(
        group.candidates.length,
        scrollTop,
        CANDIDATE_VIEWPORT_HEIGHT,
        CANDIDATE_ROW_HEIGHT,
        CANDIDATE_OVERSCAN
      )
    : null;
  const rendered = window_
    ? group.candidates.slice(window_.startIndex, window_.endIndex)
    : group.candidates;

  return (
    <div
      className={`candidateScroll ${virtualized ? "virtual" : ""}`}
      onScroll={virtualized ? (event) => setScrollTop(event.currentTarget.scrollTop) : undefined}
    >
      {window_ ? <div style={{ height: window_.topPadding }} /> : null}
      <ul className="candidateList">
        {rendered.map((candidate) => {
          const selectable = isCleanupSelectable(candidate);

          return (
            <li
              key={candidate.id}
              className={`candidateRow ${candidate.id === selectedCandidateId ? "active" : ""}`}
            >
              <Checkbox
                state={candidate.selected ? "all" : "none"}
                label={candidate.displayName}
                disabled={busy || !selectable}
                onChange={() => onToggleCandidate(candidate.id)}
              />
              <button
                className="candidateMain"
                onClick={() => onFocusCandidate(candidate)}
                onDoubleClick={(event) => {
                  // Single click focuses the row so the full path can wrap;
                  // double-click opens the item in Explorer.
                  event.preventDefault();
                  onRevealCandidate(candidate);
                }}
              >
                <span className="candidateName">{candidate.displayName}</span>
                <span className="candidatePath" title={candidate.path}>
                  {candidate.path}
                </span>
              </button>
              <span className="candidateSource">
                {localizeSourceLabel(language, candidate.source.label)}
              </span>
              {selectable ? null : (
                <Lock size={13} className="candidateLock" aria-label={translate("cleanup.blocked")} />
              )}
              <span className="candidateSize">{formatBytes(candidate.sizeBytes)}</span>
            </li>
          );
        })}
      </ul>
      {window_ ? <div style={{ height: window_.bottomPadding }} /> : null}
    </div>
  );
}

export function GroupList({
  groups,
  expandedKinds,
  selectedCandidateId,
  language,
  busy,
  emptyLabel,
  onToggleExpanded,
  onToggleGroup,
  onToggleCandidate,
  onFocusCandidate,
  onRevealCandidate,
  translate
}: GroupListProps) {
  if (groups.length === 0) {
    return <p className="groupEmpty">{emptyLabel}</p>;
  }

  return (
    <ul className="groupList">
      {groups.map((group) => {
        const expanded = expandedKinds.has(group.kind);
        const groupLabel = localizedGroupLabel(language, group.kind);

        return (
          <li key={group.kind} className={`groupItem ${expanded ? "expanded" : ""}`}>
            <div className="groupRow">
              <Checkbox
                state={group.selection}
                label={groupLabel}
                disabled={busy || group.selectableCount === 0}
                onChange={(nextSelected) => onToggleGroup(group.kind, nextSelected)}
              />
              {/* Chevron and title are one control: the title is the obvious
                  click target for "show me what is inside", and a single
                  disclosure button keeps one aria-expanded per group. */}
              <button
                className="groupToggle"
                onClick={() => onToggleExpanded(group.kind)}
                aria-expanded={expanded}
                title={translate(expanded ? "group.collapse" : "group.expand")}
              >
                <span className="groupChevron" aria-hidden="true">
                  {expanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                </span>
                <span className="groupMain">
                  <span className="groupName">{groupLabel}</span>
                  <span className="groupMeta">
                    {translate("group.summary", {
                      count: group.candidates.length,
                      size: formatBytes(group.totalBytes)
                    })}
                    {group.blockedCount > 0
                      ? ` · ${translate("group.blocked", { count: group.blockedCount })}`
                      : ""}
                  </span>
                </span>
              </button>
              <span className={`badge ${riskClass(group.maxRisk)}`}>
                {localizedRiskLabel(language, group.maxRisk)}
              </span>
              <span className="groupSize">{formatBytes(group.selectedBytes)}</span>
            </div>

            {expanded ? (
              <ExpandedCandidates
                group={group}
                selectedCandidateId={selectedCandidateId}
                language={language}
                busy={busy}
                onToggleCandidate={onToggleCandidate}
                onFocusCandidate={onFocusCandidate}
                onRevealCandidate={onRevealCandidate}
                translate={translate}
              />
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
