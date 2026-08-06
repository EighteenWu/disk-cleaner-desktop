import { ExternalLink, File, Folder } from "lucide-react";
import { formatBytes, canOpenChildren, riskClass } from "../state";
import {
  localizedObjectType,
  localizedRiskLabel,
  localizeSourceLabel,
  translateCategory,
  translateReason,
  type LanguageCode
} from "../i18n";
import type { CleanupCandidate } from "../types";

export interface DetailPanelProps {
  candidate: CleanupCandidate | null;
  children: CleanupCandidate[];
  childrenLoading: boolean;
  language: LanguageCode;
  onReveal: (candidate: CleanupCandidate) => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function DetailPanel({
  candidate,
  children,
  childrenLoading,
  language,
  onReveal,
  translate
}: DetailPanelProps) {
  if (!candidate) {
    return (
      <div className="detailEmpty">
        <p>{translate("detail.noCandidate")}</p>
      </div>
    );
  }

  return (
    <div className="detailContent">
      <header className="detailHead">
        <span className="detailIcon" aria-hidden="true">
          {candidate.objectType === "file" ? <File size={16} /> : <Folder size={16} />}
        </span>
        <div className="detailHeadText">
          <h3>{candidate.displayName}</h3>
          <p className="detailPath" title={candidate.path}>
            {candidate.path}
          </p>
        </div>
      </header>

      <dl className="detailGrid">
        <Row label={translate("table.size")} value={formatBytes(candidate.sizeBytes)} />
        <Row
          label={translate("detail.type")}
          value={localizedObjectType(language, candidate.objectType)}
        />
        <Row
          label={translate("detail.category")}
          value={translateCategory(language, candidate.category)}
        />
        <Row
          label={translate("detail.source")}
          value={localizeSourceLabel(language, candidate.source.label)}
        />
        <Row
          label={translate("table.risk")}
          value={localizedRiskLabel(language, candidate.riskLevel)}
          valueClass={`badge ${riskClass(candidate.riskLevel)}`}
        />
        {candidate.cleanupPolicy.keepDays > 0 ? (
          <Row
            label={translate("detail.keepDays")}
            value={String(candidate.cleanupPolicy.keepDays)}
          />
        ) : null}
      </dl>

      <p className="detailReason">{translateReason(language, candidate.reason)}</p>

      <div className="detailActions">
        <button className="button" onClick={() => onReveal(candidate)}>
          <ExternalLink size={15} />
          {translate("detail.actions.openLocation")}
        </button>
      </div>

      {canOpenChildren(candidate) ? (
        <section className="detailChildren">
          <h4>{translate("detail.preview")}</h4>
          {childrenLoading ? (
            <p className="detailChildrenHint">{translate("detail.actions.reading")}</p>
          ) : children.length === 0 ? (
            <p className="detailChildrenHint">{translate("detail.noChildren")}</p>
          ) : (
            <ul className="detailChildrenList">
              {children.slice(0, 50).map((child) => (
                <li key={child.id}>
                  <span className="detailChildName" title={child.path}>
                    {child.displayName}
                  </span>
                  <span className="detailChildSize">{formatBytes(child.sizeBytes)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}
    </div>
  );
}

function Row({
  label,
  value,
  valueClass
}: {
  label: string;
  value: string;
  valueClass?: string;
}) {
  return (
    <div className="detailRow">
      <dt>{label}</dt>
      <dd>{valueClass ? <span className={valueClass}>{value}</span> : value}</dd>
    </div>
  );
}
