import type { AiRuleDraft } from "./types";

export function aiDraftValidationReady(draft: AiRuleDraft | null, editorDirty: boolean): boolean {
  return draft !== null && !editorDirty;
}

export function aiDraftApprovalReady(draft: AiRuleDraft | null, editorDirty: boolean): boolean {
  return (
    aiDraftValidationReady(draft, editorDirty) &&
    draft?.validationRevision === draft?.revision &&
    draft?.compilation?.report.valid === true
  );
}
