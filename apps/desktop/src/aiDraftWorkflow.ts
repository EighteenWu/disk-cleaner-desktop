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

export function aiConfirmApprovalReady(
  draft: AiRuleDraft | null,
  editorDirty: boolean,
  rewriteIds: string[],
  instruction: string
): boolean {
  return (
    aiDraftApprovalReady(draft, editorDirty) &&
    rewriteIds.length === 0 &&
    instruction.trim().length === 0
  );
}
