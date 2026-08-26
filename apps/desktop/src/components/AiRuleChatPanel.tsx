import type { AiChatMessage } from "../types";

export interface AiRuleChatPanelProps {
  messages: AiChatMessage[];
  composer: string;
  setComposer: (value: string) => void;
  planning: boolean;
  generating: boolean;
  canApprove: boolean;
  replaceWarning: boolean;
  message: string;
  onSend: () => void;
  onCancel: () => void;
  onApprove: () => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function AiRuleChatPanel({
  messages,
  composer,
  setComposer,
  planning,
  generating,
  canApprove,
  replaceWarning,
  message,
  onSend,
  onCancel,
  onApprove,
  translate
}: AiRuleChatPanelProps) {
  const busy = planning || generating;

  function submit() {
    if (!busy) onSend();
  }

  return (
    <div className="ruleAiChat">
      <div className="ruleAiChatLog" role="log" aria-live="polite">
        {messages.length === 0 ? (
          <p className="ruleAdvancedHint">{translate("rule.aiChatEmpty")}</p>
        ) : (
          messages.map((item) => (
            <div
              key={item.id}
              className={`ruleAiChatBubble ruleAiChatBubble-${item.role}${
                item.status === "error" || item.status === "cancelled" ? " isMuted" : ""
              }`}
            >
              <strong>
                {translate(item.role === "user" ? "rule.aiChatUser" : "rule.aiChatAssistant")}
              </strong>
              <p>
                {item.content ||
                  (item.status === "streaming" ? translate("rule.aiChatStreaming") : "")}
              </p>
              {item.status === "cancelled" ? (
                <small>{translate("rule.aiChatCancelled")}</small>
              ) : null}
            </div>
          ))
        )}
      </div>
      <label className="ruleField">
        <span className="ruleFieldLabel">{translate("rule.aiChatInput")}</span>
        <textarea
          className="ruleAiChatInput"
          value={composer}
          disabled={busy}
          rows={3}
          onChange={(event) => setComposer(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              submit();
            }
          }}
          placeholder={translate("rule.aiChatPlaceholder")}
        />
      </label>
      <div className="ruleActions">
        <button className="button primary" disabled={busy} onClick={submit}>
          {planning ? translate("rule.aiChatSending") : translate("rule.aiChatSend")}
        </button>
        {busy ? (
          <button className="button danger" onClick={onCancel}>
            {translate("rule.aiChatCancel")}
          </button>
        ) : null}
        <button
          className="button primary"
          disabled={!canApprove || busy}
          onClick={onApprove}
        >
          {generating ? translate("rule.aiChatApproving") : translate("rule.aiChatApprove")}
        </button>
      </div>
      {replaceWarning ? <p className="ruleAdvancedHint">{translate("rule.aiChatReplaceHint")}</p> : null}
      {message ? (
        <p className="ruleAdvancedHint" role="status">
          {message}
        </p>
      ) : null}
    </div>
  );
}
