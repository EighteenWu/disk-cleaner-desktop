import { Check, Minus } from "lucide-react";

/**
 * The old markup rendered selection as a bare "✓" glyph inside a span, so
 * screen readers saw decorative text instead of a control and there was no way
 * to express a partially selected group. This is a real checkbox with an
 * indeterminate state.
 */

export type CheckState = "none" | "partial" | "all";

export interface CheckboxProps {
  state: CheckState;
  label: string;
  disabled?: boolean;
  onChange: (nextSelected: boolean) => void;
}

export function Checkbox({ state, label, disabled = false, onChange }: CheckboxProps) {
  return (
    <span className="checkboxWrap">
      <input
        type="checkbox"
        className="checkboxInput"
        checked={state === "all"}
        // Selecting a partially checked group should complete it, not clear it.
        ref={(node) => {
          if (node) {
            node.indeterminate = state === "partial";
          }
        }}
        disabled={disabled}
        aria-label={label}
        onChange={(event) => onChange(state === "partial" ? true : event.currentTarget.checked)}
      />
      <span className="checkboxBox" aria-hidden="true">
        {state === "all" ? <Check size={13} /> : state === "partial" ? <Minus size={13} /> : null}
      </span>
    </span>
  );
}
