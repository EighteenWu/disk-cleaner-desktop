import { X } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";

/**
 * All four dialogs previously repeated the same overlay markup inline in
 * `App.tsx`, and none of them handled Escape or focus. Centralizing that here
 * fixes the interaction defects once instead of four times.
 */

export interface DialogProps {
  title: string;
  subtitle?: string;
  closeLabel: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  className?: string;
  overlayClassName?: string;
}

const dialogEscapeStack: Array<() => void> = [];

export function Dialog({
  title,
  subtitle,
  closeLabel,
  onClose,
  children,
  footer,
  className,
  overlayClassName
}: DialogProps) {
  const panelRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const close = () => onCloseRef.current();
    dialogEscapeStack.push(close);
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      if (dialogEscapeStack[dialogEscapeStack.length - 1] !== close) return;
      event.stopPropagation();
      close();
    }

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      const index = dialogEscapeStack.lastIndexOf(close);
      if (index >= 0) dialogEscapeStack.splice(index, 1);
    };
  }, []);

  useEffect(() => {
    // Move focus into the dialog so keyboard users are not left behind on the
    // workbench underneath.
    const firstFocusable = panelRef.current?.querySelector<HTMLElement>(
      "button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])"
    );

    firstFocusable?.focus();
  }, []);

  return (
    <div
      className={overlayClassName ? `dialogOverlay ${overlayClassName}` : "dialogOverlay"}
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <section
        ref={panelRef}
        className={className ? `dialog ${className}` : "dialog"}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header className="dialogHeader">
          <div className="dialogHeading">
            <h2>{title}</h2>
            {subtitle ? <p className="dialogSubtitle">{subtitle}</p> : null}
          </div>
          <button className="iconButton" onClick={onClose} aria-label={closeLabel}>
            <X size={16} />
          </button>
        </header>
        <div className="dialogBody">{children}</div>
        {footer ? <footer className="dialogFooter">{footer}</footer> : null}
      </section>
    </div>
  );
}
