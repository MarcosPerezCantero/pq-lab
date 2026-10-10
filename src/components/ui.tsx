import { useEffect, useState, type ReactNode } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type ApiError, type Subject, type Validity } from "../api";
import { t } from "../i18n";
import { errorMessage, toApiError } from "../helpers";

export function Dialog({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="backdrop" role="dialog" aria-modal="true" aria-label={title}>
      <div className={`dialog ${wide ? "wide" : ""}`}>
        <header>{title}</header>
        <div className="body">{children}</div>
        <footer>{footer ?? <button onClick={onClose}>{t("common.close")}</button>}</footer>
      </div>
    </div>
  );
}

export function DialogFooter({
  busy,
  onCancel,
  onSubmit,
  submitLabel,
  disabled,
  extra,
}: {
  busy: boolean;
  onCancel: () => void;
  onSubmit: () => void;
  submitLabel?: string;
  disabled?: boolean;
  extra?: ReactNode;
}) {
  return (
    <>
      {extra && <div className="mr-auto flex gap-2">{extra}</div>}
      {busy && <span className="muted">{t("common.working")}</span>}
      <button onClick={onCancel} disabled={busy}>
        {t("common.cancel")}
      </button>
      <button onClick={onSubmit} disabled={busy || disabled}>
        {submitLabel ?? t("common.ok")}
      </button>
    </>
  );
}

/** Classic tab widget. */
export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  children,
  className = "",
}: {
  tabs: [T, string][];
  value: T;
  onChange: (v: T) => void;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`flex min-h-0 flex-col ${className}`}>
      <div className="tabbar" role="tablist">
        {tabs.map(([id, label]) => (
          <button key={id} role="tab" aria-selected={value === id} onClick={() => onChange(id)}>
            {label}
          </button>
        ))}
      </div>
      <div className="tabpane min-h-0 flex-1 p-3">{children}</div>
    </div>
  );
}

export function Group({ title, children, className = "" }: { title: string; children: ReactNode; className?: string }) {
  return (
    <fieldset className={`group ${className}`}>
      <legend>{title}</legend>
      {children}
    </fieldset>
  );
}

/** Form row: right-aligned label + control (QFormLayout). */
export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <label>{label}</label>
      <div className="flex min-w-0 items-center gap-2">{children}</div>
    </>
  );
}

export function Check({
  label,
  checked,
  onChange,
  disabled,
  title,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <label className={`check ${disabled ? "muted" : ""}`} title={title}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

export function ErrorBox({ error }: { error: ApiError | null }) {
  const [showDetail, setShowDetail] = useState(false);
  if (!error) return null;
  return (
    <div className="message error">
      <span className="danger" aria-hidden>
        ⚠
      </span>
      <div className="min-w-0 flex-1">
        <div>{errorMessage(error)}</div>
        {error.detail && (
          <>
            <button className="mt-1" onClick={() => setShowDetail((v) => !v)} type="button">
              {showDetail ? t("common.hideDetail") : t("common.technicalDetail")}
            </button>
            {showDetail && <pre className="pre mono mt-2">{error.detail}</pre>}
          </>
        )}
      </div>
    </div>
  );
}

export function Note({ children, warn }: { children: ReactNode; warn?: boolean }) {
  return <div className={warn ? "message warn" : "muted"}>{children}</div>;
}

export function SubjectFields({
  value,
  onChange,
  autoFocus,
}: {
  value: Subject;
  onChange: (s: Subject) => void;
  autoFocus?: boolean;
}) {
  const field = (k: keyof Subject, label: string, extra?: React.InputHTMLAttributes<HTMLInputElement>) => (
    <Row label={label}>
      <input className="flex-1" value={value[k]} onChange={(e) => onChange({ ...value, [k]: e.target.value })} {...extra} />
    </Row>
  );
  return (
    <Group title={t("subject.title")}>
      <div className="form">
        {field("cn", t("subject.cn"), { autoFocus })}
        {field("o", t("subject.o"))}
        {field("ou", t("subject.ou"))}
        {field("l", t("subject.l"))}
        {field("st", t("subject.st"))}
        {field("c", t("subject.c"), { maxLength: 2, size: 3, className: "" })}
      </div>
    </Group>
  );
}

/** PEM text area with a "load file" button. */
export function PemInput({
  label,
  value,
  onChange,
  onError,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  onError: (e: ApiError) => void;
}) {
  async function load() {
    const path = await open({ multiple: false, directory: false });
    if (typeof path !== "string") return;
    try {
      onChange(await api.readPemFile(path));
    } catch (e) {
      onError(toApiError(e));
    }
  }
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span>{label}</span>
        <button type="button" onClick={load}>
          {t("common.loadFile")}
        </button>
      </div>
      <textarea
        className="mono h-40"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        placeholder="-----BEGIN ..."
      />
    </div>
  );
}

/** One value per line. */
export function LinesInput({
  value,
  onChange,
  rows = 3,
  placeholder,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  rows?: number;
  placeholder?: string;
}) {
  const [text, setText] = useState(value.join("\n"));
  const normalized = text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .join("\n");
  if (normalized !== value.join("\n") && document.activeElement?.tagName !== "TEXTAREA") {
    setText(value.join("\n"));
  }
  return (
    <textarea
      className="mono w-full"
      rows={rows}
      value={text}
      placeholder={placeholder}
      spellCheck={false}
      onChange={(e) => {
        setText(e.target.value);
        onChange(
          e.target.value
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
        );
      }}
    />
  );
}

export function ValidityFields({ value, onChange }: { value: Validity; onChange: (v: Validity) => void }) {
  const byDates = value.not_after !== null;
  const today = new Date().toISOString().slice(0, 10);
  return (
    <Group title={t("validity.title")}>
      <div className="form">
        <Row label={t("validity.mode")}>
          <label className="check">
            <input
              type="radio"
              checked={!byDates}
              onChange={() => onChange({ days: value.days ?? 365, not_before: null, not_after: null })}
            />
            {t("validity.byDays")}
          </label>
          <label className="check">
            <input
              type="radio"
              checked={byDates}
              onChange={() => {
                const end = new Date(Date.now() + (value.days ?? 365) * 86400000).toISOString().slice(0, 10);
                onChange({ days: null, not_before: today, not_after: end });
              }}
            />
            {t("validity.byDates")}
          </label>
        </Row>
        {byDates ? (
          <>
            <Row label={t("validity.notBefore")}>
              <input
                type="date"
                value={value.not_before ?? today}
                onChange={(e) => onChange({ ...value, not_before: e.target.value })}
              />
            </Row>
            <Row label={t("validity.notAfter")}>
              <input
                type="date"
                value={value.not_after ?? ""}
                onChange={(e) => onChange({ ...value, not_after: e.target.value })}
              />
            </Row>
          </>
        ) : (
          <Row label={t("validity.days")}>
            <input
              type="number"
              min={1}
              max={36500}
              style={{ width: 90 }}
              value={value.days ?? ""}
              onChange={(e) => onChange({ ...value, days: e.target.value ? parseInt(e.target.value, 10) : null })}
            />
            <span className="muted">{t("validity.daysHint")}</span>
          </Row>
        )}
      </div>
    </Group>
  );
}
