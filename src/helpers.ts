// Non-component helpers shared by views and dialogs.
import { useState } from "react";
import { api, isApiError, type ApiError, type CertProfile, type Subject, type Validity, type Warning } from "./api";
import { hasKey, t } from "./i18n";
import type { Lab } from "./store";

export type KeyChoice = { kind: "existing"; id: number | null } | { kind: "new"; algorithm: string };

export function errorMessage(e: ApiError): string {
  const key = `error.${e.code}`;
  return hasKey(key) ? t(key, e.params) : t("error.unknown");
}

export function toApiError(e: unknown): ApiError {
  if (isApiError(e)) return e;
  return { code: "unknown", params: {}, detail: String(e) };
}

export function warningMessage(w: Warning): string {
  return t(`warning.${w.code}`, w.params);
}

/** Runs an async action, tracking busy state and the last error. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(toApiError(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  }
  return { busy, error, setError, run };
}

export const emptySubject = (cn = ""): Subject => ({ cn, o: "", ou: "", c: "", st: "", l: "" });

export const emptyProfile = (): CertProfile => ({
  ca: false,
  path_len: null,
  bc_critical: true,
  key_usage: [],
  ku_critical: true,
  ext_key_usage: [],
  eku_critical: false,
  ski: true,
  aki: true,
  san: [],
  san_critical: false,
  policies: [],
  crl_dp: [],
  ocsp: [],
  ca_issuers: [],
  nc_permitted: [],
  nc_excluded: [],
});

export const cloneProfile = (p: CertProfile): CertProfile => JSON.parse(JSON.stringify(p));

export const validityDays = (days: number): Validity => ({ days, not_before: null, not_after: null });

export const splitLines = (s: string) =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);

export const parseNumber = (s: string): number | null => {
  const n = parseInt(s, 10);
  return Number.isFinite(n) ? n : null;
};

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleDateString("es-ES", { year: "numeric", month: "2-digit", day: "2-digit" });
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("es-ES");
}

export function cnOf(dn: string): string {
  const m = dn.match(/(?:^|,)CN=((?:\\.|[^,])*)/);
  return m ? m[1].replace(/\\(.)/g, "$1") : dn;
}

export const safeFileName = (s: string) => s.replace(/[^\w.-]+/g, "_");

/** Resolves a key choice to a key id, generating the key when needed. */
export async function resolveKey(lab: Lab, choice: KeyChoice, certName: string): Promise<number> {
  if (choice.kind === "existing") {
    if (choice.id === null) throw { code: "key_required", params: {}, detail: null };
    return choice.id;
  }
  const base = certName.trim() || choice.algorithm;
  let name = base;
  for (let i = 2; lab.keys.some((k) => k.name === name); i++) name = `${base} ${i}`;
  return api.generateKey(name, choice.algorithm);
}

export function keyAlgorithm(lab: Lab, choice: KeyChoice): string | null {
  if (choice.kind === "new") return choice.algorithm;
  return lab.keys.find((k) => k.id === choice.id)?.algorithm ?? null;
}

/** Template label: preset name, user template name or the raw value. */
export function templateLabel(template: string): string {
  const key = `preset.${template}`;
  if (hasKey(key)) return t(key);
  if (hasKey(`template.${template}`)) return t(`template.${template}`);
  return template;
}
