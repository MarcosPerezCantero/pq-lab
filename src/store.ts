import { createContext, useContext } from "react";
import type { Catalog, CertRow, CrlRow, CsrRow, KeyRow, Templates, Warning } from "./api";

export interface Notice {
  id: number;
  tone: "ok" | "warn" | "error";
  text: string;
}

export interface Lab {
  keys: KeyRow[];
  certs: CertRow[];
  csrs: CsrRow[];
  crls: CrlRow[];
  templates: Templates;
  catalog: Catalog;
  refresh: () => Promise<void>;
  notify: (tone: Notice["tone"], text: string) => void;
  /** Shows a success notice plus any backend warnings. */
  done: (warnings?: Warning[]) => void;
}

export const LabContext = createContext<Lab | null>(null);

export function useLab(): Lab {
  const lab = useContext(LabContext);
  if (!lab) throw new Error("LabContext missing");
  return lab;
}

export function algorithmInfo(lab: Lab, id: string) {
  return lab.catalog.algorithms.find((a) => a.id === id);
}

/** CAs that can sign: CA:TRUE, private key present, not revoked, not expired. */
export function issuers(lab: Lab): CertRow[] {
  return lab.certs.filter((c) => {
    if (!c.is_ca || c.key_id === null || c.revoked_at) return false;
    const key = lab.keys.find((k) => k.id === c.key_id);
    return !!key && key.has_private && new Date(c.not_after) > new Date();
  });
}
