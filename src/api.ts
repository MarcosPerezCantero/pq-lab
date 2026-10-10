// Typed wrappers over the Tauri commands in src-tauri/src/commands.rs.
import { invoke } from "@tauri-apps/api/core";

export type Family = "MlDsa" | "SlhDsa" | "MlKem";

export type KeyUsage =
  | "digitalSignature"
  | "nonRepudiation"
  | "keyEncipherment"
  | "dataEncipherment"
  | "keyAgreement"
  | "keyCertSign"
  | "cRLSign"
  | "encipherOnly"
  | "decipherOnly";

export const ALL_KEY_USAGES: KeyUsage[] = [
  "digitalSignature",
  "nonRepudiation",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly",
];

export interface AlgorithmInfo {
  id: string;
  family: Family;
  can_sign: boolean;
  can_be_ca: boolean;
  key_usages: KeyUsage[];
}

export interface Catalog {
  algorithms: AlgorithmInfo[];
  ext_key_usages: string[];
  revocation_reasons: string[];
}

/** X.509v3 extensions of a certificate (src-tauri/src/profile.rs). */
export interface CertProfile {
  ca: boolean;
  path_len: number | null;
  bc_critical: boolean;
  key_usage: KeyUsage[];
  ku_critical: boolean;
  ext_key_usage: string[];
  eku_critical: boolean;
  ski: boolean;
  aki: boolean;
  san: string[];
  san_critical: boolean;
  policies: string[];
  crl_dp: string[];
  ocsp: string[];
  ca_issuers: string[];
  nc_permitted: string[];
  nc_excluded: string[];
}

export interface Preset {
  id: string;
  profile: CertProfile;
  default_days: number;
  kem: boolean;
}

export interface TemplateRow {
  id: number;
  name: string;
  profile: CertProfile;
  created_at: string;
}

export interface Templates {
  presets: Preset[];
  user: TemplateRow[];
}

export interface ApiError {
  code: string;
  params: Record<string, string>;
  detail: string | null;
}

export interface Status {
  openssl_version: string | null;
  openssl_error: ApiError | null;
  openssl_path: string | null;
  default_db_path: string;
  default_db_exists: boolean;
  unlocked: boolean;
  db_path: string | null;
  log_path: string;
}

export interface KeyRow {
  id: number;
  name: string;
  algorithm: string;
  public_pem: string;
  has_private: boolean;
  created_at: string;
  cert_count: number;
}

export interface CertRow {
  id: number;
  name: string;
  key_id: number | null;
  issuer_id: number | null;
  template: string;
  is_ca: boolean;
  subject: string;
  issuer: string;
  serial: string;
  sig_algorithm: string;
  key_algorithm: string;
  not_before: string;
  not_after: string;
  fingerprint_sha256: string;
  pem: string;
  created_at: string;
  profile: CertProfile | null;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface CsrRow {
  id: number;
  name: string;
  key_id: number | null;
  subject: string;
  key_algorithm: string;
  pem: string;
  signed_cert_id: number | null;
  created_at: string;
}

export interface CrlRow {
  id: number;
  issuer_id: number;
  number: number;
  this_update: string;
  next_update: string;
  revoked_count: number;
  pem: string;
  created_at: string;
}

export interface Subject {
  cn: string;
  o: string;
  ou: string;
  c: string;
  st: string;
  l: string;
}

export interface Validity {
  days: number | null;
  not_before: string | null;
  not_after: string | null;
}

export interface Warning {
  code: string;
  params: Record<string, string>;
}

export interface Issued {
  id: number;
  warnings: Warning[];
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serial: string;
  not_before: string;
  not_after: string;
  fingerprint_sha256: string;
  sig_algorithm: string;
  key_algorithm: string;
  is_ca: boolean;
  path_len: number | null;
  sans: string[];
  key_usage: string | null;
  ext_key_usage: string | null;
  self_signed: boolean;
}

export interface CsrInfo {
  subject: string;
  key_algorithm: string;
  sig_algorithm: string;
  sans: string[];
}

export interface CertView {
  row: CertRow;
  info: CertInfo;
  text: string;
}

export interface CsrView {
  row: CsrRow;
  info: CsrInfo;
  text: string;
}

export interface CrlView {
  row: CrlRow;
  issuer_name: string;
  text: string;
}

export interface VerifyResult {
  ok: boolean;
  output: string;
  chain: string[];
  warnings: Warning[];
  crl_checked: boolean;
  crl_complete: boolean;
  revoked: boolean;
  revoked_chain: string[];
}

export interface Pkcs12Import {
  key_id: number | null;
  cert_ids: number[];
}

export interface IssueRequest {
  name: string;
  key_id: number;
  issuer_id: number | null;
  subject: Subject;
  profile: CertProfile;
  validity: Validity;
  template: string;
}

export function isApiError(e: unknown): e is ApiError {
  return typeof e === "object" && e !== null && "code" in e;
}

export const api = {
  status: () => invoke<Status>("app_status"),
  catalog: () => invoke<Catalog>("catalog"),
  createDatabase: (path: string, password: string) => invoke<void>("create_database", { path, password }),
  openDatabase: (path: string, password: string) => invoke<void>("open_database", { path, password }),
  lock: () => invoke<void>("lock_database"),

  listKeys: () => invoke<KeyRow[]>("list_keys"),
  generateKey: (name: string, algorithm: string) => invoke<number>("generate_key", { name, algorithm }),
  importKey: (name: string, pem: string, password: string | null) =>
    invoke<number>("import_key", { name, pem, password }),
  renameKey: (id: number, name: string) => invoke<void>("rename_key", { id, name }),
  deleteKey: (id: number) => invoke<void>("delete_key", { id }),
  exportPublicKey: (id: number, path: string) => invoke<void>("export_public_key", { id, path }),
  exportPrivateKey: (id: number, path: string, password: string) =>
    invoke<void>("export_private_key", { id, path, password }),

  listCertificates: () => invoke<CertRow[]>("list_certificates"),
  issueCertificate: (req: IssueRequest) => invoke<Issued>("issue_certificate", { req }),
  renewCertificate: (id: number, validity: Validity) => invoke<Issued>("renew_certificate", { id, validity }),
  revokeCertificate: (id: number, reason: string) => invoke<void>("revoke_certificate", { id, reason }),
  unrevokeCertificate: (id: number) => invoke<void>("unrevoke_certificate", { id }),
  importCertificate: (name: string, pem: string) => invoke<Issued>("import_certificate", { name, pem }),
  deleteCertificate: (id: number) => invoke<void>("delete_certificate", { id }),
  viewCertificate: (id: number) => invoke<CertView>("view_certificate", { id }),
  verifyChain: (id: number) => invoke<VerifyResult>("verify_chain", { id }),
  exportCertificate: (id: number, format: "pem" | "der", path: string) =>
    invoke<void>("export_certificate", { id, format, path }),
  exportChain: (id: number, path: string) => invoke<void>("export_chain", { id, path }),
  exportPkcs12: (id: number, path: string, password: string, chain: boolean) =>
    invoke<void>("export_pkcs12", { id, path, password, chain }),
  importPkcs12: (name: string, path: string, password: string) =>
    invoke<Pkcs12Import>("import_pkcs12", { name, path, password }),

  listTemplates: () => invoke<Templates>("list_templates"),
  saveTemplate: (id: number | null, name: string, profile: CertProfile) =>
    invoke<number>("save_template", { id, name, profile }),
  deleteTemplate: (id: number) => invoke<void>("delete_template", { id }),

  listCrls: () => invoke<CrlRow[]>("list_crls"),
  generateCrl: (issuerId: number, days: number) => invoke<number>("generate_crl", { issuerId, days }),
  viewCrl: (id: number) => invoke<CrlView>("view_crl", { id }),
  exportCrl: (id: number, format: "pem" | "der", path: string) => invoke<void>("export_crl", { id, format, path }),
  deleteCrl: (id: number) => invoke<void>("delete_crl", { id }),

  listCsrs: () => invoke<CsrRow[]>("list_csrs"),
  generateCsr: (req: { name: string; key_id: number; subject: Subject; profile: CertProfile | null }) =>
    invoke<number>("generate_csr", { req }),
  importCsr: (name: string, pem: string) => invoke<number>("import_csr", { name, pem }),
  signCsr: (req: {
    csr_id: number;
    issuer_id: number;
    name: string;
    profile: CertProfile;
    validity: Validity;
    template: string;
  }) => invoke<Issued>("sign_csr", { req }),
  deleteCsr: (id: number) => invoke<void>("delete_csr", { id }),
  viewCsr: (id: number) => invoke<CsrView>("view_csr", { id }),
  exportCsr: (id: number, path: string) => invoke<void>("export_csr", { id, path }),

  readPemFile: (path: string) => invoke<string>("read_pem_file", { path }),
};
