import { useEffect, useState, type ReactNode } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, type CertRow, type CertView, type Validity, type VerifyResult } from "../api";
import { t } from "../i18n";
import { useLab } from "../store";
import { formatDateTime, safeFileName, templateLabel, toApiError, useAction, validityDays, warningMessage } from "../helpers";
import { Dialog, DialogFooter, ErrorBox, Group, Note, PemInput, Row, Tabs, ValidityFields } from "../components/ui";

export function ImportCertDialog({ onClose }: { onClose: () => void }) {
  const lab = useLab();
  const [name, setName] = useState("");
  const [pem, setPem] = useState("");
  const { busy, error, setError, run } = useAction();

  async function submit() {
    const res = await run(() => api.importCertificate(name, pem));
    if (res) {
      await lab.refresh();
      lab.done(res.warnings);
      onClose();
    }
  }

  return (
    <Dialog
      title={t("dlg.importCert.title")}
      onClose={onClose}
      footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} submitLabel={t("common.import")} />}
    >
      <div className="form">
        <Row label={t("common.name")}>
          <input className="flex-1" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </Row>
      </div>
      <PemInput label="PEM" value={pem} onChange={setPem} onError={setError} />
      <Note>{t("dlg.importCert.hint")}</Note>
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function ImportPkcs12Dialog({ onClose }: { onClose: () => void }) {
  const lab = useLab();
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAction();

  async function browse() {
    const p = await open({ multiple: false, directory: false, filters: [{ name: "PKCS#12", extensions: ["p12", "pfx"] }] });
    if (typeof p === "string") {
      setPath(p);
      if (!name) setName(p.split(/[\\/]/).pop()!.replace(/\.(p12|pfx)$/i, ""));
    }
  }

  async function submit() {
    const res = await run(() => api.importPkcs12(name, path, password));
    if (res) {
      await lab.refresh();
      lab.notify("ok", t("dlg.importP12.done", { certs: res.cert_ids.length, key: res.key_id ? t("common.yes") : t("common.no") }));
      onClose();
    }
  }

  return (
    <Dialog
      title={t("dlg.importP12.title")}
      onClose={onClose}
      footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} submitLabel={t("common.import")} disabled={!path} />}
    >
      <div className="form">
        <Row label={t("dlg.importP12.file")}>
          <input className="mono flex-1" value={path} onChange={(e) => setPath(e.target.value)} />
          <button onClick={browse}>{t("common.browse")}</button>
        </Row>
        <Row label={t("common.name")}>
          <input className="flex-1" value={name} onChange={(e) => setName(e.target.value)} />
        </Row>
        <Row label={t("dlg.importP12.password")}>
          <input className="flex-1" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </Row>
      </div>
      <Note>{t("dlg.importP12.hint")}</Note>
      <ErrorBox error={error} />
    </Dialog>
  );
}

type ExportKind = "pem" | "der" | "chain" | "pub" | "p12";

export function ExportCertDialog({ cert, onClose }: { cert: CertRow; onClose: () => void }) {
  const lab = useLab();
  const [kind, setKind] = useState<ExportKind>("pem");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [withChain, setWithChain] = useState(true);
  const { busy, error, run } = useAction();
  const key = lab.keys.find((k) => k.id === cert.key_id);

  async function submit() {
    const ext = { pem: ".pem", der: ".der", chain: ".chain.pem", pub: ".pub.pem", p12: ".p12" }[kind];
    const path = await save({ defaultPath: safeFileName(cert.name) + ext });
    if (!path) return;
    const ok = await run(async () => {
      if (kind === "chain") await api.exportChain(cert.id, path);
      else if (kind === "pub") await api.exportPublicKey(cert.key_id!, path);
      else if (kind === "p12") await api.exportPkcs12(cert.id, path, password, withChain);
      else await api.exportCertificate(cert.id, kind, path);
      return true;
    });
    if (ok) {
      lab.notify("ok", t("result.exported", { path }));
      onClose();
    }
  }

  const options: [ExportKind, string, boolean][] = [
    ["pem", t("dlg.exportCert.pem"), true],
    ["der", t("dlg.exportCert.der"), true],
    ["chain", t("dlg.exportCert.chain"), true],
    ["pub", t("dlg.exportCert.publicKey"), !!key],
    ["p12", t("dlg.exportCert.p12"), !!key?.has_private],
  ];

  return (
    <Dialog
      title={t("dlg.exportCert.title", { name: cert.name })}
      onClose={onClose}
      footer={
        <DialogFooter
          busy={busy}
          onCancel={onClose}
          onSubmit={submit}
          submitLabel={t("common.export")}
          disabled={kind === "p12" && (!password || password !== repeat)}
        />
      }
    >
      <Group title={t("dlg.exportCert.what")}>
        <div className="flex flex-col gap-1.5">
          {options.map(([k, label, enabled]) => (
            <label key={k} className={`check ${enabled ? "" : "muted"}`}>
              <input type="radio" name="kind" checked={kind === k} disabled={!enabled} onChange={() => setKind(k)} />
              {label}
            </label>
          ))}
        </div>
      </Group>
      {kind === "p12" && (
        <Group title={t("dlg.exportCert.p12Group")}>
          <div className="form">
            <Row label={t("dlg.exportPrivate.password")}>
              <input className="flex-1" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
            </Row>
            <Row label={t("dlg.exportPrivate.repeat")}>
              <input className="flex-1" type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
            </Row>
            <Row label="">
              <label className="check">
                <input type="checkbox" checked={withChain} onChange={(e) => setWithChain(e.target.checked)} />
                {t("dlg.exportCert.p12Chain")}
              </label>
            </Row>
          </div>
          {repeat && password !== repeat && <p className="danger mt-2">{t("unlock.mismatch")}</p>}
        </Group>
      )}
      <ErrorBox error={error} />
    </Dialog>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Row label={label}>
      <span className="selectable min-w-0 break-words">{children}</span>
    </Row>
  );
}

export function CertDetailsDialog({ id, onClose }: { id: number; onClose: () => void }) {
  const [view, setView] = useState<CertView | null>(null);
  const [tab, setTab] = useState<"summary" | "text" | "pem">("summary");
  const { error, setError } = useAction();

  useEffect(() => {
    api
      .viewCertificate(id)
      .then(setView)
      .catch((e) => setError(toApiError(e)));
  }, [id, setError]);

  const info = view?.info;
  const row = view?.row;
  return (
    <Dialog title={t("dlg.details.title", { name: row?.name ?? "" })} onClose={onClose} wide>
      <ErrorBox error={error} />
      <Tabs
        tabs={[
          ["summary", t("dlg.details.summary")],
          ["text", t("dlg.details.text")],
          ["pem", "PEM"],
        ]}
        value={tab}
        onChange={setTab}
        className="h-[520px]"
      >
        <div className="h-full overflow-auto">
          {view && info && row && tab === "summary" && (
            <div className="flex flex-col gap-3">
              <Group title={t("dlg.details.identity")}>
                <div className="form">
                  <Field label={t("certs.subject")}>{info.subject}</Field>
                  <Field label={t("dlg.details.issuer")}>
                    {info.issuer} {info.self_signed && <em className="muted">({t("dlg.details.selfSigned")})</em>}
                  </Field>
                  <Field label={t("dlg.details.serial")}>
                    <span className="mono">{info.serial}</span>
                  </Field>
                  <Field label={t("dlg.details.validity")}>
                    {formatDateTime(info.not_before)} — {formatDateTime(info.not_after)}
                  </Field>
                  <Field label={t("certs.template")}>{templateLabel(row.template)}</Field>
                  {row.revoked_at && (
                    <Field label={t("certs.revoked")}>
                      <span className="danger">
                        {formatDateTime(row.revoked_at)} — {t(`reason.${row.revocation_reason}`)}
                      </span>
                    </Field>
                  )}
                </div>
              </Group>
              <Group title={t("dlg.details.algorithms")}>
                <div className="form">
                  <Field label={t("dlg.details.keyAlg")}>{info.key_algorithm}</Field>
                  <Field label={t("dlg.details.sigAlg")}>{info.sig_algorithm}</Field>
                  <Field label={t("dlg.details.fingerprint")}>
                    <span className="mono break-all">{info.fingerprint_sha256}</span>
                  </Field>
                </div>
              </Group>
              <Group title={t("dlg.details.extensions")}>
                <div className="form">
                  <Field label={t("dlg.details.isCa")}>
                    {info.is_ca ? t("common.yes") : t("common.no")}
                    {info.path_len !== null && ` (pathlen ${info.path_len})`}
                  </Field>
                  <Field label={t("dlg.details.keyUsage")}>{info.key_usage ?? "—"}</Field>
                  <Field label={t("dlg.details.extKeyUsage")}>{info.ext_key_usage ?? "—"}</Field>
                  <Field label={t("dlg.details.sans")}>{info.sans.join(", ") || "—"}</Field>
                </div>
                <p className="muted mt-2">{t("dlg.details.moreInText")}</p>
              </Group>
            </div>
          )}
          {view && tab === "text" && <pre className="pre mono h-full max-h-none">{view.text}</pre>}
          {view && tab === "pem" && <pre className="pre mono h-full max-h-none">{view.row.pem}</pre>}
        </div>
      </Tabs>
    </Dialog>
  );
}

export function VerifyDialog({ id, onClose }: { id: number; onClose: () => void }) {
  const [result, setResult] = useState<VerifyResult | null>(null);
  const { error, setError } = useAction();

  useEffect(() => {
    api
      .verifyChain(id)
      .then(setResult)
      .catch((e) => setError(toApiError(e)));
  }, [id, setError]);

  return (
    <Dialog title={t("dlg.verify.title")} onClose={onClose}>
      <ErrorBox error={error} />
      {!result && !error && <p className="muted">{t("common.working")}</p>}
      {result && (
        <>
          <div className={`message ${result.ok ? "" : "error"}`}>
            <strong className={result.ok ? "ok" : "danger"}>
              {result.ok
                ? t("dlg.verify.ok")
                : result.revoked
                  ? t("dlg.verify.revoked")
                  : result.revoked_chain.length > 0
                    ? t("dlg.verify.revokedChain", { names: result.revoked_chain.join(", ") })
                    : t("dlg.verify.fail")}
            </strong>
          </div>
          {result.warnings.map((w) => (
            <Note key={w.code} warn>
              {warningMessage(w)}
            </Note>
          ))}
          <Group title={t("dlg.verify.chain")}>
            <div className="mono">
              {[...result.chain].reverse().map((n, i) => (
                <div key={i} style={{ paddingLeft: i * 16 }}>
                  {i === 0 ? "" : "└─ "}
                  {n}
                </div>
              ))}
            </div>
          </Group>
          <p className="muted">{result.crl_complete
              ? t("dlg.verify.crlChecked")
              : result.crl_checked
                ? t("dlg.verify.crlLeaf")
                : t("dlg.verify.noCrl")}</p>
          {result.output && <pre className="pre mono">{result.output}</pre>}
        </>
      )}
    </Dialog>
  );
}

export function RevokeDialog({ cert, onClose }: { cert: CertRow; onClose: () => void }) {
  const lab = useLab();
  const [reason, setReason] = useState("keyCompromise");
  const { busy, error, run } = useAction();

  async function submit() {
    const ok = await run(async () => {
      await api.revokeCertificate(cert.id, reason);
      return true;
    });
    if (ok) {
      await lab.refresh();
      lab.notify("ok", t("dlg.revoke.done", { name: cert.name }));
      onClose();
    }
  }

  return (
    <Dialog
      title={t("dlg.revoke.title", { name: cert.name })}
      onClose={onClose}
      footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} submitLabel={t("certs.revoke")} />}
    >
      <div className="form">
        <Row label={t("dlg.revoke.reason")}>
          <select className="flex-1" value={reason} onChange={(e) => setReason(e.target.value)}>
            {lab.catalog.revocation_reasons.map((r) => (
              <option key={r} value={r}>
                {t(`reason.${r}`)}
              </option>
            ))}
          </select>
        </Row>
      </div>
      <Note>{t("dlg.revoke.hint")}</Note>
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function RenewDialog({ cert, onClose }: { cert: CertRow; onClose: () => void }) {
  const lab = useLab();
  const span = Math.max(1, Math.round((Date.parse(cert.not_after) - Date.parse(cert.not_before)) / 86400000));
  const [validity, setValidity] = useState<Validity>(validityDays(span));
  const { busy, error, run } = useAction();

  async function submit() {
    const res = await run(() => api.renewCertificate(cert.id, validity));
    await lab.refresh();
    if (res) {
      lab.done(res.warnings);
      onClose();
    }
  }

  return (
    <Dialog
      title={t("dlg.renew.title", { name: cert.name })}
      onClose={onClose}
      footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} submitLabel={t("certs.renew")} />}
    >
      <Note>{t("dlg.renew.hint")}</Note>
      <ValidityFields value={validity} onChange={setValidity} />
      <ErrorBox error={error} />
    </Dialog>
  );
}
