import { useState, type ReactNode } from "react";
import { ask, save } from "@tauri-apps/plugin-dialog";
import { api, type CertRow } from "../api";
import { t } from "../i18n";
import { useLab } from "../store";
import { ListView } from "../components/Table";
import { cnOf, errorMessage, formatDate, safeFileName, templateLabel, toApiError } from "../helpers";
import { ExportKeyDialog, ImportKeyDialog, NewKeyDialog, RenameKeyDialog } from "../dialogs/KeyDialogs";
import { CertificateDialog } from "../dialogs/CertificateDialog";
import {
  CertDetailsDialog,
  ExportCertDialog,
  ImportCertDialog,
  ImportPkcs12Dialog,
  RenewDialog,
  RevokeDialog,
  VerifyDialog,
} from "../dialogs/CertDialogs";
import {
  CrlDetailsDialog,
  CsrDetailsDialog,
  GenerateCrlDialog,
  ImportCsrDialog,
  NewCsrDialog,
  TemplateDialog,
} from "../dialogs/OtherDialogs";

type DialogNode = ReactNode | null;

/** List + XCA-style button column on the right. */
function Pane({ list, buttons, dialog }: { list: ReactNode; buttons: ReactNode; dialog: DialogNode }) {
  return (
    <div className="flex h-full gap-3">
      <div className="min-w-0 flex-1">{list}</div>
      <div className="buttoncol">{buttons}</div>
      {dialog}
    </div>
  );
}

function useDelete() {
  const lab = useLab();
  return async (name: string, fn: () => Promise<void>, message = "common.confirmDelete") => {
    if (!(await ask(t(message, { name }), { title: t("common.delete"), kind: "warning" }))) return false;
    try {
      await fn();
      await lab.refresh();
      return true;
    } catch (e) {
      lab.notify("error", errorMessage(toApiError(e)));
      return false;
    }
  };
}

export function KeysView() {
  const lab = useLab();
  const [sel, setSel] = useState<number | null>(null);
  const [dialog, setDialog] = useState<DialogNode>(null);
  const close = () => setDialog(null);
  const del = useDelete();
  const key = lab.keys.find((k) => k.id === sel) ?? null;

  return (
    <Pane
      dialog={dialog}
      list={
        <ListView
          rows={lab.keys}
          selected={sel}
          onSelect={setSel}
          onOpen={(id) => {
            const k = lab.keys.find((x) => x.id === id);
            if (k) setDialog(<ExportKeyDialog keyRow={k} onClose={close} />);
          }}
          empty={t("keys.empty")}
          columns={[
            { header: t("common.name"), cell: (k) => k.name, width: "34%" },
            { header: t("keys.type"), cell: (k) => k.algorithm },
            { header: t("keys.private"), cell: (k) => (k.has_private ? t("common.yes") : t("keys.publicOnly")), width: "13%" },
            { header: t("keys.uses"), cell: (k) => k.cert_count, width: "10%" },
            { header: t("common.created"), cell: (k) => formatDate(k.created_at), width: "13%" },
          ]}
        />
      }
      buttons={
        <>
          <button onClick={() => setDialog(<NewKeyDialog onClose={close} />)}>{t("keys.new")}</button>
          <button disabled={!key} onClick={() => key && setDialog(<ExportKeyDialog keyRow={key} onClose={close} />)}>
            {t("common.exportEllipsis")}
          </button>
          <button onClick={() => setDialog(<ImportKeyDialog onClose={close} />)}>{t("common.importEllipsis")}</button>
          <button disabled={!key} onClick={() => key && setDialog(<RenameKeyDialog keyRow={key} onClose={close} />)}>
            {t("keys.rename")}
          </button>
          <button
            disabled={!key}
            onClick={() => key && del(key.name, () => api.deleteKey(key.id)).then((ok) => ok && setSel(null))}
          >
            {t("common.delete")}
          </button>
        </>
      }
    />
  );
}

export function CsrsView() {
  const lab = useLab();
  const [sel, setSel] = useState<number | null>(null);
  const [dialog, setDialog] = useState<DialogNode>(null);
  const close = () => setDialog(null);
  const del = useDelete();
  const csr = lab.csrs.find((c) => c.id === sel) ?? null;

  async function exportCsr() {
    if (!csr) return;
    const path = await save({ defaultPath: `${safeFileName(csr.name)}.csr` });
    if (!path) return;
    try {
      await api.exportCsr(csr.id, path);
      lab.notify("ok", t("result.exported", { path }));
    } catch (e) {
      lab.notify("error", errorMessage(toApiError(e)));
    }
  }

  return (
    <Pane
      dialog={dialog}
      list={
        <ListView
          rows={lab.csrs}
          selected={sel}
          onSelect={setSel}
          onOpen={(id) => setDialog(<CsrDetailsDialog id={id} onClose={close} />)}
          empty={t("csrs.empty")}
          columns={[
            { header: t("common.name"), cell: (c) => c.name, width: "26%" },
            { header: t("csrs.subject"), cell: (c) => c.subject },
            { header: t("keys.type"), cell: (c) => c.key_algorithm, width: "18%" },
            {
              header: t("csrs.state"),
              cell: (c) => (c.signed_cert_id ? t("csrs.signed") : t("csrs.pending")) + (c.key_id === null ? ` · ${t("csrs.external")}` : ""),
              width: "18%",
            },
          ]}
        />
      }
      buttons={
        <>
          <button onClick={() => setDialog(<NewCsrDialog onClose={close} />)}>{t("csrs.new")}</button>
          <button disabled={!csr} onClick={exportCsr}>
            {t("common.exportEllipsis")}
          </button>
          <button onClick={() => setDialog(<ImportCsrDialog onClose={close} />)}>{t("common.importEllipsis")}</button>
          <button disabled={!csr} onClick={() => csr && setDialog(<CsrDetailsDialog id={csr.id} onClose={close} />)}>
            {t("common.details")}
          </button>
          <button
            disabled={!csr}
            onClick={() => csr && setDialog(<CertificateDialog mode={{ kind: "csr", csr }} onClose={close} />)}
          >
            {t("csrs.sign")}
          </button>
          <button
            disabled={!csr}
            onClick={() => csr && del(csr.name, () => api.deleteCsr(csr.id)).then((ok) => ok && setSel(null))}
          >
            {t("common.delete")}
          </button>
        </>
      }
    />
  );
}

function Status({ cert }: { cert: CertRow }) {
  if (cert.revoked_at) return <span className="danger">{t("certs.revoked")}</span>;
  if (new Date(cert.not_after) < new Date()) return <span className="danger">{t("certs.expired")}</span>;
  return <span>{t("certs.valid")}</span>;
}

export function CertificatesView({ selected, onSelect }: { selected: number | null; onSelect: (id: number | null) => void }) {
  const lab = useLab();
  const [dialog, setDialog] = useState<DialogNode>(null);
  const close = () => setDialog(null);
  const del = useDelete();
  const cert = lab.certs.find((c) => c.id === selected) ?? null;
  const canIssue = !!cert?.is_ca && !cert.revoked_at && lab.keys.some((k) => k.id === cert.key_id && k.has_private);
  const issuerFor = canIssue ? cert!.id : undefined;

  async function unrevoke(c: CertRow) {
    try {
      await api.unrevokeCertificate(c.id);
      await lab.refresh();
    } catch (e) {
      lab.notify("error", errorMessage(toApiError(e)));
    }
  }

  return (
    <Pane
      dialog={dialog}
      list={
        <ListView
          rows={lab.certs}
          selected={selected}
          onSelect={onSelect}
          parentOf={(c) => c.issuer_id}
          onOpen={(id) => setDialog(<CertDetailsDialog id={id} onClose={close} />)}
          empty={t("certs.empty")}
          columns={[
            { header: t("certs.internalName"), cell: (c) => c.name, width: "24%" },
            { header: t("certs.cn"), cell: (c) => cnOf(c.subject), width: "18%" },
            { header: t("certs.ca"), cell: (c) => (c.is_ca ? t("common.yes") : t("common.no")), width: "6%" },
            { header: t("keys.type"), cell: (c) => c.key_algorithm, width: "15%" },
            { header: t("certs.template"), cell: (c) => templateLabel(c.template), width: "14%" },
            { header: t("certs.expires"), cell: (c) => formatDate(c.not_after), width: "11%" },
            { header: t("certs.status"), cell: (c) => <Status cert={c} />, width: "12%" },
          ]}
        />
      }
      buttons={
        <>
          <button onClick={() => setDialog(<CertificateDialog mode={{ kind: "new", preset: issuerFor ? "server" : "root", issuerId: issuerFor }} onClose={close} />)}>
            {t("certs.new")}
          </button>
          <button disabled={!cert} onClick={() => cert && setDialog(<ExportCertDialog cert={cert} onClose={close} />)}>
            {t("common.exportEllipsis")}
          </button>
          <button onClick={() => setDialog(<ImportCertDialog onClose={close} />)}>{t("common.importEllipsis")}</button>
          <button onClick={() => setDialog(<ImportPkcs12Dialog onClose={close} />)}>{t("certs.importP12")}</button>
          <button disabled={!cert} onClick={() => cert && setDialog(<CertDetailsDialog id={cert.id} onClose={close} />)}>
            {t("common.details")}
          </button>
          <button
            disabled={!cert}
            onClick={() => cert && del(cert.name, () => api.deleteCertificate(cert.id), cert.is_ca ? "cert.confirmDeleteCa" : "common.confirmDelete").then((ok) => ok && onSelect(null))}
          >
            {t("common.delete")}
          </button>
          <hr />
          <button
            onClick={() => setDialog(<CertificateDialog mode={{ kind: "new", preset: "root" }} onClose={close} />)}
          >
            {t("certs.newRoot")}
          </button>
          <button
            disabled={!canIssue}
            onClick={() =>
              setDialog(<CertificateDialog mode={{ kind: "new", preset: "intermediate", issuerId: issuerFor }} onClose={close} />)
            }
          >
            {t("certs.newIntermediate")}
          </button>
          <hr />
          <button disabled={!cert} onClick={() => cert && setDialog(<VerifyDialog id={cert.id} onClose={close} />)}>
            {t("certs.verify")}
          </button>
          <button
            disabled={!cert?.profile}
            title={cert && !cert.profile ? t("certs.renewImported") : undefined}
            onClick={() => cert && setDialog(<RenewDialog cert={cert} onClose={close} />)}
          >
            {t("certs.renew")}
          </button>
          {cert?.revoked_at ? (
            <button onClick={() => unrevoke(cert)}>{t("certs.unrevoke")}</button>
          ) : (
            <button disabled={!cert || cert.issuer_id === null} onClick={() => cert && setDialog(<RevokeDialog cert={cert} onClose={close} />)}>
              {t("certs.revoke")}
            </button>
          )}
        </>
      }
    />
  );
}

export function TemplatesView() {
  const lab = useLab();
  const [sel, setSel] = useState<number | null>(null);
  const [dialog, setDialog] = useState<DialogNode>(null);
  const close = () => setDialog(null);
  const del = useDelete();
  const tpl = lab.templates.user.find((x) => x.id === sel) ?? null;
  const summary = (ku: string[], eku: string[]) => [...ku.map((u) => t(`ku.${u}`)), ...eku.map((e) => t(`eku.${e}`))].join(", ");

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="min-h-0 flex-1">
        <Pane
          dialog={dialog}
          list={
            <ListView
              rows={lab.templates.user}
              selected={sel}
              onSelect={setSel}
              onOpen={(id) => {
                const x = lab.templates.user.find((u) => u.id === id);
                if (x) setDialog(<TemplateDialog template={x} onClose={close} />);
              }}
              empty={t("tpl.empty")}
              columns={[
                { header: t("tpl.name"), cell: (x) => x.name, width: "30%" },
                { header: t("certs.ca"), cell: (x) => (x.profile.ca ? t("common.yes") : t("common.no")), width: "8%" },
                { header: t("tpl.usages"), cell: (x) => summary(x.profile.key_usage, x.profile.ext_key_usage) },
              ]}
            />
          }
          buttons={
            <>
              <button onClick={() => setDialog(<TemplateDialog template={null} onClose={close} />)}>{t("tpl.new")}</button>
              <button disabled={!tpl} onClick={() => tpl && setDialog(<TemplateDialog template={tpl} onClose={close} />)}>
                {t("tpl.edit")}
              </button>
              <button
                disabled={!tpl}
                onClick={() => tpl && del(tpl.name, () => api.deleteTemplate(tpl.id)).then((ok) => ok && setSel(null))}
              >
                {t("common.delete")}
              </button>
            </>
          }
        />
      </div>
      <p className="muted">{t("tpl.presetsHint", { list: lab.templates.presets.map((p) => templateLabel(p.id)).join(", ") })}</p>
    </div>
  );
}

export function CrlsView() {
  const lab = useLab();
  const [sel, setSel] = useState<number | null>(null);
  const [dialog, setDialog] = useState<DialogNode>(null);
  const close = () => setDialog(null);
  const del = useDelete();
  const crl = lab.crls.find((c) => c.id === sel) ?? null;
  const issuerName = (id: number) => lab.certs.find((c) => c.id === id)?.name ?? `#${id}`;

  async function exportCrl(format: "pem" | "der") {
    if (!crl) return;
    const path = await save({ defaultPath: `${safeFileName(issuerName(crl.issuer_id))}-${crl.number}.crl` });
    if (!path) return;
    try {
      await api.exportCrl(crl.id, format, path);
      lab.notify("ok", t("result.exported", { path }));
    } catch (e) {
      lab.notify("error", errorMessage(toApiError(e)));
    }
  }

  return (
    <Pane
      dialog={dialog}
      list={
        <ListView
          rows={lab.crls}
          selected={sel}
          onSelect={setSel}
          onOpen={(id) => setDialog(<CrlDetailsDialog id={id} onClose={close} />)}
          empty={t("crls.empty")}
          columns={[
            { header: t("crls.issuer"), cell: (c) => issuerName(c.issuer_id), width: "30%" },
            { header: t("crls.number"), cell: (c) => c.number, width: "10%" },
            { header: t("crls.thisUpdate"), cell: (c) => formatDate(c.this_update) },
            { header: t("crls.nextUpdate"), cell: (c) => formatDate(c.next_update) },
            { header: t("crls.revoked"), cell: (c) => c.revoked_count, width: "12%" },
          ]}
        />
      }
      buttons={
        <>
          <button onClick={() => setDialog(<GenerateCrlDialog onClose={close} />)}>{t("crls.generate")}</button>
          <button disabled={!crl} onClick={() => exportCrl("pem")}>
            {t("crls.exportPem")}
          </button>
          <button disabled={!crl} onClick={() => exportCrl("der")}>
            {t("crls.exportDer")}
          </button>
          <button disabled={!crl} onClick={() => crl && setDialog(<CrlDetailsDialog id={crl.id} onClose={close} />)}>
            {t("common.details")}
          </button>
          <button
            disabled={!crl}
            onClick={() =>
              crl && del(`CRL #${crl.number} (${issuerName(crl.issuer_id)})`, () => api.deleteCrl(crl.id)).then((ok) => ok && setSel(null))
            }
          >
            {t("common.delete")}
          </button>
        </>
      }
    />
  );
}
