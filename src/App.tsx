import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  api,
  type Catalog,
  type CertRow,
  type CrlRow,
  type CsrRow,
  type KeyRow,
  type Status,
  type Templates,
  type Warning,
} from "./api";
import { t } from "./i18n";
import { LabContext, type Lab, type Notice } from "./store";
import { warningMessage } from "./helpers";
import { Dialog, ErrorBox, Note, Tabs } from "./components/ui";
import { CertificatesView, CrlsView, CsrsView, KeysView, TemplatesView } from "./views/Views";
import { UnlockView } from "./views/UnlockView";
import { NewKeyDialog, ImportKeyDialog } from "./dialogs/KeyDialogs";
import { CertificateDialog } from "./dialogs/CertificateDialog";
import { ImportPkcs12Dialog } from "./dialogs/CertDialogs";
import { NewCsrDialog } from "./dialogs/OtherDialogs";

type Tab = "keys" | "csrs" | "certs" | "templates" | "crls";

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const loadStatus = useCallback(() => {
    api.status().then(setStatus);
  }, []);
  useEffect(loadStatus, [loadStatus]);

  if (!status) return null;
  if (status.openssl_error) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <div className="w-full max-w-lg space-y-3">
          <h1 className="font-semibold">{t("unlock.opensslError")}</h1>
          <ErrorBox error={status.openssl_error} />
        </div>
      </div>
    );
  }
  if (!status.unlocked) return <UnlockView status={status} onUnlocked={loadStatus} />;
  return <Workspace status={status} onLocked={loadStatus} />;
}

const emptyCatalog: Catalog = { algorithms: [], ext_key_usages: [], revocation_reasons: [] };

function Workspace({ status, onLocked }: { status: Status; onLocked: () => void }) {
  const [keys, setKeys] = useState<KeyRow[]>([]);
  const [certs, setCerts] = useState<CertRow[]>([]);
  const [csrs, setCsrs] = useState<CsrRow[]>([]);
  const [crls, setCrls] = useState<CrlRow[]>([]);
  const [templates, setTemplates] = useState<Templates>({ presets: [], user: [] });
  const [catalog, setCatalog] = useState<Catalog>(emptyCatalog);
  const [tab, setTab] = useState<Tab>("certs");
  const [selectedCert, setSelectedCert] = useState<number | null>(null);
  const [notices, setNotices] = useState<Notice[]>([]);
  const [dialog, setDialog] = useState<ReactNode | null>(null);
  const nextId = useRef(1);

  const refresh = useCallback(async () => {
    const [k, c, r, l, tp] = await Promise.all([
      api.listKeys(),
      api.listCertificates(),
      api.listCsrs(),
      api.listCrls(),
      api.listTemplates(),
    ]);
    setKeys(k);
    setCerts(c);
    setCsrs(r);
    setCrls(l);
    setTemplates(tp);
  }, []);

  useEffect(() => {
    api.catalog().then(setCatalog);
    refresh();
  }, [refresh]);

  const notify = useCallback((tone: Notice["tone"], text: string) => {
    const id = nextId.current++;
    setNotices((n) => [...n.slice(-3), { id, tone, text }]);
    if (tone === "ok") setTimeout(() => setNotices((n) => n.filter((x) => x.id !== id)), 4000);
  }, []);

  const lab: Lab = useMemo(
    () => ({
      keys,
      certs,
      csrs,
      crls,
      templates,
      catalog,
      refresh,
      notify,
      done: (warnings: Warning[] = []) => {
        notify("ok", t("result.created"));
        warnings.forEach((w) => notify("warn", warningMessage(w)));
      },
    }),
    [keys, certs, csrs, crls, templates, catalog, refresh, notify],
  );

  const lock = useCallback(async () => {
    await api.lock();
    onLocked();
  }, [onLocked]);

  // Native menu (src-tauri/src/lib.rs).
  useEffect(() => {
    const close = () => setDialog(null);
    const un = listen<string>("menu", (e) => {
      switch (e.payload) {
        case "new_key":
          setDialog(<NewKeyDialog onClose={close} />);
          break;
        case "new_cert":
          setDialog(<CertificateDialog mode={{ kind: "new", preset: "server" }} onClose={close} />);
          break;
        case "new_csr":
          setDialog(<NewCsrDialog onClose={close} />);
          break;
        case "import_pem":
          setDialog(<ImportKeyDialog onClose={close} />);
          break;
        case "import_p12":
          setDialog(<ImportPkcs12Dialog onClose={close} />);
          break;
        case "lock":
          lock();
          break;
        case "about":
          setDialog(<About status={status} onClose={close} />);
          break;
      }
    });
    return () => {
      un.then((f) => f());
    };
  }, [lock, status]);

  const tabs: [Tab, string][] = [
    ["keys", `${t("tabs.keys")} (${keys.length})`],
    ["csrs", `${t("tabs.csrs")} (${csrs.length})`],
    ["certs", `${t("tabs.certs")} (${certs.length})`],
    ["templates", `${t("tabs.templates")} (${templates.user.length})`],
    ["crls", `${t("tabs.crls")} (${crls.length})`],
  ];

  return (
    <LabContext.Provider value={lab}>
      <div className="flex h-full flex-col">
        <Tabs tabs={tabs} value={tab} onChange={setTab} className="flex-1 px-2 pt-2 pb-1">
          {tab === "keys" && <KeysView />}
          {tab === "csrs" && <CsrsView />}
          {tab === "certs" && <CertificatesView selected={selectedCert} onSelect={setSelectedCert} />}
          {tab === "templates" && <TemplatesView />}
          {tab === "crls" && <CrlsView />}
        </Tabs>
        <div className="statusbar">
          <span title={status.db_path ?? ""}>{t("status.db", { path: status.db_path ?? "" })}</span>
          <span>{status.openssl_version}</span>
          <span className="ml-auto">{t("app.labOnlyShort")}</span>
        </div>

        <div className="pointer-events-none fixed right-3 bottom-8 z-50 flex w-96 flex-col gap-2">
          {notices.map((n) => (
            <div
              key={n.id}
              className={`message pointer-events-auto ${n.tone === "error" ? "error" : n.tone === "warn" ? "warn" : ""}`}
              style={{ boxShadow: "0 4px 16px rgb(0 0 0 / 0.2)" }}
            >
              <span className={n.tone === "ok" ? "ok" : n.tone === "error" ? "danger" : ""}>
                {n.tone === "ok" ? "✓" : "⚠"}
              </span>
              <span className="flex-1 break-words">{n.text}</span>
              <button onClick={() => setNotices((x) => x.filter((y) => y.id !== n.id))}>{t("common.close")}</button>
            </div>
          ))}
        </div>
        {dialog}
      </div>
    </LabContext.Provider>
  );
}

function About({ status, onClose }: { status: Status; onClose: () => void }) {
  return (
    <Dialog title={t("dlg.about.title")} onClose={onClose}>
      <p>
        <strong>{t("app.name")}</strong> 0.2.0 — {t("dlg.about.license")}
      </p>
      <p>{t("dlg.about.body")}</p>
      <Note warn>{t("dlg.about.warning")}</Note>
      <div className="form">
        <label>{t("dlg.about.engine")}</label>
        <span className="mono selectable break-all">
          {status.openssl_version}
          <br />
          {status.openssl_path}
        </span>
        <label>{t("dlg.about.log")}</label>
        <span className="mono selectable break-all">{status.log_path}</span>
      </div>
    </Dialog>
  );
}
