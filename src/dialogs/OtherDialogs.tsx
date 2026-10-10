import { useEffect, useState } from "react";
import { api, type CertProfile, type CrlView, type CsrView, type TemplateRow } from "../api";
import { t } from "../i18n";
import { issuers, useLab } from "../store";
import { cloneProfile, emptyProfile, emptySubject, resolveKey, templateLabel, toApiError, useAction, type KeyChoice } from "../helpers";
import { KeyPicker } from "../components/KeyPicker";
import { ProfileEditor, type ProfileTab } from "../components/ProfileEditor";
import { Dialog, DialogFooter, ErrorBox, Group, Note, PemInput, Row, SubjectFields, Tabs } from "../components/ui";

export function NewCsrDialog({ onClose }: { onClose: () => void }) {
  const lab = useLab();
  const [name, setName] = useState("");
  const [subject, setSubject] = useState(emptySubject());
  const [key, setKey] = useState<KeyChoice>({ kind: "new", algorithm: "ML-DSA-65" });
  const [template, setTemplate] = useState("");
  const [sans, setSans] = useState("");
  const { busy, error, run } = useAction();

  async function submit() {
    const csrName = name || subject.cn;
    const id = await run(async () => {
      const key_id = await resolveKey(lab, key, csrName);
      let profile: CertProfile | null = null;
      if (template) {
        const preset = lab.templates.presets.find((p) => `preset:${p.id}` === template);
        const user = lab.templates.user.find((u) => `user:${u.id}` === template);
        profile = cloneProfile(preset?.profile ?? user?.profile ?? emptyProfile());
      }
      const sanList = sans
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (sanList.length) profile = { ...(profile ?? { ...emptyProfile(), aki: false }), san: sanList };
      return api.generateCsr({ name: csrName, key_id, subject, profile });
    });
    await lab.refresh();
    if (id !== undefined) {
      lab.done();
      onClose();
    }
  }

  return (
    <Dialog title={t("dlg.newCsr.title")} onClose={onClose} wide footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} />}>
      <div className="grid grid-cols-2 gap-3">
        <SubjectFields value={subject} onChange={setSubject} autoFocus />
        <div className="flex flex-col gap-3">
          <Group title={t("cert.key")}>
            <div className="form">
              <Row label={t("cert.keyLabel")}>
                <KeyPicker value={key} onChange={setKey} accept={(a) => a.can_sign} />
              </Row>
              <Row label={t("common.name")}>
                <input className="flex-1" value={name} placeholder={subject.cn} onChange={(e) => setName(e.target.value)} />
              </Row>
            </div>
          </Group>
          <Group title={t("dlg.newCsr.requested")}>
            <div className="form">
              <Row label={t("cert.templateLabel")}>
                <select className="flex-1" value={template} onChange={(e) => setTemplate(e.target.value)}>
                  <option value="">{t("common.none")}</option>
                  {lab.templates.presets
                    .filter((p) => !p.kem)
                    .map((p) => (
                      <option key={p.id} value={`preset:${p.id}`}>
                        {templateLabel(p.id)}
                      </option>
                    ))}
                  {lab.templates.user.map((u) => (
                    <option key={u.id} value={`user:${u.id}`}>
                      {u.name}
                    </option>
                  ))}
                </select>
              </Row>
              <Row label="SAN">
                <textarea className="mono flex-1" rows={3} value={sans} onChange={(e) => setSans(e.target.value)} />
              </Row>
            </div>
          </Group>
        </div>
      </div>
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function ImportCsrDialog({ onClose }: { onClose: () => void }) {
  const lab = useLab();
  const [name, setName] = useState("");
  const [pem, setPem] = useState("");
  const { busy, error, setError, run } = useAction();

  async function submit() {
    const id = await run(() => api.importCsr(name, pem));
    if (id !== undefined) {
      await lab.refresh();
      lab.done();
      onClose();
    }
  }

  return (
    <Dialog
      title={t("dlg.importCsr.title")}
      onClose={onClose}
      footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} submitLabel={t("common.import")} />}
    >
      <div className="form">
        <Row label={t("common.name")}>
          <input className="flex-1" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </Row>
      </div>
      <PemInput label="PEM" value={pem} onChange={setPem} onError={setError} />
      <Note>{t("dlg.importCsr.hint")}</Note>
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function CsrDetailsDialog({ id, onClose }: { id: number; onClose: () => void }) {
  const [view, setView] = useState<CsrView | null>(null);
  const [tab, setTab] = useState<"text" | "pem">("text");
  const { error, setError } = useAction();

  useEffect(() => {
    api
      .viewCsr(id)
      .then(setView)
      .catch((e) => setError(toApiError(e)));
  }, [id, setError]);

  return (
    <Dialog title={t("dlg.details.title", { name: view?.row.name ?? "" })} onClose={onClose} wide>
      <ErrorBox error={error} />
      {view && (
        <Group title={t("dlg.details.summary")}>
          <div className="form">
            <Row label={t("certs.subject")}>
              <span className="selectable">{view.info.subject}</span>
            </Row>
            <Row label={t("dlg.details.keyAlg")}>{view.info.key_algorithm}</Row>
            <Row label={t("dlg.details.sigAlg")}>{view.info.sig_algorithm}</Row>
            <Row label={t("dlg.details.sans")}>{view.info.sans.join(", ") || "—"}</Row>
          </div>
        </Group>
      )}
      <Tabs
        tabs={[
          ["text", t("dlg.details.text")],
          ["pem", "PEM"],
        ]}
        value={tab}
        onChange={setTab}
      >
        {view && <pre className="pre mono">{tab === "text" ? view.text : view.row.pem}</pre>}
      </Tabs>
    </Dialog>
  );
}

export function TemplateDialog({ template, onClose }: { template: TemplateRow | null; onClose: () => void }) {
  const lab = useLab();
  const [name, setName] = useState(template?.name ?? "");
  const [base, setBase] = useState("");
  const [profile, setProfile] = useState<CertProfile>(cloneProfile(template?.profile ?? emptyProfile()));
  const [tab, setTab] = useState<ProfileTab>("extensions");
  const { busy, error, run } = useAction();

  function startFrom(id: string) {
    setBase(id);
    const p = lab.templates.presets.find((x) => x.id === id);
    if (p) setProfile(cloneProfile(p.profile));
  }

  async function submit() {
    const ok = await run(async () => {
      await api.saveTemplate(template?.id ?? null, name, profile);
      return true;
    });
    if (ok) {
      await lab.refresh();
      lab.notify("ok", t("tpl.saved", { name }));
      onClose();
    }
  }

  return (
    <Dialog
      title={template ? t("tpl.editTitle", { name: template.name }) : t("tpl.newTitle")}
      onClose={onClose}
      wide
      footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} submitLabel={t("common.save")} />}
    >
      <div className="form">
        <Row label={t("tpl.name")}>
          <input className="flex-1" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </Row>
        {!template && (
          <Row label={t("tpl.startFrom")}>
            <select className="flex-1" value={base} onChange={(e) => startFrom(e.target.value)}>
              <option value="">{t("tpl.empty")}</option>
              {lab.templates.presets.map((p) => (
                <option key={p.id} value={p.id}>
                  {templateLabel(p.id)}
                </option>
              ))}
            </select>
          </Row>
        )}
      </div>
      <Tabs
        tabs={[
          ["extensions", t("cert.tab.extensions")],
          ["usage", t("cert.tab.usage")],
          ["advanced", t("cert.tab.advanced")],
        ]}
        value={tab}
        onChange={setTab}
        className="h-[470px]"
      >
        <div className="h-full overflow-auto">
          <ProfileEditor tab={tab} value={profile} onChange={setProfile} algorithm={null} showSan={false} />
        </div>
      </Tabs>
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function GenerateCrlDialog({ onClose, defaultIssuer }: { onClose: () => void; defaultIssuer?: number }) {
  const lab = useLab();
  const cas = issuers(lab);
  const [issuer, setIssuer] = useState<number | null>(defaultIssuer ?? cas[0]?.id ?? null);
  const [days, setDays] = useState("30");
  const { busy, error, run } = useAction();
  const revoked = lab.certs.filter((c) => c.issuer_id === issuer && c.revoked_at).length;

  async function submit() {
    const id = await run(async () => {
      if (issuer === null) throw { code: "issuer_required", params: {}, detail: null };
      return api.generateCrl(issuer, parseInt(days, 10) || 30);
    });
    if (id !== undefined) {
      await lab.refresh();
      lab.done();
      onClose();
    }
  }

  return (
    <Dialog title={t("dlg.crl.title")} onClose={onClose} footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} />}>
      <div className="form">
        <Row label={t("dlg.crl.issuer")}>
          <select className="flex-1" value={issuer ?? ""} onChange={(e) => setIssuer(e.target.value ? Number(e.target.value) : null)}>
            <option value="">{t("common.selectPlaceholder")}</option>
            {cas.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </Row>
        <Row label={t("dlg.crl.days")}>
          <input type="number" min={1} max={3650} style={{ width: 90 }} value={days} onChange={(e) => setDays(e.target.value)} />
        </Row>
        <Row label={t("dlg.crl.revoked")}>{revoked}</Row>
      </div>
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function CrlDetailsDialog({ id, onClose }: { id: number; onClose: () => void }) {
  const [view, setView] = useState<CrlView | null>(null);
  const { error, setError } = useAction();
  useEffect(() => {
    api
      .viewCrl(id)
      .then(setView)
      .catch((e) => setError(toApiError(e)));
  }, [id, setError]);
  return (
    <Dialog title={t("dlg.crlDetails.title", { name: view?.issuer_name ?? "", number: view?.row.number ?? "" })} onClose={onClose} wide>
      <ErrorBox error={error} />
      {view && <pre className="pre mono">{view.text}</pre>}
    </Dialog>
  );
}
