import { useEffect, useState } from "react";
import { api, type CertProfile, type CsrRow, type CsrView, type Validity } from "../api";
import { t } from "../i18n";
import { issuers, useLab } from "../store";
import {
  cloneProfile,
  emptyProfile,
  emptySubject,
  keyAlgorithm,
  resolveKey,
  templateLabel,
  useAction,
  validityDays,
  type KeyChoice,
} from "../helpers";
import { KeyPicker } from "../components/KeyPicker";
import { ProfileEditor, type ProfileTab } from "../components/ProfileEditor";
import { Dialog, DialogFooter, ErrorBox, Group, Note, Row, SubjectFields, Tabs, ValidityFields } from "../components/ui";

type Tab = "origin" | "subject" | ProfileTab;

export type CertificateMode =
  | { kind: "new"; preset: string; issuerId?: number | null }
  | { kind: "csr"; csr: CsrRow };

/** Default key algorithm offered for a preset. */
function defaultAlgorithm(preset: string): string {
  if (preset === "kem") return "ML-KEM-768";
  if (preset === "root") return "ML-DSA-87";
  if (preset === "intermediate") return "ML-DSA-65";
  return "ML-DSA-44";
}

/**
 * "Create x509 certificate" dialog, modelled on XCA: source and template,
 * subject and key, extensions, key usage and advanced constraints. Also signs
 * a stored CSR (`mode.kind === "csr"`).
 */
export function CertificateDialog({ mode, onClose }: { mode: CertificateMode; onClose: () => void }) {
  const lab = useLab();
  const isCsr = mode.kind === "csr";
  const initialPreset = mode.kind === "new" ? mode.preset : "server";
  const preset0 = lab.templates.presets.find((p) => p.id === initialPreset)!;
  const cas = issuers(lab);

  const [tab, setTab] = useState<Tab>("origin");
  const [templateId, setTemplateId] = useState(`preset:${initialPreset}`);
  const [templateName, setTemplateName] = useState(initialPreset);
  const [profile, setProfile] = useState<CertProfile>(cloneProfile(preset0?.profile ?? emptyProfile()));
  const [validity, setValidity] = useState<Validity>(validityDays(preset0?.default_days ?? 365));
  const [selfSigned, setSelfSigned] = useState(!isCsr && initialPreset === "root");
  const [issuer, setIssuer] = useState<number | null>(
    mode.kind === "new" && mode.issuerId ? mode.issuerId : (cas[0]?.id ?? null),
  );
  const [name, setName] = useState(isCsr ? mode.csr.name : "");
  const [subject, setSubject] = useState(emptySubject());
  const [key, setKey] = useState<KeyChoice>({ kind: "new", algorithm: defaultAlgorithm(initialPreset) });
  const [csrView, setCsrView] = useState<CsrView | null>(null);
  const [saveAs, setSaveAs] = useState<string | null>(null);
  const { busy, error, setError, run } = useAction();

  const algorithm = isCsr ? mode.csr.key_algorithm : keyAlgorithm(lab, key);
  const isKem = algorithm?.startsWith("ML-KEM") ?? false;

  useEffect(() => {
    if (mode.kind !== "csr") return;
    api.viewCsr(mode.csr.id).then((v) => {
      setCsrView(v);
      setProfile((p) => ({ ...p, san: v.info.sans }));
    });
  }, [mode]);

  function applyTemplate(id: string) {
    setTemplateId(id);
    let next: CertProfile | undefined;
    if (id.startsWith("preset:")) {
      const p = lab.templates.presets.find((x) => x.id === id.slice(7));
      if (!p) return;
      next = p.profile;
      setValidity(validityDays(p.default_days));
      setTemplateName(p.id);
      if (!isCsr) {
        if (p.kem !== isKem) setKey({ kind: "new", algorithm: defaultAlgorithm(p.id) });
        setSelfSigned(p.id === "root");
      }
    } else {
      const u = lab.templates.user.find((x) => String(x.id) === id.slice(5));
      if (!u) return;
      next = u.profile;
      setTemplateName(u.name);
    }
    setProfile({ ...cloneProfile(next), san: profile.san });
  }

  async function submit() {
    const certName = name.trim() || (isCsr ? mode.csr.name : subject.cn);
    const res = await run(async () => {
      if (!selfSigned && issuer === null) throw { code: "issuer_required", params: {}, detail: null };
      if (mode.kind === "csr") {
        return api.signCsr({
          csr_id: mode.csr.id,
          issuer_id: issuer!,
          name: certName,
          profile,
          validity,
          template: templateName,
        });
      }
      const key_id = await resolveKey(lab, key, certName);
      return api.issueCertificate({
        name: certName,
        key_id,
        issuer_id: selfSigned ? null : issuer,
        subject,
        profile,
        validity,
        template: templateName,
      });
    });
    await lab.refresh();
    if (res) {
      lab.done(res.warnings);
      onClose();
    }
  }

  async function saveTemplate() {
    if (!saveAs?.trim()) return;
    const ok = await run(async () => {
      await api.saveTemplate(null, saveAs.trim(), { ...profile, san: [] });
      return true;
    });
    if (ok) {
      await lab.refresh();
      lab.notify("ok", t("tpl.saved", { name: saveAs.trim() }));
      setSaveAs(null);
    }
  }

  const tabs: [Tab, string][] = [
    ["origin", t("cert.tab.origin")],
    ["subject", t("cert.tab.subject")],
    ["extensions", t("cert.tab.extensions")],
    ["usage", t("cert.tab.usage")],
    ["advanced", t("cert.tab.advanced")],
  ];

  return (
    <Dialog
      title={isCsr ? t("cert.titleCsr", { name: mode.csr.name }) : t("cert.title")}
      onClose={onClose}
      wide
      footer={
        <DialogFooter
          busy={busy}
          onCancel={onClose}
          onSubmit={submit}
          extra={
            saveAs === null ? (
              <button onClick={() => setSaveAs("")}>{t("cert.saveTemplate")}</button>
            ) : (
              <>
                <input
                  autoFocus
                  placeholder={t("tpl.name")}
                  value={saveAs}
                  onChange={(e) => setSaveAs(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && saveTemplate()}
                />
                <button onClick={saveTemplate} disabled={!saveAs.trim()}>
                  {t("common.save")}
                </button>
                <button onClick={() => setSaveAs(null)}>{t("common.cancel")}</button>
              </>
            )
          }
        />
      }
    >
      <Tabs tabs={tabs} value={tab} onChange={setTab} className="h-[560px]">
        <div className="h-full overflow-auto">
          {tab === "origin" && (
            <div className="flex flex-col gap-3">
              {isCsr && (
                <Group title={t("cert.csr")}>
                  <div className="form">
                    <Row label={t("cert.csrSubject")}>
                      <span className="selectable">{mode.csr.subject}</span>
                    </Row>
                    <Row label={t("common.algorithm")}>{mode.csr.key_algorithm}</Row>
                    <Row label={t("cert.csrSans")}>{csrView?.info.sans.join(", ") || "—"}</Row>
                  </div>
                </Group>
              )}
              <Group title={t("cert.signing")}>
                <div className="form">
                  {!isCsr && (
                    <Row label="">
                      <label className="check">
                        <input type="radio" checked={selfSigned} disabled={isKem} onChange={() => setSelfSigned(true)} />
                        {t("cert.selfSigned")}
                      </label>
                    </Row>
                  )}
                  <Row label="">
                    <label className="check">
                      <input type="radio" checked={!selfSigned} onChange={() => setSelfSigned(false)} />
                      {t("cert.signedBy")}
                    </label>
                    <select
                      className="flex-1"
                      disabled={selfSigned}
                      value={issuer ?? ""}
                      onChange={(e) => setIssuer(e.target.value ? Number(e.target.value) : null)}
                    >
                      <option value="">{t("common.selectPlaceholder")}</option>
                      {cas.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name} — {c.key_algorithm}
                        </option>
                      ))}
                    </select>
                  </Row>
                </div>
                {cas.length === 0 && <p className="muted mt-2">{t("cert.noIssuers")}</p>}
                {isKem && <p className="muted mt-2">{t("cert.kemHint")}</p>}
              </Group>
              <Group title={t("cert.template")}>
                <div className="form">
                  <Row label={t("cert.templateLabel")}>
                    <select className="flex-1" value={templateId} onChange={(e) => applyTemplate(e.target.value)}>
                      <optgroup label={t("tpl.presets")}>
                        {lab.templates.presets
                          .filter((p) => !isCsr || !p.kem)
                          .map((p) => (
                            <option key={p.id} value={`preset:${p.id}`}>
                              {templateLabel(p.id)}
                            </option>
                          ))}
                      </optgroup>
                      {lab.templates.user.length > 0 && (
                        <optgroup label={t("tpl.user")}>
                          {lab.templates.user.map((u) => (
                            <option key={u.id} value={`user:${u.id}`}>
                              {u.name}
                            </option>
                          ))}
                        </optgroup>
                      )}
                    </select>
                  </Row>
                </div>
                <p className="muted mt-2">{t("cert.templateHint")}</p>
              </Group>
              <Group title={t("cert.internalName")}>
                <div className="form">
                  <Row label={t("common.name")}>
                    <input
                      className="flex-1"
                      value={name}
                      placeholder={isCsr ? mode.csr.name : subject.cn || t("cert.namePlaceholder")}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </Row>
                </div>
              </Group>
            </div>
          )}
          {tab === "subject" &&
            (isCsr ? (
              <Note>{t("cert.subjectFromCsr", { subject: mode.csr.subject })}</Note>
            ) : (
              <div className="flex flex-col gap-3">
                <SubjectFields value={subject} onChange={setSubject} autoFocus />
                {isKem && <Note>{t("cert.kemAscii")}</Note>}
                <Group title={t("cert.key")}>
                  <div className="form">
                    <Row label={t("cert.keyLabel")}>
                      <KeyPicker
                        value={key}
                        onChange={setKey}
                        accept={(a) => (profile.ca ? a.can_be_ca : true)}
                        needPrivate={!(algorithm?.startsWith("ML-KEM") ?? false)}
                      />
                    </Row>
                  </div>
                  <p className="muted mt-2">{t("cert.keyHint")}</p>
                </Group>
              </div>
            ))}
          {tab === "extensions" && (
            <div className="flex flex-col gap-3">
              <ValidityFields value={validity} onChange={setValidity} />
              <ProfileEditor tab="extensions" value={profile} onChange={setProfile} algorithm={algorithm} />
            </div>
          )}
          {(tab === "usage" || tab === "advanced") && (
            <ProfileEditor tab={tab} value={profile} onChange={setProfile} algorithm={algorithm} />
          )}
        </div>
      </Tabs>
      <ErrorBox error={error} />
      {error?.code === "server_requires_san" && tab !== "extensions" && (
        <button
          className="self-start"
          onClick={() => {
            setTab("extensions");
            setError(null);
          }}
        >
          {t("cert.goToSan")}
        </button>
      )}
    </Dialog>
  );
}
