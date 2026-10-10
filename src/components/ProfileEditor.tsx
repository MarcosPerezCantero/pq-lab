import { ALL_KEY_USAGES, type CertProfile, type KeyUsage } from "../api";
import { t } from "../i18n";
import { algorithmInfo, useLab } from "../store";
import { Check, Group, LinesInput, Row } from "./ui";

/** Tabs of the extension editor, shared by certificate and template dialogs. */
export type ProfileTab = "extensions" | "usage" | "advanced";

/**
 * XCA-style extension editor. `algorithm` (when known) restricts the keyUsage
 * checkboxes to the bits allowed for that post-quantum algorithm.
 */
export function ProfileEditor({
  tab,
  value,
  onChange,
  algorithm,
  showSan = true,
}: {
  tab: ProfileTab;
  value: CertProfile;
  onChange: (p: CertProfile) => void;
  algorithm: string | null;
  showSan?: boolean;
}) {
  const lab = useLab();
  const set = <K extends keyof CertProfile>(k: K, v: CertProfile[K]) => onChange({ ...value, [k]: v });
  const allowed = algorithm ? algorithmInfo(lab, algorithm)?.key_usages : undefined;
  const isKem = algorithm?.startsWith("ML-KEM") ?? false;

  if (tab === "extensions") {
    return (
      <div className="flex flex-col gap-3">
        <div className="grid grid-cols-2 gap-3">
          <Group title={t("ext.basicConstraints")}>
            <div className="form">
              <Row label={t("ext.type")}>
                <select
                  value={value.ca ? "ca" : "ee"}
                  disabled={isKem}
                  onChange={(e) => {
                    const ca = e.target.value === "ca";
                    const ku = value.key_usage.filter((u) => u !== "keyCertSign" && u !== "cRLSign");
                    onChange({
                      ...value,
                      ca,
                      path_len: ca ? value.path_len : null,
                      key_usage: ca ? [...ku, "keyCertSign", "cRLSign"] : ku,
                      nc_permitted: ca ? value.nc_permitted : [],
                      nc_excluded: ca ? value.nc_excluded : [],
                    });
                  }}
                >
                  <option value="ee">{t("ext.endEntity")}</option>
                  <option value="ca">{t("ext.ca")}</option>
                </select>
              </Row>
              <Row label={t("ext.pathLen")}>
                <input
                  type="number"
                  min={0}
                  max={32}
                  style={{ width: 70 }}
                  disabled={!value.ca}
                  placeholder={t("ext.unlimited")}
                  value={value.path_len ?? ""}
                  onChange={(e) => set("path_len", e.target.value === "" ? null : parseInt(e.target.value, 10))}
                />
              </Row>
              <Row label="">
                <Check label={t("ext.critical")} checked={value.bc_critical} onChange={(v) => set("bc_critical", v)} />
              </Row>
            </div>
          </Group>
          <Group title={t("ext.keyIdentifiers")}>
            <div className="flex flex-col gap-1.5">
              <Check label={t("ext.ski")} checked={value.ski} onChange={(v) => set("ski", v)} />
              <Check label={t("ext.aki")} checked={value.aki} onChange={(v) => set("aki", v)} />
            </div>
          </Group>
        </div>
        {showSan && (
          <Group title={t("ext.san")}>
            <LinesInput value={value.san} onChange={(v) => set("san", v)} placeholder={t("ext.sanPlaceholder")} />
            <div className="mt-1 flex justify-between">
              <span className="muted">{t("ext.sanHint")}</span>
              <Check label={t("ext.critical")} checked={value.san_critical} onChange={(v) => set("san_critical", v)} />
            </div>
          </Group>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Group title={t("ext.crlDp")}>
            <LinesInput value={value.crl_dp} onChange={(v) => set("crl_dp", v)} rows={2} placeholder="http://crl.lab/ca.crl" />
          </Group>
          <Group title={t("ext.policies")}>
            <LinesInput value={value.policies} onChange={(v) => set("policies", v)} rows={2} placeholder="anyPolicy / 1.3.6.1.4.1…" />
          </Group>
          <Group title={t("ext.ocsp")}>
            <LinesInput value={value.ocsp} onChange={(v) => set("ocsp", v)} rows={2} placeholder="http://ocsp.lab" />
          </Group>
          <Group title={t("ext.caIssuers")}>
            <LinesInput value={value.ca_issuers} onChange={(v) => set("ca_issuers", v)} rows={2} placeholder="http://ca.lab/ca.cer" />
          </Group>
        </div>
      </div>
    );
  }

  if (tab === "usage") {
    const toggleKu = (u: KeyUsage, on: boolean) =>
      set("key_usage", on ? [...value.key_usage, u] : value.key_usage.filter((x) => x !== u));
    const known = lab.catalog.ext_key_usages;
    const custom = value.ext_key_usage.filter((e) => !known.includes(e));
    const toggleEku = (e: string, on: boolean) =>
      set("ext_key_usage", on ? [...value.ext_key_usage, e] : value.ext_key_usage.filter((x) => x !== e));
    return (
      <div className="grid grid-cols-2 gap-3">
        <Group title={t("ext.keyUsage")}>
          <div className="flex flex-col gap-1">
            {ALL_KEY_USAGES.map((u) => {
              const notAllowed = !!allowed && !allowed.includes(u);
              return (
                <Check
                  key={u}
                  label={t(`ku.${u}`)}
                  checked={value.key_usage.includes(u)}
                  disabled={notAllowed && !value.key_usage.includes(u)}
                  title={notAllowed ? t("ext.kuNotAllowed", { algorithm: algorithm ?? "" }) : undefined}
                  onChange={(on) => toggleKu(u, on)}
                />
              );
            })}
            <hr className="my-1 border-0 border-t" style={{ borderColor: "var(--line)" }} />
            <Check label={t("ext.critical")} checked={value.ku_critical} onChange={(v) => set("ku_critical", v)} />
            {allowed && <span className="muted mt-1">{t("ext.kuAllowedFor", { algorithm: algorithm ?? "" })}</span>}
          </div>
        </Group>
        <Group title={t("ext.extKeyUsage")}>
          <div className="flex flex-col gap-1">
            {known.map((e) => (
              <Check
                key={e}
                label={t(`eku.${e}`)}
                checked={value.ext_key_usage.includes(e)}
                onChange={(on) => toggleEku(e, on)}
              />
            ))}
            <span className="mt-1">{t("ext.customOids")}</span>
            <LinesInput
              value={custom}
              rows={2}
              placeholder="1.3.6.1.5.5.7.3.x"
              onChange={(v) => set("ext_key_usage", [...value.ext_key_usage.filter((e) => known.includes(e)), ...v])}
            />
            <Check label={t("ext.critical")} checked={value.eku_critical} onChange={(v) => set("eku_critical", v)} />
          </div>
        </Group>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <Group title={t("ext.nameConstraints")}>
        {!value.ca && <p className="muted mb-2">{t("ext.ncOnlyCa")}</p>}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <span>{t("ext.ncPermitted")}</span>
            <LinesInput value={value.nc_permitted} onChange={(v) => set("nc_permitted", v)} rows={4} placeholder={".lab\n10.0.0.0/8\n@lab"} />
          </div>
          <div>
            <span>{t("ext.ncExcluded")}</span>
            <LinesInput value={value.nc_excluded} onChange={(v) => set("nc_excluded", v)} rows={4} placeholder="secret.lab" />
          </div>
        </div>
        <p className="muted mt-2">{t("ext.ncHint")}</p>
      </Group>
    </div>
  );
}
