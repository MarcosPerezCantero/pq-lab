import type { AlgorithmInfo } from "../api";
import type { KeyChoice } from "../helpers";
import { t } from "../i18n";
import { algorithmInfo, useLab } from "../store";

/**
 * Selects an existing key or a new one to generate on submit. Only keys whose
 * algorithm passes `accept` (and that have a private part, when `needPrivate`)
 * are offered, so invalid combinations cannot be chosen.
 */
export function KeyPicker({
  value,
  onChange,
  accept,
  needPrivate = true,
}: {
  value: KeyChoice;
  onChange: (v: KeyChoice) => void;
  accept: (a: AlgorithmInfo) => boolean;
  needPrivate?: boolean;
}) {
  const lab = useLab();
  const keys = lab.keys.filter((k) => {
    const info = algorithmInfo(lab, k.algorithm);
    return !!info && accept(info) && (!needPrivate || k.has_private);
  });
  const algs = lab.catalog.algorithms.filter(accept);
  const selectValue = value.kind === "existing" ? String(value.id ?? "") : `new:${value.algorithm}`;

  return (
    <select
      className="flex-1"
      value={selectValue}
      onChange={(e) => {
        const v = e.target.value;
        if (v.startsWith("new:")) onChange({ kind: "new", algorithm: v.slice(4) });
        else onChange({ kind: "existing", id: v ? Number(v) : null });
      }}
    >
      <option value="">{t("common.selectPlaceholder")}</option>
      {keys.length > 0 && (
        <optgroup label={t("keyPicker.existing")}>
          {keys.map((k) => (
            <option key={k.id} value={k.id}>
              {k.name} — {k.algorithm}
            </option>
          ))}
        </optgroup>
      )}
      <optgroup label={t("keyPicker.generate")}>
        {algs.map((a) => (
          <option key={a.id} value={`new:${a.id}`}>
            {t("keyPicker.new", { algorithm: a.id })}
          </option>
        ))}
      </optgroup>
    </select>
  );
}
