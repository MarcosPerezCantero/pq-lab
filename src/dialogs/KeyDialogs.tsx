import { useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, type Family, type KeyRow } from "../api";
import { t } from "../i18n";
import { useLab } from "../store";
import { safeFileName, useAction } from "../helpers";
import { Dialog, DialogFooter, ErrorBox, Group, Note, PemInput, Row } from "../components/ui";

const FAMILIES: Family[] = ["MlDsa", "SlhDsa", "MlKem"];

export function NewKeyDialog({ onClose }: { onClose: () => void }) {
  const lab = useLab();
  const [name, setName] = useState("");
  const [algorithm, setAlgorithm] = useState("ML-DSA-65");
  const { busy, error, run } = useAction();

  async function submit() {
    const id = await run(() => api.generateKey(name, algorithm));
    if (id !== undefined) {
      await lab.refresh();
      lab.done();
      onClose();
    }
  }

  return (
    <Dialog title={t("dlg.newKey.title")} onClose={onClose} footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} />}>
      <Group title={t("dlg.newKey.group")}>
        <div className="form">
          <Row label={t("common.name")}>
            <input className="flex-1" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </Row>
          <Row label={t("common.algorithm")}>
            <select className="flex-1" value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
              {FAMILIES.map((f) => (
                <optgroup key={f} label={t(`family.${f}`)}>
                  {lab.catalog.algorithms
                    .filter((a) => a.family === f)
                    .map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.id}
                      </option>
                    ))}
                </optgroup>
              ))}
            </select>
          </Row>
        </div>
      </Group>
      {algorithm.startsWith("SLH-DSA") && <Note>{t("dlg.newKey.slhHint")}</Note>}
      {algorithm.startsWith("ML-KEM") && <Note>{t("dlg.newKey.kemHint")}</Note>}
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function ImportKeyDialog({ onClose }: { onClose: () => void }) {
  const lab = useLab();
  const [name, setName] = useState("");
  const [pem, setPem] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, setError, run } = useAction();
  const encrypted = pem.includes("ENCRYPTED");

  async function submit() {
    const id = await run(() => api.importKey(name, pem, encrypted ? password : null));
    if (id !== undefined) {
      await lab.refresh();
      lab.done();
      onClose();
    }
  }

  return (
    <Dialog title={t("dlg.importKey.title")} onClose={onClose} footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} submitLabel={t("common.import")} />}>
      <div className="form">
        <Row label={t("common.name")}>
          <input className="flex-1" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </Row>
      </div>
      <PemInput label={t("dlg.importKey.pem")} value={pem} onChange={setPem} onError={setError} />
      {encrypted && (
        <div className="form">
          <Row label={t("dlg.importKey.password")}>
            <input className="flex-1" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Row>
        </div>
      )}
      <Note>{t("dlg.importKey.hint")}</Note>
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function RenameKeyDialog({ keyRow, onClose }: { keyRow: KeyRow; onClose: () => void }) {
  const lab = useLab();
  const [name, setName] = useState(keyRow.name);
  const { busy, error, run } = useAction();

  async function submit() {
    const ok = await run(async () => {
      await api.renameKey(keyRow.id, name);
      return true;
    });
    if (ok) {
      await lab.refresh();
      onClose();
    }
  }

  return (
    <Dialog title={t("dlg.rename.title")} onClose={onClose} footer={<DialogFooter busy={busy} onCancel={onClose} onSubmit={submit} />}>
      <div className="form">
        <Row label={t("common.name")}>
          <input className="flex-1" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </Row>
      </div>
      <ErrorBox error={error} />
    </Dialog>
  );
}

export function ExportKeyDialog({ keyRow, onClose }: { keyRow: KeyRow; onClose: () => void }) {
  const lab = useLab();
  const [kind, setKind] = useState<"public" | "private">("public");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const { busy, error, run } = useAction();
  const isPrivate = kind === "private";

  async function submit() {
    const path = await save({ defaultPath: `${safeFileName(keyRow.name)}.${isPrivate ? "key" : "pub"}.pem` });
    if (!path) return;
    const ok = await run(async () => {
      if (isPrivate) await api.exportPrivateKey(keyRow.id, path, password);
      else await api.exportPublicKey(keyRow.id, path);
      return true;
    });
    if (ok) {
      lab.notify("ok", t("result.exported", { path }));
      onClose();
    }
  }

  return (
    <Dialog
      title={t("dlg.exportKey.title", { name: keyRow.name })}
      onClose={onClose}
      footer={
        <DialogFooter
          busy={busy}
          onCancel={onClose}
          onSubmit={submit}
          submitLabel={t("common.export")}
          disabled={isPrivate && (!password || password !== repeat)}
        />
      }
    >
      <Group title={t("dlg.exportKey.format")}>
        <div className="flex flex-col gap-1.5">
          <label className="check">
            <input type="radio" checked={!isPrivate} onChange={() => setKind("public")} />
            {t("dlg.exportKey.public")}
          </label>
          <label className={`check ${keyRow.has_private ? "" : "muted"}`}>
            <input type="radio" checked={isPrivate} disabled={!keyRow.has_private} onChange={() => setKind("private")} />
            {t("dlg.exportKey.private")}
          </label>
        </div>
      </Group>
      {isPrivate && (
        <Group title={t("dlg.exportKey.passwordGroup")}>
          <div className="form">
            <Row label={t("dlg.exportPrivate.password")}>
              <input className="flex-1" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
            </Row>
            <Row label={t("dlg.exportPrivate.repeat")}>
              <input className="flex-1" type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
            </Row>
          </div>
          {repeat && password !== repeat && <p className="danger mt-2">{t("unlock.mismatch")}</p>}
          <p className="muted mt-2">{t("dlg.exportPrivate.hint")}</p>
        </Group>
      )}
      <ErrorBox error={error} />
    </Dialog>
  );
}
