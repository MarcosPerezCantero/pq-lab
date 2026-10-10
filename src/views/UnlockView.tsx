import { useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, type Status } from "../api";
import { t } from "../i18n";
import { useAction } from "../helpers";
import { ErrorBox, Group, Note, Row } from "../components/ui";

export function UnlockView({ status, onUnlocked }: { status: Status; onUnlocked: () => void }) {
  const [mode, setMode] = useState<"open" | "create">(status.default_db_exists ? "open" : "create");
  const [path, setPath] = useState(status.db_path ?? status.default_db_path);
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const { busy, error, run } = useAction();
  const mismatch = mode === "create" && repeat.length > 0 && password !== repeat;

  async function browse() {
    const chosen =
      mode === "open"
        ? await open({ multiple: false, directory: false, filters: [{ name: "PQ Lab", extensions: ["db"] }] })
        : await save({ defaultPath: "pqlab.db", filters: [{ name: "PQ Lab", extensions: ["db"] }] });
    if (typeof chosen === "string") setPath(chosen);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (mode === "create" && password !== repeat) return;
    const ok = await run(async () => {
      if (mode === "open") await api.openDatabase(path, password);
      else await api.createDatabase(path, password);
      return true;
    });
    setPassword("");
    setRepeat("");
    if (ok) onUnlocked();
  }

  return (
    <div className="flex h-full items-center justify-center p-6">
      <form onSubmit={submit} className="dialog" style={{ width: 520 }}>
        <header>{t("unlock.title")}</header>
        <div className="body">
          <p>
            <strong>{t("app.name")}</strong> — {t("app.tagline")}
          </p>
          <Note warn>{t("app.labOnly")}</Note>
          <Group title={t("unlock.database")}>
            <div className="form">
              <Row label="">
                <label className="check">
                  <input type="radio" checked={mode === "open"} onChange={() => setMode("open")} />
                  {t("unlock.modeOpen")}
                </label>
                <label className="check">
                  <input type="radio" checked={mode === "create"} onChange={() => setMode("create")} />
                  {t("unlock.modeCreate")}
                </label>
              </Row>
              <Row label={t("unlock.path")}>
                <input className="mono flex-1" value={path} onChange={(e) => setPath(e.target.value)} />
                <button type="button" onClick={browse}>
                  {t("common.browse")}
                </button>
              </Row>
              <Row label={t("unlock.password")}>
                <input className="flex-1" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
              </Row>
              {mode === "create" && (
                <Row label={t("unlock.passwordRepeat")}>
                  <input className="flex-1" type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
                </Row>
              )}
            </div>
            {mode === "create" && <p className="muted mt-2">{t("unlock.hint")}</p>}
            {mismatch && <p className="danger mt-2">{t("unlock.mismatch")}</p>}
          </Group>
          <ErrorBox error={error} />
        </div>
        <footer>
          <span className="muted mr-auto">{status.openssl_version}</span>
          {busy && <span className="muted">{t("common.working")}</span>}
          <button type="submit" disabled={busy || !password || mismatch}>
            {mode === "open" ? t("unlock.open") : t("unlock.create")}
          </button>
        </footer>
      </form>
    </div>
  );
}
