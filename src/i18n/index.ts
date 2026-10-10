// Minimal i18n: flat JSON catalogues with {param} interpolation.
// Only Spanish ships in the MVP; add en.json and register it here to translate.
import es from "./es.json";

type Catalogue = Record<string, string>;

const catalogues: Record<string, Catalogue> = { es };
const current: Catalogue = catalogues.es;

export function t(key: string, params?: Record<string, string | number>): string {
  const template = current[key] ?? key;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (_, k: string) => (k in params ? String(params[k]) : `{${k}}`));
}

export function hasKey(key: string): boolean {
  return key in current;
}
