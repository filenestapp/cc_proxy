import en from "./locales/en.mjs";
import zhHans from "./locales/zh-Hans.mjs";

export const messages = { en, "zh-Hans": zhHans };

export function resolveLanguage(preference, systemLanguages) {
  if (preference === "en" || preference === "zh-Hans") return preference;

  for (const locale of systemLanguages) {
    const language = (locale || "").toLowerCase().split(/[-_]/, 1)[0];
    if (language === "zh") return "zh-Hans";
    if (language === "en") return "en";
  }
  return "en";
}
