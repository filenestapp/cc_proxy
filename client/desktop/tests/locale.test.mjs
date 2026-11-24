import assert from "node:assert/strict";
import test from "node:test";
import { messages, resolveLanguage } from "../ui/locale.mjs";

test("system mode uses the first supported preferred language", () => {
  assert.equal(resolveLanguage("system", ["zh-CN", "en-US"]), "zh-Hans");
  assert.equal(resolveLanguage("system", ["en-GB", "zh-Hans"]), "en");
  assert.equal(resolveLanguage("system", ["ja", "zh-Hant-TW", "en"]), "zh-Hans");
  assert.equal(resolveLanguage("system", ["zh_CN"]), "zh-Hans");
});

test("system mode falls back to English when no preference is supported", () => {
  assert.equal(resolveLanguage("system", ["ja", "es"]), "en");
  assert.equal(resolveLanguage("system", []), "en");
});

test("an explicit language overrides the system setting", () => {
  assert.equal(resolveLanguage("en", ["zh-CN"]), "en");
  assert.equal(resolveLanguage("zh-Hans", ["en-US"]), "zh-Hans");
});

test("both translation bundles provide the same nonempty messages", () => {
  assert.deepEqual(Object.keys(messages["zh-Hans"]).sort(), Object.keys(messages.en).sort());
  for (const [language, bundle] of Object.entries(messages)) {
    for (const [key, value] of Object.entries(bundle)) {
      assert.ok(value.trim(), `${language} is missing ${key}`);
    }
  }
});
