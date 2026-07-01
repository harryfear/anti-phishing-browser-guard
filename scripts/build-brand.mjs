#!/usr/bin/env node
// Generates brand-specific artifacts from a brand config so the repo itself
// stays brand/vendor agnostic. Reads config/brand.yml (gitignored) when present,
// otherwise config/brand.example.yml. Zero dependencies: a minimal YAML subset
// parser is included below (maps, lists of scalars, nested maps, quoted/unquoted
// scalars, `[]`, `#` comments — which is all the config needs).
//
// Outputs (all gitignored):
//   extension/brand.js        global PhishGuardBrand default policy, loaded before shared.js
//   extension/manifest.json   from manifest.template.json with name/description injected
//   policy/policy.json        the subscription policy to host privately

import { readFile, writeFile, access, mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const p = (...parts) => resolve(root, ...parts);

// Write a file, creating its parent directory first. The generated outputs
// (policy/policy.json, extension/*) are gitignored, so their directory may not
// exist in a fresh checkout — create it rather than failing with ENOENT.
async function writeOut(file, contents) {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, contents);
}

async function exists(file) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Minimal YAML subset parser
// ---------------------------------------------------------------------------
function stripComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === "#" && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseScalar(value) {
  const v = value.trim();
  if (v === "" || v === "[]") return v === "[]" ? [] : "";
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^-?\d+$/.test(v)) return Number.parseInt(v, 10);
  if (/^-?\d+\.\d+$/.test(v)) return Number.parseFloat(v);
  return v;
}

function parseYaml(src) {
  const lines = src
    .split(/\r?\n/)
    .map((l) => stripComment(l.replace(/\t/g, "  ")))
    .filter((l) => l.trim() !== "");
  let pos = 0;
  const indentOf = (l) => l.length - l.trimStart().length;

  function parseBlock(indent) {
    if (pos >= lines.length) return {};
    return lines[pos].trimStart().startsWith("- ") ? parseList(indent) : parseMap(indent);
  }
  function parseList(indent) {
    const arr = [];
    while (pos < lines.length) {
      const l = lines[pos];
      if (indentOf(l) !== indent || !l.trimStart().startsWith("- ")) break;
      arr.push(parseScalar(l.trimStart().slice(2)));
      pos += 1;
    }
    return arr;
  }
  function parseMap(indent) {
    const obj = {};
    while (pos < lines.length) {
      const l = lines[pos];
      if (indentOf(l) !== indent) break;
      const content = l.trim();
      const ci = content.indexOf(":");
      if (ci === -1) break;
      const key = content.slice(0, ci).trim();
      const rest = content.slice(ci + 1).trim();
      pos += 1;
      if (rest === "") {
        const childIndent = pos < lines.length ? indentOf(lines[pos]) : indent;
        obj[key] = childIndent > indent ? parseBlock(childIndent) : {};
      } else {
        obj[key] = parseScalar(rest);
      }
    }
    return obj;
  }

  return parseMap(indentOf(lines[0] || ""));
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------
function buildPolicy(cfg) {
  const policy = cfg.policy || {};
  const t = policy.thresholds || {};
  const m = policy.messages || {};
  const list = (v) => (Array.isArray(v) ? v : []);
  return {
    version: Number.isInteger(policy.version) ? policy.version : 1,
    policyId: policy.policyId || "org-default",
    updatedAt: new Date().toISOString(),
    refreshMinutes: Number.isInteger(policy.refreshMinutes) ? policy.refreshMinutes : 240,
    actions: {
      warnThreshold: Number.isInteger(t.warn) ? t.warn : 45,
      blockThreshold: Number.isInteger(t.block) ? t.block : 80,
      identityChallengeMinutes: Number.isInteger(t.identityChallengeMinutes) ? t.identityChallengeMinutes : 5
    },
    protectedDomains: list(policy.protectedDomains),
    protectedBrands: list(policy.protectedBrands),
    protectedEmailDomains: list(policy.protectedEmailDomains),
    trustedHosts: list(policy.trustedHosts),
    trustedLoginHosts: list(policy.trustedLoginHosts),
    denyHosts: list(policy.denyHosts),
    reportEndpoint: policy.reportEndpoint || "",
    reportEmail: policy.reportEmail || "",
    infoUrl: policy.infoUrl || "",
    approvedLoginUrl: policy.approvedLoginUrl || "",
    approvedLoginLabel: policy.approvedLoginLabel || "Open approved login",
    messages: {
      warnTitle: m.warnTitle || "Check this sign-in page",
      warnBody: m.warnBody || "This page is asking for credentials but is not on the approved sign-in list.",
      blockTitle: m.blockTitle || "Possible phishing page blocked",
      blockBody: m.blockBody || "This page strongly resembles a protected sign-in page."
    }
  };
}

async function main() {
  const realConfig = p("config/brand.yml");
  const exampleConfig = p("config/brand.example.yml");
  const useReal = (await exists(realConfig)) && (await readFile(realConfig, "utf8")).trim() !== "";
  const configPath = useReal ? realConfig : exampleConfig;
  const cfg = parseYaml(await readFile(configPath, "utf8"));

  const policy = buildPolicy(cfg);

  // policy/policy.json — host this privately.
  await writeOut(p("policy/policy.json"), JSON.stringify(policy, null, 2) + "\n");

  // extension/brand.js — baked-in default policy (PhishGuardBrand), loaded before shared.js.
  const brandJs =
    "// GENERATED by scripts/build-brand.mjs — do not edit. Source: config/brand.yml\n" +
    "(function (g) {\n" +
    "  g.PhishGuardBrand = " +
    JSON.stringify(policy, null, 2).replace(/\n/g, "\n  ") +
    ";\n" +
    "})(typeof globalThis !== \"undefined\" ? globalThis : self);\n";
  await writeOut(p("extension/brand.js"), brandJs);

  // extension/manifest.json — name/description injected.
  const tpl = JSON.parse(await readFile(p("extension/manifest.template.json"), "utf8"));
  const ext = cfg.extension || {};
  tpl.name = ext.name || "Anti-Phishing Guard";
  tpl.description = ext.description || "Allowlist-first phishing guard with remote JSON policy updates.";
  if (tpl.action) tpl.action.default_title = tpl.name;
  await writeOut(p("extension/manifest.json"), JSON.stringify(tpl, null, 2) + "\n");

  const source = useReal ? "config/brand.yml" : "config/brand.example.yml (generic fallback)";
  console.log(`Brand build OK from ${source}: "${tpl.name}", policy ${policy.policyId} v${policy.version}`);
}

main().catch((error) => {
  console.error("Brand build failed:", error.message);
  process.exit(1);
});
