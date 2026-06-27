#!/usr/bin/env node
import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const extensionDir = resolve(process.argv[2] || "extension");
const manifestPath = resolve(extensionDir, "manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const errors = [];

if (manifest.manifest_version !== 3) errors.push("manifest_version must be 3");
if (!manifest.name) errors.push("manifest.name is required");
if (!manifest.version) errors.push("manifest.version is required");
if (!manifest.background?.service_worker) errors.push("background.service_worker is required");

for (const file of [
  manifest.background?.service_worker,
  manifest.storage?.managed_schema,
  ...(manifest.content_scripts || []).flatMap((script) => script.js || []),
  manifest.options_page
].filter(Boolean)) {
  try {
    await access(resolve(extensionDir, file));
  } catch (_) {
    errors.push(`Referenced file is missing: ${file}`);
  }
}

if (errors.length) {
  console.error("Extension check failed");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Extension OK: ${manifest.name} v${manifest.version}`);
