#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const policyPath = resolve(process.argv[2] || "policy/policy.json");
const policy = JSON.parse(await readFile(policyPath, "utf8"));
const errors = [];
const PUBLIC_SUFFIXES = new Set([
  "ac.uk",
  "co.uk",
  "gov.uk",
  "ltd.uk",
  "me.uk",
  "net.uk",
  "org.uk",
  "plc.uk",
  "com.au",
  "net.au",
  "org.au",
  "gov.au",
  "co.nz",
  "com.br",
  "com.mx",
  "co.jp",
  "co.in",
  "com.sg",
  "com",
  "edu",
  "gov",
  "info",
  "mil",
  "net",
  "org",
  "uk",
  "us"
]);

requireObject(policy, "policy");
requireInteger(policy.version, "version", 1);
requireString(policy.policyId, "policyId");
requireDate(policy.updatedAt, "updatedAt");
requireInteger(policy.refreshMinutes, "refreshMinutes", 15, 1440);
requireObject(policy.actions, "actions");
requireInteger(policy.actions?.warnThreshold, "actions.warnThreshold", 1, 100);
requireInteger(policy.actions?.blockThreshold, "actions.blockThreshold", 1, 100);
requireInteger(policy.actions?.identityChallengeMinutes, "actions.identityChallengeMinutes", 1, 60);

if (Number(policy.actions?.warnThreshold) >= Number(policy.actions?.blockThreshold)) {
  errors.push("actions.warnThreshold must be lower than actions.blockThreshold");
}

requireHostList(policy.protectedDomains, "protectedDomains", { wildcard: false, min: 1 });
requireStringList(policy.protectedBrands, "protectedBrands", { min: 1 });
requireHostList(policy.protectedEmailDomains, "protectedEmailDomains", { wildcard: false, min: 1 });
requireHostList(policy.trustedHosts, "trustedHosts", { wildcard: true, min: 1 });
requireHostList(policy.trustedLoginHosts, "trustedLoginHosts", { wildcard: false, min: 1 });
requireHostList(policy.denyHosts, "denyHosts", { wildcard: true, min: 0 });
requireString(policy.reportEndpoint, "reportEndpoint", { allowEmpty: true });
validateReportEndpoint(policy.reportEndpoint);
requireString(policy.infoUrl, "infoUrl", { allowEmpty: true });
validateInfoUrl(policy.infoUrl);
if (policy.approvedLoginUrl !== undefined) {
  requireString(policy.approvedLoginUrl, "approvedLoginUrl", { allowEmpty: true });
  validateApprovedLoginUrl(policy.approvedLoginUrl);
}
if (policy.approvedLoginLabel !== undefined) {
  requireString(policy.approvedLoginLabel, "approvedLoginLabel", { allowEmpty: true });
}
if (policy.reportEmail !== undefined) {
  requireString(policy.reportEmail, "reportEmail", { allowEmpty: true });
  if (policy.reportEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(policy.reportEmail)) {
    errors.push("reportEmail must be a valid email address");
  }
}

requireObject(policy.messages, "messages");
for (const key of ["warnTitle", "warnBody", "blockTitle", "blockBody"]) {
  requireString(policy.messages?.[key], `messages.${key}`);
}

for (const host of policy.protectedDomains || []) {
  if (!hostListIncludes(policy.trustedHosts || [], host)) {
    errors.push(`trustedHosts should include protected domain "${host}"`);
  }
}

if (errors.length) {
  console.error(`Policy validation failed for ${policyPath}`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Policy OK: ${policy.policyId} v${policy.version}`);

function requireObject(value, path) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    errors.push(`${path} must be an object`);
  }
}

function requireString(value, path, options = {}) {
  if (typeof value !== "string") {
    errors.push(`${path} must be a string`);
    return;
  }
  if (!options.allowEmpty && value.trim().length === 0) {
    errors.push(`${path} must not be empty`);
  }
}

function requireStringList(value, path, options = {}) {
  if (!Array.isArray(value)) {
    errors.push(`${path} must be an array`);
    return;
  }
  if (value.length < (options.min || 0)) {
    errors.push(`${path} must contain at least ${options.min} item(s)`);
  }
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== "string" || !item.trim()) errors.push(`${path} contains a non-string value`);
    const key = String(item).toLowerCase();
    if (seen.has(key)) errors.push(`${path} contains duplicate value "${item}"`);
    seen.add(key);
  }
}

function requireInteger(value, path, min = undefined, max = undefined) {
  if (!Number.isInteger(value)) {
    errors.push(`${path} must be an integer`);
    return;
  }
  if (min !== undefined && value < min) errors.push(`${path} must be >= ${min}`);
  if (max !== undefined && value > max) errors.push(`${path} must be <= ${max}`);
}

function requireDate(value, path) {
  requireString(value, path);
  if (typeof value === "string" && Number.isNaN(Date.parse(value))) {
    errors.push(`${path} must be a valid ISO date-time`);
  }
}

function requireHostList(value, path, options) {
  requireStringList(value, path, options);
  if (!Array.isArray(value)) return;

  const pattern = options.wildcard
    ? /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i
    : /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;

  for (const host of value) {
    if (typeof host !== "string") continue;
    if (host.includes("://") || host.includes("/") || host.includes(":")) {
      errors.push(`${path} entry "${host}" must be a hostname only, not a URL`);
    }
    if (!pattern.test(host)) {
      errors.push(`${path} entry "${host}" is not a valid hostname pattern`);
    }
    if (!options.wildcard && host.includes("*")) {
      errors.push(`${path} entry "${host}" must not contain wildcards`);
    }
    const normalized = host.toLowerCase().replace(/^\*\./, "");
    if (isKnownPublicSuffix(normalized)) {
      errors.push(`${path} entry "${host}" must not be a public suffix`);
    }
    if (host.startsWith("*.") && isKnownPublicSuffix(normalized)) {
      errors.push(`${path} entry "${host}" must not wildcard an entire public suffix`);
    }
  }
}

function validateReportEndpoint(value) {
  if (!value) return;
  let url;
  try {
    url = new URL(value);
  } catch (_) {
    errors.push("reportEndpoint must be blank or a valid HTTPS URL");
    return;
  }
  if (url.protocol !== "https:") errors.push("reportEndpoint must use HTTPS");
  const forbiddenHosts = ["hooks.slack.com", "discord.com", "discordapp.com"];
  if (forbiddenHosts.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`))) {
    errors.push("reportEndpoint must point to your backend, not a public chat webhook containing a secret");
  }
}

function validateInfoUrl(value) {
  validateHttpsUrl(value, "infoUrl");
}

function validateApprovedLoginUrl(value) {
  validateHttpsUrl(value, "approvedLoginUrl");
  if (!value) return;

  let url;
  try {
    url = new URL(value);
  } catch (_) {
    return;
  }

  const allowedHosts = [
    ...(policy.protectedDomains || []),
    ...(policy.trustedLoginHosts || []),
    ...(policy.trustedHosts || []).filter((host) => !String(host).startsWith("*."))
  ];

  if (!hostListIncludes(allowedHosts, url.hostname)) {
    errors.push("approvedLoginUrl host must be a protected domain or exact trusted login host");
  }
}

function validateHttpsUrl(value, path) {
  if (!value) return;
  let url;
  try {
    url = new URL(value);
  } catch (_) {
    errors.push(`${path} must be blank or a valid HTTPS URL`);
    return;
  }
  if (url.protocol !== "https:") errors.push(`${path} must use HTTPS`);
}

function hostListIncludes(patterns, hostname) {
  return patterns.some((pattern) => pattern === hostname || pattern === `*.${hostname}`);
}

function isKnownPublicSuffix(hostname) {
  return PUBLIC_SUFFIXES.has(String(hostname || "").toLowerCase());
}
