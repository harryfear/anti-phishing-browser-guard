# Anti-Phishing Guard

Minimal Chrome/WebExtension anti-phishing guard with a remote JSON subscription policy.

The repo is **brand/vendor agnostic**: all organisation-specific values (brand names, protected domains, email domains, trusted hosts, report inbox, info URL, thresholds, copy) live in a single config file that is **not committed**. A small build reads that config and generates the brand-specific artifacts, so the public repo never reveals whose tool it is.

Two deployable parts:

- `extension/` — a no-bundler Manifest V3 browser extension.
- `policy/policy.json` — the remote subscription policy you host privately and the extension syncs.

## Brand Configuration

All brand-specific data lives in `config/brand.yml`.

1. Copy the template and fill in your values:

   ```sh
   cp config/brand.example.yml config/brand.yml
   # edit config/brand.yml
   node scripts/build-brand.mjs
   ```

2. `build-brand.mjs` generates (all **gitignored**):

   | Generated file            | Purpose                                                        |
   | ------------------------- | -------------------------------------------------------------- |
   | `extension/brand.js`      | Baked-in default policy (`globalThis.PhishGuardBrand`), loaded first.  |
   | `extension/manifest.json` | From `manifest.template.json`, with name/description injected. |
   | `policy/policy.json`      | The subscription policy to host privately.                     |

If `config/brand.yml` is absent, the build falls back to `config/brand.example.yml` and produces a harmless **generic** build (this is what CI does on a public PR).

The committed code (`shared.js` etc.) contains only inert generic defaults; the brand only materialises after the build runs.

## Repo Layout

```text
config/
  brand.example.yml   Generic template (committed)
  brand.yml           Real org config (gitignored)
extension/
  manifest.template.json  MV3 manifest template (committed)
  manifest.json           Generated (gitignored)
  brand.js                Generated default policy (gitignored)
  shared.js               Detection/scoring engine (brand-agnostic)
  background.js           Policy sync, deny-list DNR, reporting, screenshot capture
  content.js              Page inspection, banner, modal, form guard
  options.*               Policy URL/status UI
policy/
  policy.example.json  Example/template subscription policy (committed)
  policy.json          Generated subscription policy (gitignored) — host privately
schema/
  policy.schema.json  JSON Schema for the policy
scripts/
  build-brand.mjs     Generates brand artifacts from config (zero-dependency)
  validate-policy.mjs  Policy validation (local + CI)
  check-extension.mjs  Extension package sanity check
.github/workflows/
  validate.yml              PR/push checks (generic build)
  package-extension.yml     Builds the extension ZIP (brand via CI secret)
```

## Build & Load Locally

```sh
node scripts/build-brand.mjs              # generates manifest.json, brand.js, policy.json
node scripts/validate-policy.mjs policy/policy.json
node scripts/check-extension.mjs extension
```

Load in Chrome:

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` directory.
4. (Optional) Open the extension options and set the policy URL.

> The extension works out of the box from the baked-in `brand.js` default policy. The remote policy is only needed for live updates.

## Hosting The Policy (privately)

The policy is intentionally **not** published from this repo (there is no public Pages workflow). See `policy/policy.example.json` for the exact JSON shape (you can copy it as a starting template, or generate your own with the build). Host it somewhere your fleet can reach but the public cannot — e.g. an authenticated endpoint, a private bucket, or a separate private repo's Pages. Then either:

- paste the URL into the extension options page, or
- for managed deployment, set it via Chrome managed storage key `policyUrl` (users then cannot edit it).

To change brand data, edit `config/brand.yml`, bump `policy.version`, re-run the build, and re-publish `policy.json` (and/or re-release the extension to refresh the baked-in default).

The policy validator rejects: URL-shaped host entries, invalid wildcards, public-suffix entries (`co.uk`) and public-suffix wildcards (`*.co.uk`), wildcards in `trustedLoginHosts`, `approvedLoginUrl` hosts outside the known trusted set, duplicates, `warn >= block` thresholds, and direct Slack/Discord webhook URLs.

## Releasing The Extension

Tag `v*` or run **Package Extension** manually. The workflow builds with the `BRAND_CONFIG_YML` repo secret if set (otherwise a generic build), validates, and uploads the `anti-phishing-extension` artifact. Upload that ZIP to the Chrome Web Store or distribute internally.

For Safari, use the `extension/` directory as the source for Apple's Safari Web Extension conversion (run the brand build first).

## Security Model

The extension is allowlist-first for sign-in protection:

- Exact protected domains and exact trusted login hosts are fully allowed.
- Wildcard trusted hosts and broad third-party platform hosts are scan-through context: they suppress brand/lookalike noise but do not bypass credential, identity, insecure-transport, or deny-list checks.
- Unknown password pages alone are only a weak signal.
- A protected email plus a password field on a non-fully-trusted host is block-level friction by default.
- If a protected email was entered, any password field in the same tab during the next `identityChallengeMinutes` window is challenged again.
- HTTPS pages with password forms targeting HTTP endpoints are warned as insecure credential transport.
- Lookalike domains, protected-brand pages on untrusted hosts, punycode hosts, and suspicious form actions raise the score.
- Content scripts run in all frames; child frames report findings to the top frame so only one warning UI renders.
- Deny-listed hosts are also enforced with Manifest V3 dynamic `declarativeNetRequest` block rules.
- The toolbar icon shows a guard-state badge: red **!** when **not protecting** (no real policy loaded — e.g. a generic build that has not been provisioned), amber **!** when protecting but the policy sync is failing or stale, and no badge when guarding normally. A placeholder `policyId` (`org-default`/`local-default`) with no successful sync counts as unconfigured, so a generic build distributed via the Web Store reads as "not protecting" until a real policy is provisioned (paste a policy URL, or push `policyUrl` via managed storage). The same state is shown as a banner on the options page.
- Severity colour is consistent across surfaces: amber for warn, red for block, on banner, chip, and modal.
- The modal's primary action is **Report to Internal Security** (copies a diagnostic blob to the clipboard and opens a prefilled `mailto:` to `reportEmail`); **Learn More** opens `infoUrl`; **Download a screenshot to attach** captures the page via the background `captureVisibleTab`.
- The password-escape footer is only shown when the page actually involves a credential context; email-only/brand-only warnings get an informational modal.
- On **warn** with a credential context, proceeding requires friction: an acknowledgement checkbox plus a countdown before **Enter password anyway** enables. On **block** there is no proceed action.
- The modal traps focus, autofocuses the primary action, restores focus on close, and **Esc** collapses it to a persistent chip. There is no "approved login" destination — the extension blocks/warns only.

Remote policy is JSON data only; it must not contain executable logic, and is treated as untrusted input at runtime (thresholds clamped, public-suffix wildcards rejected, version rollback rejected, remote reporting cannot be newly enabled by policy alone, `reportEmail` constrained to a single clean address).

`Enter password anyway` does not auto-submit; it dismisses the challenge so the user must submit again deliberately. This is not a complete DLP layer — a page the user continues on can still exfiltrate via JS/AJAX/beacons. Treat the pre-entry challenge as the main control.

For production hardening, add detached policy signing with a public key embedded in the extension. OAuth consent phishing against the genuine IdP is out of scope for this page-level guard.

## Making The Repo Public

`config/brand.yml` and the generated `extension/brand.js`, `extension/manifest.json`, and `policy/policy.json` are gitignored, so new commits stay generic. Two things to do before publishing:

- **Untrack the now-generated files** that were previously committed:
  ```sh
  git rm --cached extension/manifest.json policy/policy.json
  ```
- **Scrub git history** — earlier commits still contain the brand values (in `shared.js`, `policy.json`, etc.). Use `git filter-repo` (or start a fresh history) before making the repo public.
