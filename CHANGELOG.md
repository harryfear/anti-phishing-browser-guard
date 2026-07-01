# Changelog

All notable changes to the extension are documented here. This project follows
semantic versioning.

## [0.2.0] — 2026-06-30

### Added

- **Toolbar status badge.** Red **!** when the extension is not protecting (no
  real policy loaded), amber **!** when the policy sync is failing or stale, and
  no badge when guarding normally. The options page shows the same status and a
  "Read more" link.
- **Strict-consent unlock for soft blocks.** When work credentials are entered on
  an unrecognised — but not outright malicious — site, the block can be cleared
  only by typing the site's domain to confirm you've checked the address. This
  unlocks credential entry for 30 seconds on that host. (**Unlock Anyway…** → type
  the domain → **Unlock for Now**.)
- **Draggable warning UI.** The warning banner and the minimised corner chip can
  be dragged out of the way; at least half stays on screen, and the position
  resets on reload so nothing is permanently covered.
- **Distinctive toolbar icon** (shield + eye).

### Changed

- **Insecure credential transport is now a hard block.** A password form that
  posts over HTTP can never be unlocked.
- **Weak "brand mentioned" warnings start minimised** as a corner chip instead of
  a full banner; click the chip to expand.
- **Trust-aware iframe handling.** A brand-mention-only signal coming from an
  embedded viewer (e.g. a document or media frame) under a trusted top-level page
  no longer escalates to a warning — removing a class of false positives.
- **Reworked warning dialog.** Cleaner two-button layout (**Report to Internal
  Security…** / **Unlock Anyway…**); reporting opens a focused sub-modal with an
  optional screenshot; "Learn More" is demoted to a link at the foot.

### Fixed

- The "company email on an unapproved site" check no longer fires on a protected
  address that merely *appears* in page content — e.g. an online document, email
  compose box, or chat that displays the address. Only short field entries (and
  real login `<input>`s) count as "entered", so a document that mentions your
  security inbox no longer shows a false warning.

### Security

- High-confidence phishing (deny-list, look-alike, punycode, brand +
  credential-harvest) and insecure transport remain **absolute blocks with no
  escape**. Only soft blocks — work credentials on an unrecognised host — can be
  unlocked, and only via the type-the-domain confirmation.

## [0.1.0]

### Added

- Initial release: allowlist-first phishing detection driven by a remote JSON
  policy, in-page warning/block UI, identity-reuse detection, look-alike/punycode
  and insecure-transport checks, and deny-list enforcement via Manifest V3
  `declarativeNetRequest`.
