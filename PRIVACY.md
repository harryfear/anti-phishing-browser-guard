# Privacy Policy — Anti-Phishing Guard

_Last updated: 27 June 2026_

Anti-Phishing Guard is a browser extension that detects and warns about
credential-phishing pages. This policy explains how it handles data.

## Summary

All phishing detection runs **locally in your browser**. The extension does not
sell or share your data with third parties, and does not use your data for
advertising, creditworthiness, lending, or any purpose other than phishing
protection.

## What the extension accesses

To detect phishing, the content script reads the content and form structure of
pages you visit — page text, the presence of password fields, and whether a work
email address is typed. This processing happens entirely **on your device**, in
real time, solely to decide whether to show a warning.

## What is stored

Stored in the browser only:

- the protection policy and the URL it is fetched from;
- the last sync time and any sync error;
- short-lived markers noting that a work email was recently entered (used to
  detect an email-then-password sequence), which expire automatically.

No browsing history, page content, or credentials are stored.

## What is (optionally) transmitted

By default the extension transmits **no user data**. An organisation deploying it
may optionally enable incident reporting. If enabled:

- **Report to security** prepares an email that you review and send yourself,
  and/or sends limited incident metadata — the flagged page's hostname, title,
  and the detection reasons — to **your own organisation's** security inbox or
  endpoint. This is first-party reporting to your employer, not a third party.
- **Download a screenshot** saves an image of the flagged page to your device so
  you can attach it to a report. The image is not uploaded by the extension.

The extension **never captures or transmits passwords**.

## Network

The extension periodically fetches its protection policy (a JSON configuration
file) from a URL set by you or your administrator. This request sends no user
data; it only retrieves the configuration.

## Contact

Questions: open an issue at
https://github.com/harryfear/anti-phishing-browser-guard/issues
