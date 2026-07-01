(function attachShared(global) {
  "use strict";

  // Brand-specific defaults are injected by the build (scripts/build-brand.mjs)
  // via a generated brand.js that sets globalThis.PhishGuardBrand. This file stays
  // brand/vendor agnostic: without PhishGuardBrand it falls back to inert generic
  // defaults so the repo can be public without revealing any organisation.
  const BRAND =
    (typeof globalThis !== "undefined" && globalThis.PhishGuardBrand) ||
    (typeof self !== "undefined" && self.PhishGuardBrand) ||
    (typeof window !== "undefined" && window.PhishGuardBrand) ||
    {};

  const DEFAULT_POLICY = Object.freeze(
    Object.assign(
      {
        version: 1,
        policyId: "local-default",
        updatedAt: "1970-01-01T00:00:00.000Z",
        refreshMinutes: 240,
        actions: {
          warnThreshold: 45,
          blockThreshold: 80,
          identityChallengeMinutes: 5
        },
        protectedDomains: [],
        protectedBrands: [],
        protectedEmailDomains: [],
        trustedHosts: [],
        trustedLoginHosts: [],
        denyHosts: [],
        reportEndpoint: "",
        reportEmail: "",
        infoUrl: "",
        approvedLoginUrl: "",
        approvedLoginLabel: "Open approved login",
        messages: {
          warnTitle: "Check this sign-in page",
          warnBody: "This page is asking for credentials but is not on a recognised sign-in list.",
          blockTitle: "Possible phishing page blocked",
          blockBody: "This page strongly resembles a protected sign-in page."
        }
      },
      BRAND
    )
  );

  const SKELETON_REPLACEMENTS = new Map([
    ["0", "o"],
    ["1", "l"],
    ["3", "e"],
    ["4", "a"],
    ["5", "s"],
    ["7", "t"],
    ["@", "a"],
    ["$", "s"]
  ]);

  const MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
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
    "com.sg"
  ]);

  const COMMON_PUBLIC_SUFFIXES = new Set([
    ...MULTI_LABEL_PUBLIC_SUFFIXES,
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

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function normalizePolicy(candidate) {
    const base = clone(DEFAULT_POLICY);
    if (!candidate || typeof candidate !== "object") return base;

    const merged = Object.assign(base, candidate);
    merged.actions = Object.assign(base.actions, candidate.actions || {});
    merged.messages = Object.assign(base.messages, candidate.messages || {});
    merged.infoUrl =
      typeof candidate.infoUrl === "string" && candidate.infoUrl.trim()
        ? candidate.infoUrl.trim()
        : base.infoUrl;
    merged.reportEmail =
      typeof candidate.reportEmail === "string" && candidate.reportEmail.trim()
        ? candidate.reportEmail.trim()
        : base.reportEmail;
    merged.approvedLoginUrl =
      typeof candidate.approvedLoginUrl === "string" && candidate.approvedLoginUrl.trim()
        ? candidate.approvedLoginUrl.trim()
        : base.approvedLoginUrl;
    merged.approvedLoginLabel =
      typeof candidate.approvedLoginLabel === "string" && candidate.approvedLoginLabel.trim()
        ? candidate.approvedLoginLabel.trim()
        : base.approvedLoginLabel;

    for (const key of [
      "protectedDomains",
      "protectedBrands",
      "protectedEmailDomains",
      "trustedHosts",
      "trustedLoginHosts",
      "denyHosts"
    ]) {
      merged[key] = Array.isArray(candidate[key]) ? candidate[key].filter(Boolean) : base[key];
    }

    return merged;
  }

  function normalizeHost(hostname) {
    return String(hostname || "")
      .trim()
      .toLowerCase()
      .replace(/\.$/, "");
  }

  function hostMatchesPattern(hostname, pattern) {
    const host = normalizeHost(hostname);
    const value = normalizeHost(pattern);
    if (!host || !value) return false;

    if (value.startsWith("*.")) {
      const base = value.slice(2);
      return host === base || host.endsWith(`.${base}`);
    }

    return host === value;
  }

  function hostInList(hostname, patterns) {
    return patterns.some((pattern) => hostMatchesPattern(hostname, pattern));
  }

  function exactHostPatterns(patterns) {
    return (patterns || []).filter((pattern) => !normalizeHost(pattern).startsWith("*."));
  }

  function isKnownPublicSuffix(hostname) {
    return COMMON_PUBLIC_SUFFIXES.has(normalizeHost(hostname));
  }

  function isUnsafeWildcardPattern(pattern) {
    const value = normalizeHost(pattern);
    if (!value.startsWith("*.")) return false;
    return isKnownPublicSuffix(value.slice(2));
  }

  function fullyTrustedHost(hostname, policy) {
    return hostInList(hostname, policy.protectedDomains) ||
      hostInList(hostname, exactHostPatterns(policy.trustedHosts)) ||
      hostInList(hostname, exactHostPatterns(policy.trustedLoginHosts));
  }

  function trustedContextHost(hostname, policy) {
    return hostInList(hostname, [...policy.trustedHosts, ...policy.trustedLoginHosts]);
  }

  function stripPortAndPath(value) {
    return String(value || "").replace(/^https?:\/\//i, "").split(/[/?#]/)[0].split(":")[0];
  }

  function hostFromUrl(url) {
    try {
      return normalizeHost(new URL(url).hostname);
    } catch (_) {
      return normalizeHost(stripPortAndPath(url));
    }
  }

  function siteKey(hostname) {
    const host = normalizeHost(hostname);
    const labels = host.split(".").filter(Boolean);
    if (labels.length <= 2) return host;

    const suffix = labels.slice(-2).join(".");
    if (MULTI_LABEL_PUBLIC_SUFFIXES.has(suffix) && labels.length >= 3) {
      return labels.slice(-3).join(".");
    }

    return labels.slice(-2).join(".");
  }

  function skeleton(value) {
    return String(value || "")
      .toLowerCase()
      .split("")
      .map((char) => SKELETON_REPLACEMENTS.get(char) || char)
      .join("")
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]/g, "");
  }

  function primaryLabel(domain) {
    return skeleton(String(domain || "").split(".")[0]);
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a) return b.length;
    if (!b) return a.length;

    const previous = Array.from({ length: b.length + 1 }, (_, index) => index);
    const current = Array(b.length + 1);

    for (let i = 1; i <= a.length; i += 1) {
      current[0] = i;
      for (let j = 1; j <= b.length; j += 1) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        current[j] = Math.min(
          current[j - 1] + 1,
          previous[j] + 1,
          previous[j - 1] + cost
        );
      }
      for (let j = 0; j <= b.length; j += 1) previous[j] = current[j];
    }

    return previous[b.length];
  }

  function labelsForHost(hostname) {
    return normalizeHost(hostname)
      .split(".")
      .map(skeleton)
      .filter((label) => label.length >= 4);
  }

  function looksLikeProtectedHost(hostname, policy) {
    const host = normalizeHost(hostname);
    const labels = labelsForHost(host);
    const protectedKeys = [
      ...policy.protectedDomains.map(primaryLabel),
      ...policy.protectedBrands.map(skeleton)
    ].filter((key) => key.length >= 4);

    for (const key of protectedKeys) {
      for (const label of labels) {
        if (label === key) return true;
        if (label.includes(key) || key.includes(label)) return true;
        if (Math.abs(label.length - key.length) <= 2 && levenshtein(label, key) <= 2) {
          return true;
        }
      }
    }

    return false;
  }

  function pageMentionsProtectedBrand(text, policy) {
    const haystack = String(text || "").toLowerCase();
    return policy.protectedBrands.some((brand) => {
      const needle = String(brand || "").trim().toLowerCase();
      return needle.length >= 4 && haystack.includes(needle);
    });
  }

  function emailsFromValue(value) {
    return (
      String(value || "")
        .toLowerCase()
        .match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/g) || []
    );
  }

  function protectedIdentityEntered(values, policy) {
    return values.some((value) => {
      return emailsFromValue(value).some((email) => {
        return policy.protectedEmailDomains.some((domain) => email.endsWith(`@${domain}`));
      });
    });
  }

  function evaluatePage(rawPolicy, page) {
    const policy = normalizePolicy(rawPolicy);
    const host = normalizeHost(page.hostname || hostFromUrl(page.url));
    const fullyTrusted = fullyTrustedHost(host, policy);
    const trustedContext = trustedContextHost(host, policy);
    const denied = hostInList(host, policy.denyHosts);
    const protectedDomain = hostInList(host, policy.protectedDomains);
    const hasPassword = Boolean(page.hasPassword);
    const recentProtectedIdentity = Boolean(page.recentProtectedIdentity);
    const hasPunycode = host.includes("xn--");
    const lookalike = !trustedContext && !protectedDomain && looksLikeProtectedHost(host, policy);
    const brandMention = !trustedContext && pageMentionsProtectedBrand(page.text, policy);
    const formActionOffsite = (page.formActionHosts || []).some((actionHost) => {
      if (!actionHost || actionHost === host) return false;
      return !fullyTrustedHost(actionHost, policy);
    });
    const insecureFormAction = (page.formActions || []).some((action) => {
      const protocol = String(action.protocol || "").toLowerCase();
      return protocol === "http:" || action.secure === false;
    });
    const enteredProtectedIdentity = protectedIdentityEntered(page.enteredValues || [], policy);

    const signals = [];
    let score = 0;

    if (fullyTrusted) {
      return { action: "allow", score: 0, signals: ["trusted-host"], policy };
    }

    if (denied) {
      score += 100;
      signals.push("deny-host");
    }

    if (hasPunycode) {
      score += 45;
      signals.push("punycode-host");
    }

    if (lookalike) {
      score += 55;
      signals.push("protected-lookalike-host");
    }

    if (brandMention) {
      score += 45;
      signals.push("protected-brand-on-untrusted-host");
    }

    if (hasPassword) {
      score += 10;
      signals.push("password-field-on-untrusted-host");
    }

    if (hasPassword && (lookalike || brandMention)) {
      score += 35;
      signals.push("credential-harvest-risk");
    }

    if (formActionOffsite && hasPassword && (lookalike || brandMention)) {
      score += 25;
      signals.push("password-form-posts-offsite");
    } else if (formActionOffsite && hasPassword) {
      score += 10;
      signals.push("password-form-posts-offsite");
    }

    if (insecureFormAction && hasPassword) {
      score += 55;
      signals.push("password-form-targets-http");
    }

    if (enteredProtectedIdentity) {
      score += 50;
      signals.push("protected-email-on-untrusted-host");
    }

    if (enteredProtectedIdentity && hasPassword) {
      score += 20;
      signals.push("protected-email-password-on-untrusted-host");
    }

    if (hasPassword && recentProtectedIdentity) {
      score += 70;
      signals.push("recent-protected-email-then-password");
    }

    const warnThreshold = Number(policy.actions.warnThreshold || DEFAULT_POLICY.actions.warnThreshold);
    const blockThreshold = Number(policy.actions.blockThreshold || DEFAULT_POLICY.actions.blockThreshold);
    let action = score >= blockThreshold ? "block" : score >= warnThreshold ? "warn" : "allow";
    // Insecure credential transport (a password form posting over HTTP) is always a
    // hard block — there is no safe way to send a password in plaintext.
    if (signals.includes("password-form-targets-http")) action = "block";

    return { action, score, signals, policy };
  }

  global.PhishGuard = {
    DEFAULT_POLICY,
    clone,
    evaluatePage,
    fullyTrustedHost,
    trustedContextHost,
    protectedIdentityEntered,
    hostFromUrl,
    hostInList,
    hostMatchesPattern,
    isKnownPublicSuffix,
    isUnsafeWildcardPattern,
    normalizeHost,
    normalizePolicy,
    siteKey
  };
})(typeof globalThis !== "undefined" ? globalThis : window);
