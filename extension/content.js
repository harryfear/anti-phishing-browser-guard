(async function runContentScript() {
  "use strict";

  const ROOT_ID = "anti-phishing-guard-root";
  const IS_TOP_FRAME = window.top === window;
  let policy = PhishGuard.DEFAULT_POLICY;
  let lastEvaluation = null;
  let bypassNextSubmit = false;
  let recentProtectedIdentity = false;
  let credentialEntryAllowedUntil = 0;
  let warningHost = null;
  let warningRoot = null;
  let warningHostObserver = null;
  let uiMode = "none"; // none | banner | chip | modal
  let renderedAction = null;

  policy = await loadPolicy();
  recentProtectedIdentity = await loadRecentIdentityHint();
  evaluateAndRender();
  bindSubmitGuard();
  bindInputRecheck();
  bindDomRecheck();
  bindFrameEvaluationUpdates();

  async function loadPolicy() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_POLICY" });
      if (response && response.ok) return PhishGuard.normalizePolicy(response.policy);
    } catch (_) {
      // Fall through to the built-in policy when extension messaging is unavailable.
    }
    return PhishGuard.DEFAULT_POLICY;
  }

  async function loadRecentIdentityHint() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "GET_IDENTITY_HINT",
        siteKey: PhishGuard.siteKey(location.hostname)
      });
      return Boolean(response && response.ok && response.hint);
    } catch (_) {
      return false;
    }
  }

  // Messaging that never throws: an orphaned content script (after the extension
  // is reloaded/updated) has an invalidated context where chrome.runtime.sendMessage
  // throws synchronously. Swallow that so it can't abort rendering.
  function safeSend(message) {
    try {
      if (!chrome.runtime || !chrome.runtime.id) return Promise.resolve(null);
      const result = chrome.runtime.sendMessage(message);
      return result && typeof result.then === "function" ? result.catch(() => null) : Promise.resolve(result);
    } catch (_) {
      return Promise.resolve(null);
    }
  }

  function collectPage() {
    const forms = Array.from(document.forms || []);
    const formActions = forms
      .map((form) => {
        try {
          const url = new URL(form.getAttribute("action") || location.href, location.href);
          return {
            host: url.hostname,
            protocol: url.protocol,
            secure: url.protocol === "https:"
          };
        } catch (_) {
          return null;
        }
      })
      .filter(Boolean);
    const formActionHosts = formActions.map((action) => action.host);

    const enteredValues = collectEnteredValues();

    const visibleText = [
      document.title,
      ...Array.from(document.querySelectorAll("h1,h2,[aria-label]"))
        .slice(0, 20)
        .map((node) => node.innerText || node.getAttribute("aria-label") || ""),
      ...Array.from(document.querySelectorAll("img[alt],img[title],svg[aria-label],svg title"))
        .slice(0, 50)
        .map((node) => node.innerText || node.getAttribute("aria-label") || node.getAttribute("alt") || node.getAttribute("title") || ""),
      ...Array.from(document.querySelectorAll("meta[property='og:title'],meta[name='title'],meta[name='application-name'],link[rel~='icon']"))
        .slice(0, 20)
        .map((node) => node.getAttribute("content") || node.getAttribute("href") || ""),
      (document.body && document.body.innerText ? document.body.innerText.slice(0, 3000) : "")
    ].join("\n");

    return {
      url: location.href,
      hostname: location.hostname,
      title: document.title,
      text: visibleText,
      hasPassword: hasCredentialSecretField(),
      formActionHosts,
      formActions,
      pageProtocol: location.protocol,
      enteredValues,
      recentProtectedIdentity
    };
  }

  async function evaluateAndRender() {
    if (!recentProtectedIdentity) {
      recentProtectedIdentity = await loadRecentIdentityHint();
    }
    const pageEvaluation = PhishGuard.evaluatePage(policy, collectPage());
    recordIdentityHintIfNeeded(pageEvaluation);

    if (!IS_TOP_FRAME) {
      lastEvaluation = pageEvaluation;
      reportFrameEvaluation(pageEvaluation);
      removeWarning();
      return;
    }

    lastEvaluation = strongestEvaluation([
      pageEvaluation,
      ...(await loadFrameEvaluations())
    ]);

    if (lastEvaluation.action === "allow") {
      if (uiMode !== "none") removeWarning();
      return;
    }

    // Only (re)build the UI on a genuine state transition. An open modal or a
    // user-collapsed chip is left untouched so background re-evaluations can't
    // destroy it mid-interaction. Actual credential submission is still caught
    // by the submit guard regardless of which surface is showing.
    let rendered = false;
    if (uiMode === "modal" || uiMode === "chip") {
      // Leave the current surface in place.
    } else if (shouldShowPreEntryModal(lastEvaluation)) {
      renderInterstitial(lastEvaluation);
      rendered = true;
    } else if (uiMode !== "banner" || renderedAction !== lastEvaluation.action) {
      renderWarning(lastEvaluation);
      rendered = true;
    }

    if (rendered) {
      safeSend({
        type: "REPORT_EVENT",
        event: {
          action: lastEvaluation.action,
          score: lastEvaluation.score,
          hostname: displayHost(lastEvaluation),
          signals: lastEvaluation.signals,
          title: document.title
        }
      }).catch(() => {});
    }
  }

  function bindInputRecheck() {
    let timer = null;
    document.addEventListener(
      "input",
      () => {
        clearTimeout(timer);
        timer = setTimeout(evaluateAndRender, 250);
      },
      true
    );
  }

  function bindDomRecheck() {
    let timer = null;
    const observer = new MutationObserver((mutations) => {
      if (!mutations.some(mutationMightAffectCredentialFlow)) return;
      clearTimeout(timer);
      timer = setTimeout(evaluateAndRender, 150);
    });

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["aria-label", "autocomplete", "contenteditable", "id", "name", "placeholder", "role", "type"],
      childList: true,
      subtree: true
    });
  }

  function bindFrameEvaluationUpdates() {
    if (!IS_TOP_FRAME || !chrome.runtime?.onMessage) return;
    chrome.runtime.onMessage.addListener((message) => {
      if (message && message.type === "FRAME_EVALUATION_UPDATED") {
        evaluateAndRender();
      }
    });
  }

  function mutationMightAffectCredentialFlow(mutation) {
    if (mutation.type === "attributes") {
      return mutation.target instanceof HTMLInputElement || mutation.target instanceof HTMLFormElement;
    }

    return Array.from(mutation.addedNodes || []).some((node) => {
      if (!(node instanceof Element)) return false;
      return node.matches("input,form") || Boolean(node.querySelector("input,form"));
    });
  }

  function bindSubmitGuard() {
    document.addEventListener(
      "submit",
      (event) => {
        const evaluation = PhishGuard.evaluatePage(policy, collectPage());
        lastEvaluation = evaluation;
        recordIdentityHintIfNeeded(evaluation);

        if (evaluation.action === "allow" || !shouldChallengeWithModal(evaluation)) return;
        if (!IS_TOP_FRAME) {
          event.preventDefault();
          event.stopPropagation();
          reportFrameEvaluation(evaluation);
          return;
        }
        if (bypassNextSubmit && evaluation.action === "warn") {
          bypassNextSubmit = false;
          return;
        }

        event.preventDefault();
        event.stopPropagation();
        renderInterstitial(evaluation, event.target);
      },
      true
    );
  }

  function collectEnteredValues() {
    const values = Array.from(
      document.querySelectorAll("input,textarea,[contenteditable],[role='textbox']")
    )
      .filter(isVisibleTextValueElement)
      .map(valueFromElement)
      .map((value) => value.trim())
      .filter(Boolean);

    const joined = values.join("");
    if (joined && joined !== values.join(" ")) values.push(joined);
    return values;
  }

  function valueFromElement(element) {
    if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
      return element.value || "";
    }
    return element.textContent || "";
  }

  function isVisibleTextValueElement(element) {
    if (!(element instanceof HTMLElement)) return false;
    if (element.hidden || element.getAttribute("aria-hidden") === "true") return false;
    if (String(element.getAttribute("contenteditable") || "").toLowerCase() === "false") return false;
    if (element instanceof HTMLInputElement) {
      if (element.disabled || element.readOnly) return false;
      if (!isTextLikeInput(element)) return false;
    }
    if (element instanceof HTMLTextAreaElement && (element.disabled || element.readOnly)) return false;
    return element.getClientRects().length > 0;
  }

  function isTextLikeInput(input) {
    const type = String(input.getAttribute("type") || "text").toLowerCase();
    return ["email", "number", "search", "tel", "text", "url"].includes(type);
  }

  function hasCredentialSecretField() {
    if (Array.from(document.querySelectorAll("input[type='password']")).some(isVisibleCredentialElement)) {
      return true;
    }
    return Array.from(document.querySelectorAll("input,textarea,[role='textbox']")).some((element) => {
      return isVisibleCredentialElement(element) && looksLikePasswordTextField(element);
    });
  }

  async function loadFrameEvaluations() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_FRAME_EVALUATIONS" });
      if (!response || !response.ok || !Array.isArray(response.evaluations)) return [];
      return response.evaluations.map((evaluation) => ({
        action: evaluation.action || "allow",
        score: Number(evaluation.score || 0),
        signals: Array.isArray(evaluation.signals) ? evaluation.signals : [],
        policy,
        sourceFrame: true,
        sourceHost: evaluation.hostname || "",
        sourceTitle: evaluation.title || ""
      }));
    } catch (_) {
      return [];
    }
  }

  function reportFrameEvaluation(evaluation) {
    safeSend({
      type: "REPORT_FRAME_EVALUATION",
      evaluation: {
        action: evaluation.action,
        score: evaluation.score,
        signals: evaluation.signals,
        hostname: location.hostname,
        title: document.title
      }
    }).catch(() => {});
  }

  function strongestEvaluation(evaluations) {
    return evaluations
      .filter(Boolean)
      .sort((left, right) => {
        const actionDelta = actionRank(right.action) - actionRank(left.action);
        if (actionDelta) return actionDelta;
        return Number(right.score || 0) - Number(left.score || 0);
      })[0] || {
        action: "allow",
        score: 0,
        signals: [],
        policy
      };
  }

  function actionRank(action) {
    if (action === "block") return 2;
    if (action === "warn") return 1;
    return 0;
  }

  function isVisibleCredentialElement(element) {
    if (!(element instanceof HTMLElement)) return false;
    if (element.hidden || element.getAttribute("aria-hidden") === "true") return false;
    if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
      if (element.disabled || element.readOnly) return false;
      if (element instanceof HTMLInputElement && element.type === "hidden") return false;
    }
    return element.getClientRects().length > 0;
  }

  function looksLikePasswordTextField(element) {
    if (element instanceof HTMLInputElement && element.type === "password") return true;
    const text = [
      element.getAttribute("autocomplete"),
      element.getAttribute("aria-label"),
      element.getAttribute("id"),
      element.getAttribute("name"),
      element.getAttribute("placeholder")
    ].join(" ");
    return /\b(pass(word|code)?|passwd|pwd)\b/i.test(text);
  }

  function recordIdentityHintIfNeeded(evaluation) {
    if (!evaluation.signals.includes("protected-email-on-untrusted-host")) return;
    recentProtectedIdentity = true;
    safeSend({
      type: "RECORD_IDENTITY_HINT",
      hint: {
        siteKey: PhishGuard.siteKey(location.hostname),
        hostname: location.hostname
      }
    });
  }

  function shouldShowPreEntryModal(evaluation) {
    if (!shouldChallengeWithModal(evaluation)) return false;
    return Date.now() > credentialEntryAllowedUntil;
  }

  function shouldChallengeWithModal(evaluation) {
    const currentPageIdentityThenPassword =
      evaluation.signals.includes("protected-email-on-untrusted-host") &&
      evaluation.signals.includes("password-field-on-untrusted-host");
    const recentIdentityThenPassword = evaluation.signals.includes("recent-protected-email-then-password");
    const highConfidenceThreat =
      evaluation.signals.includes("deny-host") ||
      evaluation.signals.includes("credential-harvest-risk") ||
      (evaluation.signals.includes("punycode-host") &&
        evaluation.signals.includes("password-field-on-untrusted-host"));

    return currentPageIdentityThenPassword || recentIdentityThenPassword || highConfidenceThreat;
  }

  function allowCredentialEntryTemporarily() {
    const minutes = Number(policy.actions.identityChallengeMinutes || 5);
    credentialEntryAllowedUntil = Date.now() + Math.max(1, minutes) * 60 * 1000;
  }

  function warningIcon() {
    return `
      <svg class="apg-glyph" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d="M12 3 22 20H2L12 3Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"></path>
        <path d="M12 9v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>
        <circle cx="12" cy="17" r="1.25" fill="currentColor"></circle>
      </svg>`;
  }

  function shieldIcon() {
    return `
      <svg class="apg-btn-ico" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d="M12 3 4 6v5c0 5 3.4 8.3 8 10 4.6-1.7 8-5 8-10V6l-8-3Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"></path>
        <path d="m8.5 12 2.3 2.3L15.5 9.7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
      </svg>`;
  }

  function infoIcon() {
    return `
      <svg class="apg-btn-ico" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"></circle>
        <path d="M12 11v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>
        <circle cx="12" cy="7.6" r="1.1" fill="currentColor"></circle>
      </svg>`;
  }

  function renderWarning(evaluation) {
    const root = ensureRoot();
    uiMode = "banner";
    renderedAction = evaluation.action;
    const block = evaluation.action === "block";
    const copy = copyForEvaluation(evaluation, evaluation.action);
    root.innerHTML = `
      <style>${styles()}</style>
      <div class="apg ${block ? "apg-is-block" : ""}">
        <div class="apg-banner" role="alert">
          <span class="apg-bico">${warningIcon()}</span>
          <span class="apg-btxt">
            <strong>${escapeHtml(copy.title)}</strong>
            <span>${escapeHtml(copy.body)}</span>
          </span>
          <span class="apg-bact">
            <button type="button" class="apg-review" id="apg-review">Review</button>
            <button type="button" class="apg-x" id="apg-close" aria-label="Hide warning">&times;</button>
          </span>
        </div>
      </div>
    `;

    root.querySelector("#apg-close").addEventListener("click", () => renderCollapsedIcon(evaluation));
    root.querySelector("#apg-review").addEventListener("click", () => renderInterstitial(evaluation));
  }

  function renderCollapsedIcon(evaluation) {
    const root = ensureRoot();
    uiMode = "chip";
    const block = evaluation.action === "block";
    root.innerHTML = `
      <style>${styles()}</style>
      <div class="apg ${block ? "apg-is-block" : ""}">
        <button type="button" class="apg-chip" id="apg-chip" aria-label="Show anti-phishing guard warning">
          ${warningIcon()}
        </button>
      </div>
    `;

    root.querySelector("#apg-chip").addEventListener("click", () => renderInterstitial(evaluation));
  }

  function renderInterstitial(evaluation, form) {
    const root = ensureRoot();
    uiMode = "modal";
    const block = evaluation.action === "block";
    // The "Enter password anyway" escape only makes sense when the page actually
    // involves a password/credential context. An email-only warning (e.g. a
    // corporate address typed into a newsletter form with no password field)
    // gets an informational modal, not a credential challenge.
    const showEscape = !block && hasCredentialContext(evaluation);
    const copy = copyForEvaluation(evaluation, evaluation.action);
    const reasons = reasonsForEvaluation(evaluation);
    const learn = learnUrl(evaluation);

    root.innerHTML = `
      <style>${styles()}</style>
      <div class="apg ${block ? "apg-is-block" : ""}">
        <div class="apg-overlay" role="presentation">
          <section class="apg-panel" role="dialog" aria-modal="true" aria-labelledby="apg-title" aria-describedby="apg-lede">
            <div class="apg-head">
              <span class="apg-hico">${warningIcon()}</span>
              <h1 class="apg-title" id="apg-title">${escapeHtml(copy.title)}</h1>
              <button type="button" class="apg-x" id="apg-x" aria-label="Hide warning">&times;</button>
            </div>
            <div class="apg-bodywrap">
              <div class="apg-evidence">
                <span class="apg-evidence-label">You're on</span>
                <span class="apg-host">${escapeHtml(displayHost(evaluation))}</span>
              </div>
              <p class="apg-lede" id="apg-lede">${escapeHtml(copy.body)}</p>
              <div class="apg-reasons" aria-label="Why you're seeing this">
                <strong>Why you're seeing this</strong>
                <ul>${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
              </div>
              <details class="apg-technical">
                <summary>Show technical details</summary>
                <dl>
                  <dt>Host</dt><dd>${escapeHtml(displayHost(evaluation))}</dd>
                  <dt>Score</dt><dd>${Number(evaluation.score)}</dd>
                  <dt>Signals</dt><dd>${escapeHtml(evaluation.signals.join(", ") || "none")}</dd>
                </dl>
              </details>
            </div>
            <div class="apg-actions">
              <button type="button" class="apg-primary" id="apg-report">${shieldIcon()}<span>Report to Internal Security</span></button>
              ${learn ? `<button type="button" class="apg-secondary" id="apg-learn">${infoIcon()}<span>Learn More</span></button>` : ""}
              <button type="button" class="apg-link" id="apg-shot">Download a screenshot to attach</button>
              <p class="apg-confirm" id="apg-confirm" role="status" hidden></p>
            </div>
            ${
              showEscape
                ? `
            <div class="apg-foot">
              <label class="apg-ack"><input type="checkbox" id="apg-ack"> I've checked the address above and want to continue on this site anyway.</label>
              <div class="apg-escape-row">
                <button type="button" class="apg-escape" id="apg-escape" disabled>Enter password anyway</button>
                <span class="apg-count" id="apg-count">Available in 3s</span>
              </div>
            </div>`
                : ""
            }
          </section>
        </div>
      </div>
    `;

    wireInterstitial(root, evaluation, showEscape);
  }

  function hasCredentialContext(evaluation) {
    const s = evaluation.signals || [];
    return (
      s.includes("password-field-on-untrusted-host") ||
      s.includes("protected-email-password-on-untrusted-host") ||
      s.includes("credential-harvest-risk") ||
      s.includes("recent-protected-email-then-password") ||
      s.includes("password-form-targets-http") ||
      s.includes("password-form-posts-offsite")
    );
  }

  function wireInterstitial(root, evaluation, showEscape) {
    const overlay = root.querySelector(".apg-overlay");
    const panel = root.querySelector(".apg-panel");
    const confirmEl = root.querySelector("#apg-confirm");
    const setConfirm = (message) => {
      if (!confirmEl) return;
      confirmEl.hidden = false;
      confirmEl.textContent = message;
    };

    root.querySelector("#apg-x").addEventListener("click", () => renderCollapsedIcon(evaluation));

    root.querySelector("#apg-report").addEventListener("click", () => {
      const text = buildReportText(evaluation);
      if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
      const email = String(evaluation.policy.reportEmail || "").trim();
      if (email) {
        const subject = "Suspicious sign-in page flagged by Anti-Phishing Guard";
        window.open(
          "mailto:" + email + "?subject=" + encodeURIComponent(subject) + "&body=" + encodeURIComponent(text),
          "_self"
        );
        setConfirm("Details copied — opening your email to " + email + ".");
      } else {
        setConfirm("Report details copied to your clipboard.");
      }
    });

    const learnButton = root.querySelector("#apg-learn");
    if (learnButton) {
      learnButton.addEventListener("click", () => {
        window.open(learnUrl(evaluation), "_blank", "noopener,noreferrer");
      });
    }

    const shotButton = root.querySelector("#apg-shot");
    if (shotButton) {
      shotButton.addEventListener("click", async () => {
        shotButton.disabled = true;
        setConfirm("Capturing screenshot…");
        const saved = await captureScreenshotToDownload();
        shotButton.disabled = false;
        setConfirm(
          saved
            ? "Screenshot saved to your Downloads — attach it to the email."
            : "Couldn't capture a screenshot. Use your system screenshot tool instead."
        );
      });
    }

    if (showEscape) {
      const ack = root.querySelector("#apg-ack");
      const escape = root.querySelector("#apg-escape");
      const count = root.querySelector("#apg-count");
      let remaining = 3;
      const update = () => {
        escape.disabled = !(ack.checked && remaining <= 0);
      };
      const timer = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
          clearInterval(timer);
          count.textContent = "You can continue, but it isn't recommended.";
        } else {
          count.textContent = "Available in " + remaining + "s";
        }
        update();
      }, 1000);
      ack.addEventListener("change", update);
      escape.addEventListener("click", () => {
        if (escape.disabled) return;
        clearInterval(timer);
        allowCredentialEntryTemporarily();
        bypassNextSubmit = true;
        removeWarning();
        const password = document.querySelector("input[type='password']");
        if (password) password.focus();
      });
    }

    bindFocusTrap(root, overlay, panel, evaluation);
  }

  function bindFocusTrap(root, overlay, panel, evaluation) {
    const focusable = () =>
      Array.from(
        panel.querySelectorAll('button:not([disabled]), a[href], input, summary, [tabindex]:not([tabindex="-1"])')
      ).filter((element) => element.getClientRects().length > 0);

    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        renderCollapsedIcon(evaluation);
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      const active = root.activeElement;
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    });

    const primary = root.querySelector("#apg-report");
    if (primary) primary.focus();
  }

  function learnUrl(evaluation) {
    const url = String(evaluation.policy.infoUrl || "").trim();
    if (!url) return "";
    try {
      return new URL(url).protocol === "https:" ? url : "";
    } catch (_) {
      return "";
    }
  }

  function buildReportText(evaluation) {
    return [
      "Reported via Anti-Phishing Guard",
      "Host: " + displayHost(evaluation),
      "URL: " + location.href,
      "Verdict: " + evaluation.action,
      "Signals: " + (evaluation.signals.join(", ") || "none")
    ].join("\n");
  }

  async function captureScreenshotToDownload() {
    const hostElement = warningHost || document.getElementById(ROOT_ID);
    const hadObserver = Boolean(warningHostObserver);
    // Suspend the host watchdog so it doesn't re-show the overlay mid-capture.
    if (warningHostObserver) {
      warningHostObserver.disconnect();
      warningHostObserver = null;
    }
    if (hostElement) hostElement.style.setProperty("visibility", "hidden", "important");
    try {
      // Let the browser paint the hidden state before the background grabs the frame.
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const response = await chrome.runtime.sendMessage({ type: "CAPTURE_SCREENSHOT" });
      return Boolean(response && response.ok && response.saved);
    } catch (_) {
      return false;
    } finally {
      if (hostElement) applyWarningHostStyles(hostElement);
      if (hadObserver) watchWarningHost();
    }
  }

  function copyForEvaluation(evaluation, displayAction) {
    const signals = evaluation.signals || [];
    const brand = protectedBrandName(evaluation.policy);
    const messages = evaluation.policy.messages || {};

    if (signals.includes("deny-host")) {
      return {
        title: "Blocked sign-in page",
        body: "This site is on the company block list. Don't enter your password here."
      };
    }

    if (signals.includes("credential-harvest-risk")) {
      return {
        title: `Possible fake ${brand} sign-in`,
        body: `This unapproved site combines ${brand} sign-in cues with a password request. Do not enter your password here.`
      };
    }

    if (
      signals.includes("protected-email-on-untrusted-host") &&
      signals.includes("password-field-on-untrusted-host")
    ) {
      return {
        title: "Stop before entering your password",
        body: `You used a ${brand} email address on an unapproved site, and this page is now asking for a password.`
      };
    }

    if (signals.includes("recent-protected-email-then-password")) {
      return {
        title: "Password requested after company email",
        body: `A ${brand} email address was entered on this site recently. Confirm this site is legitimate before entering a password.`
      };
    }

    if (signals.includes("protected-email-on-untrusted-host")) {
      return {
        title: "Company email on an unapproved site",
        body: `You entered a ${brand} email address on a site that isn't a recognised ${brand} service. Be careful about what you share here.`
      };
    }

    if (signals.includes("password-form-targets-http")) {
      return {
        title: "Insecure sign-in form",
        body: "This page has a password form that submits over insecure HTTP. Avoid entering work credentials."
      };
    }

    if (signals.includes("protected-lookalike-host")) {
      return {
        title: "Lookalike sign-in address",
        body: `This site address looks similar to a protected ${brand} domain but is not approved.`
      };
    }

    if (signals.includes("protected-brand-on-untrusted-host")) {
      return {
        title: `${brand} mentioned on an unapproved site`,
        body: `This page mentions ${brand}, but the site is not on the approved sign-in list.`
      };
    }

    return {
      title: displayAction === "block" ? messages.blockTitle : messages.warnTitle,
      body: displayAction === "block" ? messages.blockBody : messages.warnBody
    };
  }

  function reasonsForEvaluation(evaluation) {
    const signals = evaluation.signals || [];
    const reasons = [];
    const add = (signal, text) => {
      if (signals.includes(signal)) reasons.push(text);
    };

    if (evaluation.sourceFrame) reasons.push("The suspicious credential page is inside an embedded frame.");
    add("deny-host", "This host is on the block list.");
    add("protected-email-on-untrusted-host", "A protected company email address was entered here.");
    add("protected-email-password-on-untrusted-host", "A protected company email and password field appeared together.");
    add("recent-protected-email-then-password", "A protected company email was entered on this site recently.");
    add("password-field-on-untrusted-host", "A password field is present on an unapproved site.");
    add("password-form-targets-http", "The password form targets an insecure HTTP endpoint.");
    add("password-form-posts-offsite", "The password form submits to another unapproved host.");
    add("credential-harvest-risk", "The page combines company sign-in cues with a password request.");
    add("protected-lookalike-host", "The site address resembles a protected company domain.");
    add("protected-brand-on-untrusted-host", "The page mentions a protected company brand.");
    add("punycode-host", "The site address uses encoded international characters.");

    return reasons.length ? reasons : ["This site is not on the approved sign-in list."];
  }

  function protectedBrandName(rawPolicy) {
    const candidate = (rawPolicy.protectedBrands || []).find((brand) => String(brand || "").trim());
    if (candidate) return String(candidate).trim();
    return "company";
  }

  function displayHost(evaluation) {
    return evaluation.sourceHost || location.hostname;
  }

  function ensureRoot() {
    let host = warningHost;
    if (!host || !host.isConnected) {
      const existing = document.getElementById(ROOT_ID);
      if (existing && existing !== warningHost) existing.remove();

      host = warningHost || document.createElement("div");
      host.id = ROOT_ID;
      // `all: initial` is the reset baseline, set ONCE here. It must not be
      // re-asserted in applyWarningHostStyles: getPropertyValue("all") never
      // reads back "initial", so re-asserting it would rewrite the style
      // attribute on every watchdog tick and spin an infinite mutation loop.
      host.style.setProperty("all", "initial", "important");
      applyWarningHostStyles(host);
      document.documentElement.appendChild(host);

      if (!warningRoot) {
        warningRoot = host.attachShadow({ mode: "closed" });
      }
      warningHost = host;
    }

    applyWarningHostStyles(host);
    watchWarningHost();
    return warningRoot;
  }

  function removeWarning() {
    uiMode = "none";
    renderedAction = null;
    if (warningHostObserver) {
      warningHostObserver.disconnect();
      warningHostObserver = null;
    }
    const host = document.getElementById(ROOT_ID);
    if (host) host.remove();
    warningHost = null;
    warningRoot = null;
  }

  function applyWarningHostStyles(host) {
    const importantStyles = {
      clip: "auto",
      "clip-path": "none",
      display: "block",
      filter: "none",
      height: "auto",
      opacity: "1",
      overflow: "visible",
      "pointer-events": "auto",
      position: "static",
      transform: "none",
      visibility: "visible",
      width: "auto",
      "z-index": "auto"
    };

    for (const [property, value] of Object.entries(importantStyles)) {
      if (
        host.style.getPropertyValue(property) !== value ||
        host.style.getPropertyPriority(property) !== "important"
      ) {
        host.style.setProperty(property, value, "important");
      }
    }
    if (host.hasAttribute("hidden")) host.removeAttribute("hidden");
    if (host.getAttribute("aria-hidden") !== "false") host.setAttribute("aria-hidden", "false");
  }

  function watchWarningHost() {
    if (!warningHost || warningHostObserver) return;

    warningHostObserver = new MutationObserver(() => {
      if (!warningHost) return;
      // Re-anchor if removed or relocated out of <html>'s direct children.
      if (warningHost.parentNode !== document.documentElement) {
        document.documentElement.appendChild(warningHost);
      }
      applyWarningHostStyles(warningHost);
    });

    // childList only (no subtree): the host is a direct child of <html>, so its
    // removal is detectable without observing every mutation on the page.
    warningHostObserver.observe(document.documentElement, {
      childList: true
    });
    warningHostObserver.observe(warningHost, {
      attributes: true,
      attributeFilter: ["aria-hidden", "class", "hidden", "style"]
    });
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function styles() {
    return `
      :host {
        all: initial;
        color-scheme: light;
      }
      .apg {
        --ink: #1b1d21;
        --muted: #6b7280;
        --surface: #ffffff;
        --hair: #e5e7eb;
        --accent: #b45309;
        --tint: #fff7ed;
        --accent-ink: #7c3a06;
        --safe: #15803d;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
        color: var(--ink);
      }
      .apg.apg-is-block {
        --accent: #b91c1c;
        --tint: #fef2f2;
        --accent-ink: #7f1d1d;
      }
      .apg *,
      .apg *::before,
      .apg *::after {
        box-sizing: border-box;
      }
      .apg button {
        appearance: none;
        font-family: inherit;
        cursor: pointer;
      }
      .apg :focus-visible {
        outline: 3px solid #1d4ed8;
        outline-offset: 2px;
        border-radius: 6px;
      }
      .apg-glyph {
        display: block;
        width: 24px;
        height: 24px;
      }

      .apg-banner {
        position: fixed;
        top: 12px;
        left: 12px;
        right: 12px;
        z-index: 2147483647;
        max-width: 760px;
        margin: 0 auto;
        display: flex;
        align-items: center;
        gap: 14px;
        flex-wrap: wrap;
        background: var(--tint);
        border: 1px solid var(--accent);
        border-left: 6px solid var(--accent);
        border-radius: 10px;
        padding: 12px 14px;
        box-shadow: 0 10px 30px rgba(20, 20, 20, 0.16);
        line-height: 1.35;
      }
      .apg-bico {
        flex: 0 0 auto;
        color: var(--accent);
      }
      .apg-btxt {
        flex: 1 1 240px;
        min-width: 0;
      }
      .apg-btxt strong {
        display: block;
        font-size: 14px;
        font-weight: 600;
        color: var(--ink);
      }
      .apg-btxt > span {
        font-size: 13px;
        color: var(--accent-ink);
      }
      .apg-bact {
        flex: 0 0 auto;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .apg-review {
        background: #1b1d21;
        color: #fff;
        border: 0;
        border-radius: 8px;
        padding: 9px 14px;
        font-size: 13px;
        font-weight: 600;
        white-space: nowrap;
      }
      .apg-review:hover {
        background: #000;
      }
      .apg-x {
        background: transparent;
        border: 0;
        color: var(--accent-ink);
        font-size: 20px;
        line-height: 1;
        padding: 6px 8px;
        border-radius: 8px;
      }

      .apg-chip {
        position: fixed;
        top: 12px;
        left: 12px;
        z-index: 2147483647;
        width: 46px;
        height: 46px;
        border-radius: 999px;
        border: 2px solid #fff;
        background: var(--accent);
        color: #fff;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 10px 30px rgba(20, 20, 20, 0.28);
        padding: 0;
      }

      .apg-overlay {
        position: fixed;
        inset: 0;
        z-index: 2147483647;
        background: rgba(20, 18, 16, 0.55);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
      }
      .apg-is-block .apg-overlay {
        background: rgba(40, 12, 12, 0.6);
      }
      .apg-panel {
        background: var(--surface);
        width: min(540px, 100%);
        max-height: 90vh;
        overflow: auto;
        border-radius: 14px;
        border-top: 6px solid var(--accent);
        box-shadow: 0 24px 70px rgba(0, 0, 0, 0.4);
      }
      .apg-head {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 22px 24px 0;
      }
      .apg-hico {
        color: var(--accent);
        flex: 0 0 auto;
        margin-top: 2px;
      }
      .apg-title {
        font-size: 20px;
        font-weight: 700;
        line-height: 1.25;
        margin: 0;
        flex: 1;
      }
      .apg-head .apg-x {
        margin: -4px -6px 0 0;
      }
      .apg-bodywrap {
        padding: 14px 24px 0;
      }
      .apg-evidence {
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 13px;
        background: #f6f7f9;
        border: 1px solid var(--hair);
        border-radius: 8px;
        padding: 10px 12px;
        margin: 0 0 14px;
        word-break: break-all;
      }
      .apg-evidence-label {
        display: block;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 11px;
        font-weight: 600;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.04em;
        margin-bottom: 3px;
      }
      .apg-host {
        color: var(--accent-ink);
        font-weight: 500;
      }
      .apg-lede {
        font-size: 14px;
        line-height: 1.5;
        margin: 0 0 16px;
        color: #2c2f34;
      }
      .apg-reasons {
        background: var(--tint);
        border-left: 4px solid var(--accent);
        border-radius: 0 8px 8px 0;
        padding: 11px 14px;
        margin: 0 0 14px;
      }
      .apg-reasons strong {
        display: block;
        font-size: 12px;
        margin-bottom: 5px;
        color: var(--accent-ink);
      }
      .apg-reasons ul {
        margin: 0;
        padding-left: 18px;
      }
      .apg-reasons li {
        font-size: 13px;
        line-height: 1.45;
        margin: 3px 0;
      }
      .apg-technical {
        margin: 0 0 16px;
      }
      .apg-technical summary {
        font-size: 12px;
        color: var(--muted);
        cursor: pointer;
        padding: 4px 0;
      }
      .apg-technical dl {
        display: grid;
        grid-template-columns: 78px 1fr;
        gap: 5px 12px;
        background: #f6f7f9;
        border-radius: 8px;
        padding: 11px;
        margin: 6px 0 0;
      }
      .apg-technical dt {
        color: var(--muted);
        font-size: 12px;
        margin: 0;
      }
      .apg-technical dd {
        margin: 0;
        font-size: 12px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        word-break: break-all;
      }

      .apg-actions {
        padding: 8px 24px 0;
        display: grid;
        gap: 10px;
      }
      .apg-actions:last-child {
        padding-bottom: 22px;
      }
      .apg-primary {
        width: 100%;
        background: #1b1d21;
        color: #fff;
        border: 0;
        border-radius: 10px;
        padding: 14px;
        font-size: 15px;
        font-weight: 600;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
      }
      .apg-primary:hover {
        background: #000;
      }
      .apg-secondary {
        width: 100%;
        background: #fff;
        color: var(--ink);
        border: 1px solid #cbd2da;
        border-radius: 10px;
        padding: 12px;
        font-size: 14px;
        font-weight: 600;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
      }
      .apg-btn-ico {
        width: 16px;
        height: 16px;
        flex: 0 0 auto;
        display: block;
      }
      .apg-secondary:hover {
        background: #f6f7f9;
      }
      .apg-link {
        background: none;
        border: 0;
        color: var(--muted);
        font-size: 12.5px;
        font-weight: 500;
        text-decoration: underline;
        padding: 2px 0;
        justify-self: start;
      }
      .apg-link:hover {
        color: var(--ink);
      }
      .apg-confirm {
        font-size: 12.5px;
        color: var(--safe);
        margin: 4px 0 0;
        line-height: 1.4;
      }

      .apg-foot {
        padding: 14px 24px 22px;
        margin-top: 14px;
        border-top: 1px solid var(--hair);
      }
      .apg-ack {
        display: flex;
        gap: 9px;
        align-items: flex-start;
        font-size: 13px;
        color: #374151;
        cursor: pointer;
      }
      .apg-ack input {
        margin-top: 2px;
        width: 16px;
        height: 16px;
        flex: 0 0 auto;
      }
      .apg-escape-row {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-top: 12px;
        flex-wrap: wrap;
      }
      .apg-escape {
        background: transparent;
        color: #6b7280;
        border: 1px solid #d1d5db;
        border-radius: 8px;
        padding: 9px 13px;
        font-size: 13px;
        font-weight: 500;
      }
      .apg-escape:enabled {
        color: var(--accent-ink);
        border-color: #e7b8b8;
      }
      .apg-escape:disabled {
        opacity: 0.55;
        cursor: not-allowed;
      }
      .apg-count {
        font-size: 12px;
        color: var(--muted);
      }

      @media (max-width: 420px) {
        .apg-bact {
          flex: 1 1 100%;
          justify-content: flex-end;
        }
      }
    `;
  }
})();
