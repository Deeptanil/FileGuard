/**
 * FileGuard - Authoritative Expiration Countdown
 */
function initCountdown(targetIsoString, token, onExpireCallback) {
  const targetDate = new Date(targetIsoString).getTime();

  function update() {
    const now = new Date().getTime();
    const distance = targetDate - now;

    const hoursEl = document.getElementById("countdown-hours");
    const minsEl = document.getElementById("countdown-mins");
    const secsEl = document.getElementById("countdown-secs");

    if (distance <= 0) {
      if (hoursEl) hoursEl.textContent = "00";
      if (minsEl) minsEl.textContent = "00";
      if (secsEl) secsEl.textContent = "00";

      const container = document.getElementById("countdown-wrapper");
      if (container) {
        container.innerHTML = `
          <div class="alert alert-warning" style="margin-top:1rem;">
            <strong>File Expired:</strong> This temporary file has passed its 12-hour availability window.
          </div>
        `;
      }

      const dlBtn = document.getElementById("download-btn");
      if (dlBtn) {
        dlBtn.setAttribute("disabled", "true");
        dlBtn.classList.add("btn-secondary");
        dlBtn.classList.remove("btn-primary");
        dlBtn.innerHTML = `<span>File Expired</span>`;
      }

      if (typeof onExpireCallback === "function") {
        onExpireCallback();
      }
      return;
    }

    const hours = Math.floor(distance / (1000 * 60 * 60));
    const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((distance % (1000 * 60)) / 1000);

    if (hoursEl) hoursEl.textContent = String(hours).padStart(2, "0");
    if (minsEl) minsEl.textContent = String(minutes).padStart(2, "0");
    if (secsEl) secsEl.textContent = String(seconds).padStart(2, "0");

    setTimeout(update, 1000);
  }

  update();
}

/**
 * Copy text to clipboard utility with UI feedback
 */
function copyToClipboard(text, triggerBtnId, feedbackText = "Copied!") {
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(triggerBtnId);
    if (btn) {
      const originalHtml = btn.innerHTML;
      btn.innerHTML = `<span style="color:#10B981;">✓ ${feedbackText}</span>`;
      setTimeout(() => {
        btn.innerHTML = originalHtml;
      }, 2000);
    }
  }).catch(err => {
    console.error("Failed to copy:", err);
  });
}

