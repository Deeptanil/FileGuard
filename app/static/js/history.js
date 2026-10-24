/**
 * FileGuard — Client-Side Ephemeral Vault & History Manager
 */
(function () {
  let activeTab = "uploads";
  let uploadItems = [];
  let viewItems = [];
  let pendingRevokeToken = null;
  let countdownTimerId = null;

  document.addEventListener("DOMContentLoaded", () => {
    loadLocalData();
    updateBadges();
    renderCurrentTab();
    syncLiveStatuses();

    // Start 1-second interval to update countdowns smoothly
    countdownTimerId = setInterval(updateCountdowns, 1000);

    const confirmRevokeBtn = document.getElementById("confirm-revoke-btn");
    if (confirmRevokeBtn) {
      confirmRevokeBtn.addEventListener("click", executeRevoke);
    }
  });

  function loadLocalData() {
    try {
      uploadItems = JSON.parse(localStorage.getItem("fileguard_user_uploads") || "[]");
    } catch (e) {
      uploadItems = [];
    }

    try {
      viewItems = JSON.parse(localStorage.getItem("fileguard_user_views") || "[]");
    } catch (e) {
      viewItems = [];
    }
  }

  function saveLocalData() {
    try {
      localStorage.setItem("fileguard_user_uploads", JSON.stringify(uploadItems));
    } catch (e) {}

    try {
      localStorage.setItem("fileguard_user_views", JSON.stringify(viewItems));
    } catch (e) {}

    updateBadges();
  }

  function updateBadges() {
    const uploadBadge = document.getElementById("uploads-count-badge");
    const viewBadge = document.getElementById("views-count-badge");
    if (uploadBadge) uploadBadge.textContent = uploadItems.length;
    if (viewBadge) viewBadge.textContent = viewItems.length;
  }

  window.switchHistoryTab = function (tab) {
    activeTab = tab;
    const tabUploads = document.getElementById("tab-btn-uploads");
    const tabViews = document.getElementById("tab-btn-views");
    const secUploads = document.getElementById("section-uploads");
    const secViews = document.getElementById("section-views");

    if (tab === "uploads") {
      tabUploads.classList.add("active-tab");
      tabViews.classList.remove("active-tab");
      secUploads.style.display = "block";
      secViews.style.display = "none";
    } else {
      tabViews.classList.add("active-tab");
      tabUploads.classList.remove("active-tab");
      secViews.style.display = "block";
      secUploads.style.display = "none";
    }
    renderCurrentTab();
  };

  function renderCurrentTab() {
    if (activeTab === "uploads") {
      renderUploads();
    } else {
      renderViews();
    }
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  function formatTime(isoString) {
    if (!isoString) return "--";
    try {
      const d = new Date(isoString);
      return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch (e) {
      return isoString;
    }
  }

  function formatRemaining(seconds) {
    if (seconds <= 0) return "EXPIRED";
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    if (hrs > 0) {
      return `${hrs}h ${mins}m ${secs}s`;
    }
    return `${mins}m ${secs}s`;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  const SVG_BOX = '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--comic-cyan)" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>';
  const SVG_EYE = '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--comic-yellow)" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const SVG_FILE = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#000000" stroke-width="2.3"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
  const SVG_BUNDLE = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#000000" stroke-width="2.3"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
  const SVG_DOWNLOAD = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#000000" stroke-width="2.3"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
  const SVG_TRASH = '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
  const SVG_CLOCK = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="vertical-align:middle;margin-right:3px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';

  function renderUploads() {
    const container = document.getElementById("uploads-list-container");
    if (!container) return;

    if (!uploadItems || uploadItems.length === 0) {
      container.innerHTML = `
        <div class="card" style="padding: 3rem 1.5rem; text-align: center; background: #0B0E17; border: 2px dashed #334155;">
          <div style="display: flex; justify-content: center; margin-bottom: 0.75rem;">${SVG_BOX}</div>
          <h3 style="font-family: var(--font-display); font-size: 1.25rem; color: #FFFFFF; margin-bottom: 0.35rem;">NO UPLOADS RECORDED YET</h3>
          <p style="color: #94A3B8; font-size: 0.9rem; max-width: 480px; margin: 0 auto 1.5rem;">
            When you upload single files or full folder bundles from this browser, they will appear here with live countdowns and instant revocation buttons.
          </p>
          <a href="/upload" class="btn btn-primary" style="background: var(--comic-cyan); color: #000; font-weight: 800; border: 2px solid #000; box-shadow: 3px 3px 0px #000;">
            Upload Your First File
          </a>
        </div>
      `;
      return;
    }

    let html = "";
    uploadItems.forEach((item, idx) => {
      const isBundle = item.is_bundle;
      const status = item.live_status || item.status || "active";
      const remaining = typeof item.remaining_seconds === "number" ? item.remaining_seconds : 0;
      const isExpired = status === "expired" || remaining <= 0;
      const isDeleted = status === "deleted";

      let statusBadge = "";
      if (isDeleted) {
        statusBadge = `<span class="badge" style="background: #EF4444; color: #FFFFFF; font-size: 0.7rem; font-weight: 800;">REVOKED</span>`;
      } else if (isExpired) {
        statusBadge = `<span class="badge" style="background: #F59E0B; color: #000000; font-size: 0.7rem; font-weight: 800;">EXPIRED</span>`;
      } else {
        statusBadge = `<span class="badge" style="background: var(--comic-lime); color: #000000; font-size: 0.7rem; font-weight: 800;">ACTIVE</span>`;
      }

      const timerDisplay = (!isDeleted && !isExpired && remaining > 0)
        ? `<span id="timer-upload-${item.token}" style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--comic-yellow); font-weight: 700;">${SVG_CLOCK}${formatRemaining(remaining)} remaining</span>`
        : `<span style="font-family: var(--font-mono); font-size: 0.8rem; color: #64748B;">Unavailable</span>`;

      html += `
        <div class="history-item-card" id="upload-card-${item.token}">
          <!-- Left: Icon & File Meta -->
          <div style="display: flex; align-items: center; gap: 1rem; flex: 1; min-width: min(100%, 240px);">
            <div class="file-icon-box" style="background: ${isBundle ? 'var(--comic-purple)' : 'var(--comic-cyan)'}; color: #000000;">
              ${isBundle ? SVG_BUNDLE : SVG_FILE}
            </div>
            <div style="min-width: 0; flex: 1;">
              <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.25rem;">
                ${statusBadge}
                ${isBundle ? '<span class="badge" style="background: var(--comic-pink); color: #FFF; font-size: 0.65rem;">FOLDER BUNDLE</span>' : ''}
                <span class="badge" style="background: #1E293B; color: #94A3B8; font-size: 0.65rem;">${formatBytes(item.file_size)}</span>
                <span class="badge" style="background: #1E293B; color: var(--comic-cyan); font-family: var(--font-mono); font-size: 0.65rem;">#${item.token}</span>
              </div>
              <strong style="color: #FFFFFF; font-size: 1.05rem; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(item.filename)}">
                ${escapeHtml(item.filename)}
              </strong>
              <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 0.2rem; display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap;">
                <span>Uploaded: ${formatTime(item.uploaded_at)}</span>
                ${timerDisplay}
              </div>
            </div>
          </div>

          <!-- Right: Actions -->
          <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
            <button type="button" class="btn btn-secondary btn-sm" onclick="copyShareLink('${escapeHtml(item.share_url)}', 'copy-btn-${item.token}')" id="copy-btn-${item.token}" style="background: var(--comic-yellow); color: #000000; font-weight: 800; font-size: 0.75rem; border: 2px solid #000; box-shadow: 2px 2px 0px #000;">
              COPY LINK
            </button>
            <a href="${escapeHtml(item.share_url)}" target="_blank" class="btn btn-secondary btn-sm" style="font-size: 0.75rem; border: 2px solid #334155;">
              VIEW
            </a>
            ${(!isDeleted && !isExpired) ? `
              <button type="button" class="btn btn-secondary btn-sm" onclick="promptRevoke('${item.token}', '${escapeHtml(item.filename)}')" style="background: rgba(255, 46, 147, 0.2); color: var(--comic-pink); border: 2px solid var(--comic-pink); font-size: 0.75rem; font-weight: 800;">
                REVOKE & PURGE
              </button>
            ` : ''}
            <button type="button" onclick="removeUploadRecord('${item.token}')" title="Remove from this device's history" style="background: none; border: none; color: #64748B; cursor: pointer; padding: 0.35rem; display: inline-flex; align-items: center;">
              ${SVG_TRASH}
            </button>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  }

  function renderViews() {
    const container = document.getElementById("views-list-container");
    if (!container) return;

    if (!viewItems || viewItems.length === 0) {
      container.innerHTML = `
        <div class="card" style="padding: 3rem 1.5rem; text-align: center; background: #0B0E17; border: 2px dashed #334155;">
          <div style="display: flex; justify-content: center; margin-bottom: 0.75rem;">${SVG_EYE}</div>
          <h3 style="font-family: var(--font-display); font-size: 1.25rem; color: #FFFFFF; margin-bottom: 0.35rem;">NO SHARED FILES OPENED YET</h3>
          <p style="color: #94A3B8; font-size: 0.9rem; max-width: 480px; margin: 0 auto;">
            Whenever someone shares a FileGuard link with you and you open it, it will be saved here so you can easily find and re-download it before it self-destructs.
          </p>
        </div>
      `;
      return;
    }

    let html = "";
    viewItems.forEach((item, idx) => {
      const isBundle = item.is_bundle;
      const status = item.live_status || item.status || "active";
      const remaining = typeof item.remaining_seconds === "number" ? item.remaining_seconds : 0;
      const isExpired = status === "expired" || remaining <= 0;
      const isDeleted = status === "deleted" || status === "not_found";

      let statusBadge = "";
      if (isDeleted) {
        statusBadge = `<span class="badge" style="background: #EF4444; color: #FFFFFF; font-size: 0.7rem; font-weight: 800;">REVOKED</span>`;
      } else if (isExpired) {
        statusBadge = `<span class="badge" style="background: #F59E0B; color: #000000; font-size: 0.7rem; font-weight: 800;">EXPIRED</span>`;
      } else {
        statusBadge = `<span class="badge" style="background: var(--comic-lime); color: #000000; font-size: 0.7rem; font-weight: 800;">ACTIVE</span>`;
      }

      const timerDisplay = (!isDeleted && !isExpired && remaining > 0)
        ? `<span id="timer-view-${item.token}" style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--comic-yellow); font-weight: 700;">${SVG_CLOCK}${formatRemaining(remaining)} remaining</span>`
        : `<span style="font-family: var(--font-mono); font-size: 0.8rem; color: #64748B;">Unavailable</span>`;

      const shaDisplay = item.sha256 ? item.sha256.substring(0, 16) + "..." : "";

      html += `
        <div class="history-item-card" id="view-card-${item.token}">
          <!-- Left: Icon & Meta -->
          <div style="display: flex; align-items: center; gap: 1rem; flex: 1; min-width: min(100%, 240px);">
            <div class="file-icon-box" style="background: var(--comic-yellow); color: #000000;">
              ${isBundle ? SVG_BUNDLE : SVG_DOWNLOAD}
            </div>
            <div style="min-width: 0; flex: 1;">
              <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.25rem;">
                ${statusBadge}
                ${isBundle ? '<span class="badge" style="background: var(--comic-pink); color: #FFF; font-size: 0.65rem;">FOLDER BUNDLE</span>' : ''}
                <span class="badge" style="background: #1E293B; color: #94A3B8; font-size: 0.65rem;">${formatBytes(item.file_size)}</span>
              </div>
              <strong style="color: #FFFFFF; font-size: 1.05rem; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(item.filename)}">
                ${escapeHtml(item.filename)}
              </strong>
              <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 0.2rem; display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap;">
                <span>Viewed: ${formatTime(item.viewed_at)}</span>
                ${timerDisplay}
                ${item.sha256 ? `<span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--comic-cyan);" title="SHA-256: ${escapeHtml(item.sha256)}">SHA: ${shaDisplay}</span>` : ''}
              </div>
            </div>
          </div>

          <!-- Right: Actions -->
          <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
            ${(!isDeleted && !isExpired) ? `
              <a href="${escapeHtml(item.share_url)}" class="btn btn-primary btn-sm" style="background: var(--comic-cyan); color: #000000; font-weight: 800; font-size: 0.75rem; border: 2px solid #000; box-shadow: 2px 2px 0px #000;">
                OPEN & DOWNLOAD
              </a>
            ` : `
              <span class="badge" style="background: #1E293B; color: #64748B; font-size: 0.75rem;">Unavailable</span>
            `}
            <button type="button" onclick="removeViewRecord('${item.token}')" title="Remove from viewed history" style="background: none; border: none; color: #64748B; cursor: pointer; padding: 0.35rem; display: inline-flex; align-items: center;">
              ${SVG_TRASH}
            </button>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  }

  function syncLiveStatuses() {
    const allTokens = Array.from(new Set([
      ...uploadItems.map(u => u.token),
      ...viewItems.map(v => v.token)
    ])).filter(Boolean);

    if (allTokens.length === 0) return;

    fetch("/api/files/batch-status", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCsrfToken()
      },
      body: JSON.stringify({ tokens: allTokens })
    })
      .then(res => res.json())
      .then(data => {
        if (!data || !data.statuses) return;
        const statuses = data.statuses;

        uploadItems.forEach(item => {
          if (statuses[item.token]) {
            item.live_status = statuses[item.token].status;
            item.remaining_seconds = statuses[item.token].remaining_seconds;
            if (statuses[item.token].filename) item.filename = statuses[item.token].filename;
            if (statuses[item.token].file_size) item.file_size = statuses[item.token].file_size;
          }
        });

        viewItems.forEach(item => {
          if (statuses[item.token]) {
            item.live_status = statuses[item.token].status;
            item.remaining_seconds = statuses[item.token].remaining_seconds;
            if (statuses[item.token].filename) item.filename = statuses[item.token].filename;
            if (statuses[item.token].file_size) item.file_size = statuses[item.token].file_size;
          }
        });

        saveLocalData();
        renderCurrentTab();
      })
      .catch(err => {
        console.warn("Could not sync live statuses:", err);
      });
  }

  function updateCountdowns() {
    let updated = false;

    uploadItems.forEach(item => {
      if (item.live_status === "active" && typeof item.remaining_seconds === "number" && item.remaining_seconds > 0) {
        item.remaining_seconds -= 1;
        if (item.remaining_seconds <= 0) {
          item.live_status = "expired";
          updated = true;
        }
        const el = document.getElementById(`timer-upload-${item.token}`);
        if (el) {
          el.innerHTML = `${SVG_CLOCK}${formatRemaining(item.remaining_seconds)} remaining`;
        }
      }
    });

    viewItems.forEach(item => {
      if (item.live_status === "active" && typeof item.remaining_seconds === "number" && item.remaining_seconds > 0) {
        item.remaining_seconds -= 1;
        if (item.remaining_seconds <= 0) {
          item.live_status = "expired";
          updated = true;
        }
        const el = document.getElementById(`timer-view-${item.token}`);
        if (el) {
          el.innerHTML = `${SVG_CLOCK}${formatRemaining(item.remaining_seconds)} remaining`;
        }
      }
    });

    if (updated) {
      renderCurrentTab();
    }
  }

  window.copyShareLink = function (url, btnId) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(() => {
        const btn = document.getElementById(btnId);
        if (btn) {
          const oldText = btn.textContent;
          btn.textContent = "COPIED!";
          setTimeout(() => { btn.textContent = oldText; }, 1500);
        }
      });
    } else {
      prompt("Share link:", url);
    }
  };

  window.promptRevoke = function (token, filename) {
    pendingRevokeToken = token;
    const modal = document.getElementById("revoke-modal");
    const nameEl = document.getElementById("modal-filename");
    if (nameEl) nameEl.textContent = filename;
    if (modal) modal.style.display = "flex";
  };

  window.closeRevokeModal = function () {
    pendingRevokeToken = null;
    const modal = document.getElementById("revoke-modal");
    if (modal) modal.style.display = "none";
  };

  function executeRevoke() {
    if (!pendingRevokeToken) return;
    const token = pendingRevokeToken;
    const btn = document.getElementById("confirm-revoke-btn");
    if (btn) {
      btn.textContent = "PURGING...";
      btn.disabled = true;
    }

    fetch(`/api/files/${token}/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCsrfToken()
      }
    })
      .then(res => res.json())
      .then(data => {
        if (btn) {
          btn.textContent = "YES, PURGE NOW";
          btn.disabled = false;
        }
        closeRevokeModal();

        // Update local item
        const item = uploadItems.find(u => u.token === token);
        if (item) {
          item.live_status = "deleted";
          item.status = "deleted";
          item.remaining_seconds = 0;
        }
        const vItem = viewItems.find(v => v.token === token);
        if (vItem) {
          vItem.live_status = "deleted";
          vItem.status = "deleted";
          vItem.remaining_seconds = 0;
        }

        saveLocalData();
        renderCurrentTab();
      })
      .catch(err => {
        alert("Failed to revoke file. Please check connection.");
        if (btn) {
          btn.textContent = "YES, PURGE NOW";
          btn.disabled = false;
        }
        closeRevokeModal();
      });
  }

  window.removeUploadRecord = function (token) {
    uploadItems = uploadItems.filter(u => u.token !== token);
    saveLocalData();
    renderCurrentTab();
  };

  window.clearUploadHistory = function () {
    if (confirm("Clear local upload history on this browser? (Note: active files on the server will still remain valid until 12 hours or revoked)")) {
      uploadItems = [];
      saveLocalData();
      renderCurrentTab();
    }
  };

  window.removeViewRecord = function (token) {
    viewItems = viewItems.filter(v => v.token !== token);
    saveLocalData();
    renderCurrentTab();
  };

  window.clearViewHistory = function () {
    if (confirm("Clear all viewed files from this browser's history?")) {
      viewItems = [];
      saveLocalData();
      renderCurrentTab();
    }
  };

  function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
  }
})();

