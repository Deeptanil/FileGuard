/**
 * FileGuard - Drag & Drop Upload Engine with Progress & Pre-validation
 */
document.addEventListener("DOMContentLoaded", () => {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const uploadForm = document.getElementById("upload-form");
  const filePreview = document.getElementById("file-preview");
  const fileNameDisplay = document.getElementById("file-name-display");
  const fileSizeDisplay = document.getElementById("file-size-display");
  const progressContainer = document.getElementById("progress-container");
  const progressBar = document.getElementById("progress-bar");
  const progressPercent = document.getElementById("progress-percent");
  const uploadBtn = document.getElementById("upload-btn");
  const errorContainer = document.getElementById("upload-error");

  if (!dropzone || !fileInput) return;

  const MAX_SIZE_MB = parseInt(dropzone.dataset.maxMb || "100", 10);
  const MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024;
  const ALLOWED_EXTS = (dropzone.dataset.allowedExts || "pdf,png,jpg,jpeg,txt,csv,docx,xlsx,pptx,zip")
    .split(",")
    .map(e => e.trim().toLowerCase());

  let selectedFile = null;

  function showError(msg) {
    if (errorContainer) {
      errorContainer.textContent = msg;
      errorContainer.style.display = "block";
    }
  }

  function clearError() {
    if (errorContainer) {
      errorContainer.textContent = "";
      errorContainer.style.display = "none";
    }
  }

  function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function handleFileSelect(file) {
    clearError();
    if (!file) return;

    // Pre-validation 1: File size
    if (file.size > MAX_SIZE_BYTES) {
      showError(`File size (${formatBytes(file.size)}) exceeds the maximum allowed limit of ${MAX_SIZE_MB} MB.`);
      return;
    }

    // Pre-validation 2: File extension
    const nameParts = file.name.split(".");
    const ext = nameParts.length > 1 ? nameParts.pop().toLowerCase() : "";
    if (!ALLOWED_EXTS.includes(ext)) {
      showError(`Disallowed file extension '.${ext}'. Allowed types: ${ALLOWED_EXTS.join(", ")}`);
      return;
    }

    selectedFile = file;

    if (fileNameDisplay) fileNameDisplay.textContent = file.name;
    if (fileSizeDisplay) fileSizeDisplay.textContent = formatBytes(file.size);
    if (filePreview) filePreview.style.display = "block";
    if (uploadBtn) uploadBtn.removeAttribute("disabled");
  }

  // File input change
  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0]);
    }
  });

  // Drag and drop events
  ["dragenter", "dragover"].forEach(evt => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(evt => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  });

  dropzone.addEventListener("click", () => {
    fileInput.click();
  });

  // Perform upload
  if (uploadBtn) {
    uploadBtn.addEventListener("click", (e) => {
      e.preventDefault();
      if (!selectedFile) {
        showError("Please select a file to upload.");
        return;
      }

      clearError();
      uploadBtn.setAttribute("disabled", "true");
      if (progressContainer) progressContainer.style.display = "block";

      const formData = new FormData();
      formData.append("file", selectedFile);

      const csrfMeta = document.querySelector('meta[name="csrf-token"]');
      const csrfToken = csrfMeta ? csrfMeta.content : "";
      if (csrfToken) {
        formData.append("csrf_token", csrfToken);
      }

      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/files", true);
      if (csrfToken) {
        xhr.setRequestHeader("X-CSRFToken", csrfToken);
      }

      xhr.upload.addEventListener("progress", (evt) => {
        if (evt.lengthComputable) {
          const percent = Math.round((evt.loaded / evt.total) * 100);
          if (progressBar) progressBar.style.width = `${percent}%`;
          if (progressPercent) progressPercent.textContent = `${percent}%`;
        }
      });

      xhr.addEventListener("load", () => {
        if (xhr.status === 201) {
          try {
            const data = JSON.parse(xhr.responseText);
            // Redirect directly to the 8-digit sharing page
            window.location.href = `/share/${data.token}?just_uploaded=true`;
          } catch (e) {
            showError("Unexpected response format from server.");
            uploadBtn.removeAttribute("disabled");
          }
        } else {
          try {
            const errData = JSON.parse(xhr.responseText);
            showError(errData.error || "Upload failed. Please check file and try again.");
          } catch (e) {
            showError(`Upload error (HTTP ${xhr.status})`);
          }
          uploadBtn.removeAttribute("disabled");
          if (progressContainer) progressContainer.style.display = "none";
        }
      });

      xhr.addEventListener("error", () => {
        showError("Network connection error during file upload.");
        uploadBtn.removeAttribute("disabled");
        if (progressContainer) progressContainer.style.display = "none";
      });

      xhr.send(formData);
    });
  }
});

