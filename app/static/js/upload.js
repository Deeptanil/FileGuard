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

  let selectedFiles = [];

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

  function handleFilesSelect(fileList) {
    clearError();
    if (!fileList || fileList.length === 0) return;

    const filesArray = Array.from(fileList);
    let totalBytes = 0;

    for (const file of filesArray) {
      totalBytes += file.size;

      // Check extension unless it's a folder or bundle entry
      const nameParts = file.name.split(".");
      const ext = nameParts.length > 1 ? nameParts.pop().toLowerCase() : "";
      if (ext && !ALLOWED_EXTS.includes(ext)) {
        showError(`Disallowed file extension '.${ext}' in '${file.name}'. Allowed types: ${ALLOWED_EXTS.join(", ")}`);
        return;
      }
    }

    if (totalBytes > MAX_SIZE_BYTES) {
      showError(`Total size (${formatBytes(totalBytes)}) exceeds the 100 MB limit.`);
      return;
    }

    selectedFiles = filesArray;

    if (fileNameDisplay) {
      if (filesArray.length === 1) {
        fileNameDisplay.textContent = filesArray[0].name;
      } else {
        fileNameDisplay.textContent = `Bundle: ${filesArray.length} items (${filesArray[0].name} + ${filesArray.length - 1} more)`;
      }
    }
    if (fileSizeDisplay) fileSizeDisplay.textContent = formatBytes(totalBytes);
    if (filePreview) filePreview.style.display = "block";

    // Auto-upload immediately upon valid file selection
    startUpload(filesArray);
  }

  function startUpload(files) {
    if (!files || files.length === 0) return;
    clearError();
    if (uploadBtn) {
      uploadBtn.setAttribute("disabled", "true");
      uploadBtn.textContent = files.length > 1 ? "Bundling & Uploading..." : "Uploading & Hashing...";
    }
    if (progressContainer) progressContainer.style.display = "block";
    if (progressBar) progressBar.style.width = "0%";
    if (progressPercent) progressPercent.textContent = "0%";

    const formData = new FormData();
    for (const file of files) {
      formData.append("file", file);
    }

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
        if (progressPercent) {
          progressPercent.textContent = `${percent}% (${files.length > 1 ? 'Bundling folder & transferring' : 'Transferring to encrypted vault'})`;
        }
      }
    });

    xhr.addEventListener("load", () => {
      if (xhr.status === 201) {
        try {
          const data = JSON.parse(xhr.responseText);
          if (progressPercent) progressPercent.textContent = "100% (Verifying SHA-256...)";
          window.location.href = `/share/${data.token}?just_uploaded=true`;
        } catch (e) {
          showError("Unexpected response format from server.");
          resetUploadBtn();
        }
      } else {
        try {
          const errData = JSON.parse(xhr.responseText);
          showError(errData.error || "Upload failed. Please check file and try again.");
        } catch (e) {
          showError(`Upload error (HTTP ${xhr.status})`);
        }
        resetUploadBtn();
      }
    });

    xhr.addEventListener("error", () => {
      showError("Network connection error during file upload.");
      resetUploadBtn();
    });

    xhr.send(formData);
  }

  function resetUploadBtn() {
    if (uploadBtn) {
      uploadBtn.removeAttribute("disabled");
      uploadBtn.textContent = "Try Uploading Again";
    }
    if (progressContainer) progressContainer.style.display = "none";
  }

  // File input change
  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFilesSelect(e.target.files);
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
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFilesSelect(e.dataTransfer.files);
    }
  });

  // Trigger file selection on dropzone click (prevent re-triggering if user clicks inside preview/btn)
  dropzone.addEventListener("click", (e) => {
    if (e.target.closest("#file-preview") || e.target.closest("button") || e.target.closest("a") || e.target.closest(".folder-select-btn")) {
      return;
    }
    fileInput.click();
  });

  if (uploadBtn) {
    uploadBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (selectedFiles.length > 0) {
        startUpload(selectedFiles);
      } else {
        fileInput.click();
      }
    });
  }
});

