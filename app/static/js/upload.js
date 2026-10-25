/**
 * FileGuard - Drag & Drop Upload Engine with In-Place Yellow Bundle Preview & Multi-Step Accumulation
 */
document.addEventListener("DOMContentLoaded", () => {
  const dropzone = document.getElementById("dropzone");
  const dropzoneInitial = document.getElementById("dropzone-initial");
  const dropzoneSelected = document.getElementById("dropzone-selected");
  const fileInput = document.getElementById("file-input");
  const folderInput = document.getElementById("folder-input");
  const selectFilesBtn = document.getElementById("select-files-btn");
  const selectFolderBtn = document.getElementById("select-folder-btn");
  const addMoreFilesBtn = document.getElementById("add-more-files-btn");
  const addMoreFolderBtn = document.getElementById("add-more-folder-btn");
  const clearFilesBtn = document.getElementById("clear-files-btn");
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
  let selectedIsFolder = false;

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

  function getBundleSummaryName(filesArray) {
    if (!filesArray || filesArray.length === 0) return "";
    if (filesArray.length === 1) {
      return filesArray[0].name;
    }
    if (filesArray.length === 2) {
      return `${filesArray[0].name} + 1 more file`;
    }
    return `${filesArray[0].name} + ${filesArray.length - 1} more files`;
  }

  function updateDropzoneView() {
    if (selectedFiles.length === 0) {
      dropzone.classList.remove("has-files");
      if (dropzoneInitial) dropzoneInitial.style.display = "block";
      if (dropzoneSelected) dropzoneSelected.style.display = "none";
      return;
    }

    let totalBytes = 0;
    for (const f of selectedFiles) {
      totalBytes += f.size;
    }

    dropzone.classList.add("has-files");
    if (dropzoneInitial) dropzoneInitial.style.display = "none";
    if (dropzoneSelected) dropzoneSelected.style.display = "block";

    if (fileNameDisplay) {
      fileNameDisplay.textContent = getBundleSummaryName(selectedFiles);
    }
    if (fileSizeDisplay) {
      fileSizeDisplay.textContent = `${formatBytes(totalBytes)} • ${selectedFiles.length} ${selectedFiles.length === 1 ? "file" : "files"}`;
    }
  }

  function handleFilesSelect(fileList, isFolderSelection = false) {
    clearError();
    if (!fileList || fileList.length === 0) return;

    const incomingFiles = Array.from(fileList);
    const combinedFiles = [...selectedFiles, ...incomingFiles];
    let totalBytes = 0;

    const hasRelativePaths = combinedFiles.some(
      f => (f.webkitRelativePath && f.webkitRelativePath.includes("/")) || (f.relativePath && f.relativePath.includes("/"))
    );

    for (const file of combinedFiles) {
      totalBytes += file.size;

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

    selectedFiles = combinedFiles;
    selectedIsFolder = Boolean(selectedIsFolder || isFolderSelection || hasRelativePaths);
    updateDropzoneView();
  }

  function clearSelectedFiles() {
    selectedFiles = [];
    selectedIsFolder = false;
    clearError();
    updateDropzoneView();
  }

  async function startUpload(files, isFolder = false) {
    if (!files || files.length === 0) return;
    clearError();
    const isBundle = isFolder || files.length > 1;

    const titleInput = document.getElementById("opt-display-title");
    const passwordInput = document.getElementById("opt-password");
    const expirationSelect = document.getElementById("opt-expiration");

    let displayTitle = titleInput ? titleInput.value.trim() : "";
    if (!displayTitle && files.length > 1) {
      displayTitle = getBundleSummaryName(files);
    }

    const password = passwordInput ? passwordInput.value.trim() : "";
    const expirationHours = expirationSelect ? expirationSelect.value : "12";

    if (uploadBtn) {
      uploadBtn.setAttribute("disabled", "true");
      uploadBtn.textContent = "GENERATING SHAREABLE LINK...";
    }
    if (progressContainer) progressContainer.style.display = "block";
    if (progressBar) progressBar.style.width = "0%";
    if (progressPercent) {
      progressPercent.style.display = "block";
      progressPercent.textContent = "0%";
    }

    const formData = new FormData();
    for (const file of files) {
      const relPath = file.webkitRelativePath || file.relativePath || file.name;
      formData.append("file", file, relPath);
    }

    if (isFolder) {
      formData.append("is_folder", "true");
    }
    if (displayTitle) {
      formData.append("display_title", displayTitle);
    }
    if (password) {
      formData.append("password", password);
    }
    if (expirationHours) {
      formData.append("expiration_hours", expirationHours);
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
          progressPercent.textContent = `${percent}% (${isBundle ? "Bundling & uploading" : "Uploading"})`;
        }
      }
    });

    xhr.addEventListener("load", () => {
      if (xhr.status === 201) {
        try {
          const data = JSON.parse(xhr.responseText);
          if (progressPercent) progressPercent.textContent = "100% — Redirecting...";

          try {
            const uploads = JSON.parse(localStorage.getItem("fileguard_user_uploads") || "[]");
            if (!uploads.some(u => u.token === data.token)) {
              uploads.unshift({
                token: data.token,
                filename: data.display_title || data.filename,
                original_filename: data.filename,
                file_size: data.file_size,
                share_url: data.share_url,
                has_password: data.has_password,
                is_e2ee: data.is_e2ee,
                sha256: data.sha256_reference,
                uploaded_at: data.uploaded_at,
                expires_at: data.expires_at,
                is_bundle: Boolean(isBundle)
              });
              if (uploads.length > 100) uploads.length = 100;
              localStorage.setItem("fileguard_user_uploads", JSON.stringify(uploads));
            }
          } catch (storageErr) {}

          window.location.href = `/share/${data.token}?just_uploaded=true`;
        } catch (e) {
          showError("Unexpected response from server.");
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
      showError("Network error occurred during file upload.");
      resetUploadBtn();
    });

    xhr.send(formData);
  }

  function resetUploadBtn() {
    if (uploadBtn) {
      uploadBtn.removeAttribute("disabled");
      uploadBtn.textContent = "GET SHAREABLE LINK";
    }
    if (progressContainer) progressContainer.style.display = "none";
    if (progressPercent) progressPercent.style.display = "none";
  }

  async function readEntryFiles(entry, pathPrefix = "") {
    if (entry.isFile) {
      return new Promise((resolve) => {
        entry.file((file) => {
          file.relativePath = pathPrefix + file.name;
          resolve([file]);
        }, () => resolve([]));
      });
    } else if (entry.isDirectory) {
      const dirReader = entry.createReader();
      const entries = await new Promise((resolve) => {
        const allEntries = [];
        function readBatch() {
          dirReader.readEntries((batch) => {
            if (batch.length === 0) {
              resolve(allEntries);
            } else {
              allEntries.push(...batch);
              readBatch();
            }
          }, () => resolve(allEntries));
        }
        readBatch();
      });
      const nestedFiles = [];
      for (const child of entries) {
        const subFiles = await readEntryFiles(child, `${pathPrefix}${entry.name}/`);
        nestedFiles.push(...subFiles);
      }
      return nestedFiles;
    }
    return [];
  }

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFilesSelect(e.target.files, false);
      fileInput.value = "";
    }
  });

  if (folderInput) {
    folderInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files.length > 0) {
        handleFilesSelect(e.target.files, true);
        folderInput.value = "";
      }
    });
  }

  if (selectFilesBtn) {
    selectFilesBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      fileInput.click();
    });
  }

  if (selectFolderBtn && folderInput) {
    selectFolderBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      folderInput.click();
    });
  }

  if (addMoreFilesBtn) {
    addMoreFilesBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      fileInput.click();
    });
  }

  if (addMoreFolderBtn && folderInput) {
    addMoreFolderBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      folderInput.click();
    });
  }

  if (clearFilesBtn) {
    clearFilesBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      clearSelectedFiles();
    });
  }

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

  dropzone.addEventListener("drop", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove("dragover");

    const items = e.dataTransfer && e.dataTransfer.items ? Array.from(e.dataTransfer.items) : [];
    const entries = items
      .filter(item => item.kind === "file" && typeof item.webkitGetAsEntry === "function")
      .map(item => item.webkitGetAsEntry())
      .filter(Boolean);

    if (entries.length > 0 && entries.some(en => en.isDirectory)) {
      const results = await Promise.all(entries.map(en => readEntryFiles(en)));
      const extractedFiles = results.flat();
      if (extractedFiles.length > 0) {
        handleFilesSelect(extractedFiles, true);
      }
      return;
    }

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFilesSelect(e.dataTransfer.files, false);
    }
  });

  dropzone.addEventListener("click", (e) => {
    if (
      dropzone.classList.contains("has-files") ||
      e.target.closest("button") ||
      e.target.closest("a") ||
      e.target.closest("#dropzone-selected")
    ) {
      return;
    }
    fileInput.click();
  });

  if (uploadBtn) {
    uploadBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (selectedFiles.length > 0) {
        startUpload(selectedFiles, selectedIsFolder);
      } else {
        fileInput.click();
      }
    });
  }
});
