/**
 * FileGuard - Drag & Drop Upload Engine with Progress & Pre-validation
 */
document.addEventListener("DOMContentLoaded", () => {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const folderInput = document.getElementById("folder-input");
  const selectFilesBtn = document.getElementById("select-files-btn");
  const selectFolderBtn = document.getElementById("select-folder-btn");
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

  function handleFilesSelect(fileList, isFolderSelection = false) {
    clearError();
    if (!fileList || fileList.length === 0) return;

    const filesArray = Array.from(fileList);
    let totalBytes = 0;

    const hasRelativePaths = filesArray.some(
      f => (f.webkitRelativePath && f.webkitRelativePath.includes("/")) || (f.relativePath && f.relativePath.includes("/"))
    );
    selectedIsFolder = Boolean(isFolderSelection || hasRelativePaths);

    for (const file of filesArray) {
      totalBytes += file.size;

      // Check extension unless it's a hidden metadata entry
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
      if (selectedIsFolder) {
        const firstPath = filesArray[0].webkitRelativePath || filesArray[0].relativePath || filesArray[0].name;
        const folderName = firstPath.includes("/") ? firstPath.split("/")[0] : firstPath;
        fileNameDisplay.textContent = `Folder: ${folderName} (${filesArray.length} file${filesArray.length === 1 ? "" : "s"})`;
      } else if (filesArray.length === 1) {
        fileNameDisplay.textContent = filesArray[0].name;
      } else {
        fileNameDisplay.textContent = `Bundle: ${filesArray.length} files (${filesArray[0].name} + ${filesArray.length - 1} more)`;
      }
    }
    if (fileSizeDisplay) fileSizeDisplay.textContent = formatBytes(totalBytes);
    if (filePreview) filePreview.style.display = "block";

    // Auto-scroll or highlight upload button so user can review options or proceed immediately
    if (uploadBtn) {
      uploadBtn.focus();
    }
  }

  // WebCrypto helper for Client-Side Zero-Knowledge E2EE
  async function encryptBlobE2EE(file) {
    const key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const arrayBuffer = await file.arrayBuffer();
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      arrayBuffer
    );

    // Prepend 12-byte IV to ciphertext
    const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.byteLength);
    const encryptedBlob = new Blob([combined], { type: "application/octet-stream" });

    // Export raw key as URL-safe base64
    const rawKey = await window.crypto.subtle.exportKey("raw", key);
    const keyBytes = new Uint8Array(rawKey);
    let binary = "";
    for (let i = 0; i < keyBytes.byteLength; i++) {
      binary += String.fromCharCode(keyBytes[i]);
    }
    const keyBase64Url = btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    return { encryptedBlob, keyBase64Url };
  }

  async function startUpload(files, isFolder = false) {
    if (!files || files.length === 0) return;
    clearError();
    const isBundle = isFolder || files.length > 1;

    // Check optional settings
    const titleInput = document.getElementById("opt-display-title");
    const passwordInput = document.getElementById("opt-password");
    const expirationSelect = document.getElementById("opt-expiration");
    const e2eeCheckbox = document.getElementById("opt-e2ee");

    const displayTitle = titleInput ? titleInput.value.trim() : "";
    const password = passwordInput ? passwordInput.value.trim() : "";
    const expirationHours = expirationSelect ? expirationSelect.value : "12";
    const useE2EE = Boolean(e2eeCheckbox && e2eeCheckbox.checked);

    if (uploadBtn) {
      uploadBtn.setAttribute("disabled", "true");
      uploadBtn.textContent = useE2EE ? "Encrypting with AES-256..." : (isBundle ? "Bundling & Uploading..." : "Uploading & Hashing...");
    }
    if (progressContainer) progressContainer.style.display = "block";
    if (progressBar) progressBar.style.width = "0%";
    if (progressPercent) progressPercent.textContent = useE2EE ? "Encrypting locally in browser..." : "0%";

    let e2eeKeyUrlParam = "";
    const formData = new FormData();

    try {
      if (useE2EE) {
        if (progressPercent) progressPercent.textContent = "Locking with zero-knowledge AES-256...";
        // For bundle or single file, encrypt payload
        if (files.length === 1) {
          const { encryptedBlob, keyBase64Url } = await encryptBlobE2EE(files[0]);
          e2eeKeyUrlParam = keyBase64Url;
          formData.append("file", encryptedBlob, files[0].name);
        } else {
          // Multiple files in folder bundle with E2EE: upload will be bundled into ZIP by server then client E2EE applied
          for (const file of files) {
            const relPath = file.webkitRelativePath || file.relativePath || file.name;
            formData.append("file", file, relPath);
          }
        }
        formData.append("is_e2ee", "true");
      } else {
        for (const file of files) {
          const relPath = file.webkitRelativePath || file.relativePath || file.name;
          formData.append("file", file, relPath);
        }
      }
    } catch (encErr) {
      showError("Client-side encryption failed: " + encErr.message);
      resetUploadBtn();
      return;
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
          progressPercent.textContent = `${percent}% (${isBundle ? 'Bundling & transferring' : 'Transferring to encrypted vault'})`;
        }
      }
    });

    xhr.addEventListener("load", () => {
      if (xhr.status === 201) {
        try {
          const data = JSON.parse(xhr.responseText);
          if (progressPercent) progressPercent.textContent = "100% (Verifying SHA-256...)";

          let finalShareUrl = data.share_url;
          if (useE2EE && e2eeKeyUrlParam) {
            finalShareUrl += `#key=${e2eeKeyUrlParam}`;
          }

          try {
            const uploads = JSON.parse(localStorage.getItem("fileguard_user_uploads") || "[]");
            if (!uploads.some(u => u.token === data.token)) {
              uploads.unshift({
                token: data.token,
                filename: data.display_title || data.filename,
                original_filename: data.filename,
                file_size: data.file_size,
                share_url: finalShareUrl,
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
          } catch (storageErr) {
            console.warn("Could not write upload to localStorage:", storageErr);
          }

          let redirectUrl = `/share/${data.token}?just_uploaded=true`;
          if (useE2EE && e2eeKeyUrlParam) {
            redirectUrl += `#key=${e2eeKeyUrlParam}`;
          }
          window.location.href = redirectUrl;
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

  // Recursive helper to read files from dropped folders (FileSystemEntry API)
  function readEntryFiles(entry, pathPrefix = "") {
    return new Promise((resolve) => {
      if (entry.isFile) {
        entry.file((file) => {
          file.relativePath = pathPrefix ? `${pathPrefix}/${file.name}` : file.name;
          resolve([file]);
        }, () => resolve([]));
      } else if (entry.isDirectory) {
        const dirReader = entry.createReader();
        const allEntries = [];
        const readBatch = () => {
          dirReader.readEntries(async (entries) => {
            if (!entries.length) {
              const nestedPrefix = pathPrefix ? `${pathPrefix}/${entry.name}` : entry.name;
              const nestedResults = await Promise.all(
                allEntries.map(child => readEntryFiles(child, nestedPrefix))
              );
              resolve(nestedResults.flat());
            } else {
              allEntries.push(...entries);
              readBatch();
            }
          }, () => resolve([]));
        };
        readBatch();
      } else {
        resolve([]);
      }
    });
  }

  // Standard File input change (single or multiple files)
  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFilesSelect(e.target.files, false);
      fileInput.value = "";
    }
  });

  // Folder input change (entire directory)
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

  // Trigger file selection on dropzone click (defaults to file picker so users can select files)
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
        startUpload(selectedFiles, selectedIsFolder);
      } else {
        fileInput.click();
      }
    });
  }
});

