export const addonBundle = String.raw`(function () {
  const UI_ID = "bsky-alt-addon";
  if (document.getElementById(UI_ID)) {
    return;
  }

  const DB_NAME = "bsky-alt-addon";
  const DB_VERSION = 2;
  const STORE_ACCOUNTS = "accounts";
  const STORE_META = "meta";
  const CHECK_PLAINTEXT = "vault-check-v1";
  const META_KEY_VAULT = "vault";
  const META_KEY_DEVICE_UNLOCK = "device-unlock";
  const PBKDF2_ITERATIONS = 150000;
  const MAX_ATTACHMENTS = 4;
  const POST_CHARACTER_LIMIT = 300;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function openDb() {
    return new Promise(function (resolve, reject) {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = function (event) {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_ACCOUNTS)) {
          db.createObjectStore(STORE_ACCOUNTS, { keyPath: "did" });
        }
        if (!db.objectStoreNames.contains(STORE_META)) {
          db.createObjectStore(STORE_META, { keyPath: "key" });
        }
        if (event.oldVersion && event.oldVersion < 2) {
          const tx = request.transaction;
          if (tx) {
            const store = tx.objectStore(STORE_ACCOUNTS);
            store.openCursor().onsuccess = function (cursorEvent) {
              const cursor = cursorEvent.target.result;
              if (cursor) {
                const value = cursor.value;
                if (value && !value.payload) {
                  cursor.update({ did: value.did, legacy: value });
                }
                cursor.continue();
              }
            };
          }
        }
      };
      request.onsuccess = function () {
        resolve(request.result);
      };
      request.onerror = function () {
        reject(request.error || new Error("IndexedDB open failed"));
      };
    });
  }

  function withStore(storeNames, mode, executor) {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        const tx = db.transaction(storeNames, mode);
        const stores = {};
        if (Array.isArray(storeNames)) {
          storeNames.forEach(function (name) {
            stores[name] = tx.objectStore(name);
          });
        } else {
          stores[storeNames] = tx.objectStore(storeNames);
        }
        let done = false;
        function finish(value) {
          done = true;
          resolve(value);
        }
        try {
          executor(stores, finish, reject);
        } catch (error) {
          tx.abort();
          reject(error);
          return;
        }
        tx.oncomplete = function () {
          db.close();
          if (!done) {
            resolve(undefined);
          }
        };
        tx.onabort = function () {
          db.close();
          reject(tx.error || new Error("Transaction aborted"));
        };
        tx.onerror = function () {
          db.close();
          reject(tx.error || new Error("Transaction error"));
        };
      });
    });
  }

  function loadVaultMeta() {
    return withStore(STORE_META, "readonly", function (stores, resolve, reject) {
      const request = stores[STORE_META].get(META_KEY_VAULT);
      request.onsuccess = function () {
        resolve(request.result ? request.result.value : null);
      };
      request.onerror = function () {
        reject(request.error || new Error("Failed to read vault meta"));
      };
    });
  }

  function saveVaultMeta(meta) {
    return withStore(STORE_META, "readwrite", function (stores) {
      stores[STORE_META].put({ key: META_KEY_VAULT, value: meta });
    });
  }

  function clearVaultMeta() {
    return withStore(STORE_META, "readwrite", function (stores) {
      stores[STORE_META].delete(META_KEY_VAULT);
    });
  }

  function loadDeviceUnlockConfig() {
    return withStore(STORE_META, "readonly", function (stores, resolve, reject) {
      const request = stores[STORE_META].get(META_KEY_DEVICE_UNLOCK);
      request.onsuccess = function () {
        resolve(request.result ? request.result.value : null);
      };
      request.onerror = function () {
        reject(request.error || new Error("Failed to read device unlock config"));
      };
    });
  }

  function saveDeviceUnlockConfig(config) {
    return withStore(STORE_META, "readwrite", function (stores) {
      stores[STORE_META].put({ key: META_KEY_DEVICE_UNLOCK, value: config });
    });
  }

  function clearDeviceUnlockConfig() {
    return withStore(STORE_META, "readwrite", function (stores) {
      stores[STORE_META].delete(META_KEY_DEVICE_UNLOCK);
    });
  }

  function loadAccountEntries() {
    return withStore(STORE_ACCOUNTS, "readonly", function (stores, resolve, reject) {
      const request = stores[STORE_ACCOUNTS].getAll();
      request.onsuccess = function () {
        resolve(request.result || []);
      };
      request.onerror = function () {
        reject(request.error || new Error("Failed to read accounts"));
      };
    });
  }

  function putAccountEntry(entry) {
    return withStore(STORE_ACCOUNTS, "readwrite", function (stores) {
      stores[STORE_ACCOUNTS].put(entry);
    });
  }

  function deleteAccountEntry(did) {
    return withStore(STORE_ACCOUNTS, "readwrite", function (stores) {
      stores[STORE_ACCOUNTS].delete(did);
    });
  }

  function clearAccountStore() {
    return withStore(STORE_ACCOUNTS, "readwrite", function (stores) {
      stores[STORE_ACCOUNTS].clear();
    });
  }

  function deriveKey(passphrase, salt) {
    return crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]).then(function (baseKey) {
      return crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
    });
  }

  function encryptText(key, text) {
    const iv = randomBytes(12);
    const data = encoder.encode(text);
    return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, data).then(function (cipher) {
      return { iv: bufferToBase64(iv.buffer), payload: bufferToBase64(cipher) };
    });
  }

  function decryptText(key, payload) {
    if (!payload || !payload.iv || !payload.payload) {
      return Promise.reject(new Error("Invalid encrypted payload"));
    }
    const iv = new Uint8Array(base64ToBuffer(payload.iv));
    const data = base64ToBuffer(payload.payload);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, data).then(function (plain) {
      return decoder.decode(new Uint8Array(plain));
    });
  }

  function encryptAccount(key, account) {
    return encryptText(key, JSON.stringify(account)).then(function (payload) {
      return { did: account.did, iv: payload.iv, payload: payload.payload };
    });
  }

  function decryptAccount(key, entry) {
    if (entry.payload && entry.iv) {
      return decryptText(key, { iv: entry.iv, payload: entry.payload }).then(function (text) {
        return { account: JSON.parse(text), legacy: false };
      });
    }
    if (entry.legacy) {
      return Promise.resolve({ account: entry.legacy, legacy: true });
    }
    return Promise.reject(new Error("Unknown account entry"));
  }

  function normalizeService(input) {
    let service = (input || "").trim();
    if (!service) {
      return "https://bsky.social";
    }
    if (!/^https?:\/\//i.test(service)) {
      service = "https://" + service;
    }
    return service.replace(/\/$/, "");
  }

  let vaultKey = null;
  let vaultMeta = null;
  let deviceUnlockConfig = null;
  let knownAccounts = [];
  const draftsByDid = {};
  const handleDidCache = {};
  let activeAccountDid = null;
  let currentAttachments = [];
  let postingInProgress = false;
  let composer = null;
  let quoteInput = null;
  let replyInput = null;
  let postButton = null;
  let deviceUnlockButton = null;
  let attachmentsPreview = null;
  let addImageButton = null;
  let fileInput = null;
  let charCounter = null;

  function isUnlocked() {
    return !!vaultKey;
  }

  function lockVault() {
    vaultKey = null;
    vaultMeta = null;
    knownAccounts = [];
    activeAccountDid = null;
    currentAttachments = [];
    postingInProgress = false;
    Object.keys(draftsByDid).forEach(function (key) {
      delete draftsByDid[key];
    });
    populateAccounts([]);
    resetComposerState();
    setUnlockedState(false);
  }

  function verifyVaultKey(key, meta) {
    if (!meta || !meta.check) {
      return Promise.resolve();
    }
    return decryptText(key, meta.check).then(function (text) {
      if (text !== CHECK_PLAINTEXT) {
        throw new Error("Invalid passphrase");
      }
    });
  }

  function promptForPassphrase(message, confirm) {
    const first = window.prompt(message);
    if (!first) {
      return null;
    }
    if (!confirm) {
      return first;
    }
    const second = window.prompt("Confirm passphrase");
    if (second === null) {
      return null;
    }
    if (first !== second) {
      window.alert("Passphrases do not match");
      return null;
    }
    return first;
  }

  function unlockVaultWithExisting(meta) {
    const passphrase = promptForPassphrase("Enter vault passphrase", false);
    if (!passphrase) {
      return Promise.reject(new Error("Passphrase required"));
    }
    const salt = new Uint8Array(base64ToBuffer(meta.salt));
    return deriveKey(passphrase, salt).then(function (key) {
      return verifyVaultKey(key, meta).then(function () {
        vaultKey = key;
        vaultMeta = meta;
        setUnlockedState(true);
        setStatus("Vault unlocked", "success");
        return undefined;
      });
    }).catch(function (error) {
      vaultKey = null;
      throw error;
    });
  }

  function unlockVaultFirstTime(meta) {
    const passphrase = promptForPassphrase("Create a vault passphrase", true);
    if (!passphrase) {
      return Promise.reject(new Error("Passphrase required"));
    }
    const salt = randomBytes(16);
    return deriveKey(passphrase, salt).then(function (key) {
      return encryptText(key, CHECK_PLAINTEXT).then(function (check) {
        vaultKey = key;
        vaultMeta = { salt: bufferToBase64(salt.buffer), check: check };
        return saveVaultMeta(vaultMeta).then(function () {
          setUnlockedState(true);
          setStatus("Vault created", "success");
        });
      });
    });
  }

  function unlockVault() {
    return loadVaultMeta().then(function (meta) {
      if (!meta || !meta.salt) {
        return unlockVaultFirstTime(meta);
      }
      return unlockVaultWithExisting(meta);
    }).then(function () {
      if (isUnlocked()) {
        return reloadAccounts();
      }
      return undefined;
    });
  }

  function changePassphrase() {
    if (!isUnlocked()) {
      return Promise.reject(new Error("Unlock first"));
    }
    const next = promptForPassphrase("Enter new vault passphrase", true);
    if (!next) {
      return Promise.reject(new Error("Passphrase required"));
    }
    const newSalt = randomBytes(16);
    return listAccounts().then(function (accounts) {
      return deriveKey(next, newSalt).then(function (newKey) {
        return Promise.all(accounts.map(function (account) {
          return encryptAccount(newKey, account).then(function (entry) {
            return putAccountEntry(entry);
          });
        })).then(function () {
          return encryptText(newKey, CHECK_PLAINTEXT);
        }).then(function (check) {
          vaultKey = newKey;
          vaultMeta = { salt: bufferToBase64(newSalt.buffer), check: check };
          return saveVaultMeta(vaultMeta);
        });
      });
    }).then(function () {
      if (!deviceUnlockConfig) {
        setStatus("Passphrase updated", "success");
        return;
      }
      return rewrapDeviceUnlockKey().then(function () {
        setStatus("Passphrase updated", "success");
      }).catch(function (error) {
        console.warn("Failed to refresh device unlock", error);
        return clearDeviceUnlockConfig().catch(function () {
        }).then(function () {
          deviceUnlockConfig = null;
          updateDeviceUnlockButton();
          setStatus("Passphrase updated. Re-enable device unlock to continue.", "info");
        });
      });
    });
  }

  function listAccounts() {
    if (!isUnlocked()) {
      return Promise.resolve([]);
    }
    return loadAccountEntries().then(function (entries) {
      return Promise.all(entries.map(function (entry) {
        return decryptAccount(vaultKey, entry);
      })).then(function (results) {
        const accounts = results.map(function (result) {
          return result.account;
        });
        const migrations = results.filter(function (result) {
          return result.legacy;
        }).map(function (result) {
          return saveAccount(result.account);
        });
        if (migrations.length) {
          return Promise.all(migrations).then(function () {
            return accounts;
          });
        }
        return accounts;
      });
    }).then(function (accounts) {
      knownAccounts = accounts;
      return accounts;
    });
  }

  function reloadAccounts() {
    if (!isUnlocked()) {
      populateAccounts([]);
      return Promise.resolve();
    }
    return listAccounts().then(function (accounts) {
      populateAccounts(accounts);
    }).catch(function (error) {
      console.error("Failed to load accounts", error);
      setStatus("Failed to load accounts", "error");
    });
  }

  function saveAccount(account) {
    if (!isUnlocked()) {
      return Promise.reject(new Error("Unlock vault first"));
    }
    return encryptAccount(vaultKey, account).then(function (entry) {
      return putAccountEntry(entry).then(function () {
        return account;
      });
    });
  }

  function deleteAccount(did) {
    if (!isUnlocked()) {
      return Promise.reject(new Error("Unlock vault first"));
    }
    return deleteAccountEntry(did);
  }

  function clearVault() {
    return Promise.all([clearAccountStore(), clearVaultMeta(), clearDeviceUnlockConfig()]).then(function () {
      deviceUnlockConfig = null;
      lockVault();
      updateDeviceUnlockButton();
    });
  }

  function refreshDeviceUnlockConfig() {
    return loadDeviceUnlockConfig().then(function (config) {
      deviceUnlockConfig = config;
      updateDeviceUnlockButton();
      return config;
    });
  }

  function updateDeviceUnlockButton() {
    if (!deviceUnlockButton) {
      return;
    }
    if (isUnlocked()) {
      deviceUnlockButton.disabled = false;
      deviceUnlockButton.textContent = deviceUnlockConfig ? "Disable device unlock" : "Enable device unlock";
    } else {
      deviceUnlockButton.textContent = deviceUnlockConfig ? "Unlock with device" : "Device unlock unavailable";
      deviceUnlockButton.disabled = !deviceUnlockConfig;
    }
  }

  function resetComposerState() {
    if (composer) {
      composer.value = "";
    }
    if (quoteInput) {
      quoteInput.value = "";
    }
    if (replyInput) {
      replyInput.value = "";
    }
    currentAttachments = [];
    renderAttachments();
    updateCharacterCount();
  }

  function rememberCurrentDraft() {
    if (!activeAccountDid || !isUnlocked()) {
      return;
    }
    draftsByDid[activeAccountDid] = {
      text: composer ? composer.value : "",
      quote: quoteInput ? quoteInput.value : "",
      reply: replyInput ? replyInput.value : "",
      attachments: currentAttachments.slice()
    };
  }

  function restoreDraftForDid(did) {
    const draft = draftsByDid[did] || null;
    if (composer) {
      composer.value = draft && draft.text ? draft.text : "";
    }
    if (quoteInput) {
      quoteInput.value = draft && draft.quote ? draft.quote : "";
    }
    if (replyInput) {
      replyInput.value = draft && draft.reply ? draft.reply : "";
    }
    currentAttachments = draft && draft.attachments ? draft.attachments.slice() : [];
    renderAttachments();
    updateCharacterCount();
  }

  function persistDraftForCurrent() {
    if (!activeAccountDid || !isUnlocked()) {
      return;
    }
    draftsByDid[activeAccountDid] = {
      text: composer.value,
      quote: quoteInput.value,
      reply: replyInput.value,
      attachments: currentAttachments.slice()
    };
  }

  function removeAttachmentAt(index) {
    if (index < 0 || index >= currentAttachments.length) {
      return;
    }
    const removed = currentAttachments.splice(index, 1)[0];
    if (removed && removed.previewUrl) {
      try {
        URL.revokeObjectURL(removed.previewUrl);
      } catch (error) {
      }
    }
    renderAttachments();
    persistDraftForCurrent();
  }

  function addAttachmentsFromFiles(files) {
    if (!files || !files.length) {
      return;
    }
    let limited = false;
    Array.prototype.forEach.call(files, function (file) {
      if (currentAttachments.length >= MAX_ATTACHMENTS) {
        limited = true;
        return;
      }
      if (!file.type || file.type.indexOf("image") !== 0) {
        setStatus("Only image uploads are supported", "error");
        return;
      }
      const previewUrl = URL.createObjectURL(file);
      currentAttachments.push({ file: file, previewUrl: previewUrl, alt: "" });
    });
    if (limited) {
      setStatus("Maximum images attached", "error");
    }
    renderAttachments();
    persistDraftForCurrent();
  }

  function updateAttachmentControls() {
    const unlocked = isUnlocked();
    const disabled = !unlocked || currentAttachments.length >= MAX_ATTACHMENTS || postingInProgress;
    if (addImageButton) {
      addImageButton.disabled = disabled;
    }
    if (fileInput) {
      fileInput.disabled = disabled;
    }
    if (attachmentsPreview) {
      attachmentsPreview.style.display = currentAttachments.length ? "flex" : "none";
    }
  }

  function renderAttachments() {
    if (!attachmentsPreview) {
      return;
    }
    attachmentsPreview.innerHTML = "";
    if (!currentAttachments.length) {
      updateAttachmentControls();
      return;
    }
    currentAttachments.forEach(function (attachment, index) {
      const item = document.createElement("div");
      item.style.position = "relative";
      item.style.display = "flex";
      item.style.flexDirection = "column";
      item.style.gap = "0.35rem";
      item.style.padding = "0.4rem";
      item.style.borderRadius = "0.75rem";
      item.style.background = "rgba(255,255,255,0.08)";
      item.style.width = "120px";

      const img = document.createElement("img");
      img.src = attachment.previewUrl;
      img.alt = attachment.alt || "";
      img.style.width = "100%";
      img.style.height = "80px";
      img.style.objectFit = "cover";
      img.style.borderRadius = "0.6rem";

      const altInput = document.createElement("input");
      altInput.type = "text";
      altInput.placeholder = "Alt text";
      altInput.value = attachment.alt || "";
      altInput.style.padding = "0.35rem";
      altInput.style.borderRadius = "0.5rem";
      altInput.style.border = "1px solid rgba(255,255,255,0.15)";
      altInput.style.background = "rgba(12, 14, 23, 0.6)";
      altInput.style.color = "white";
      altInput.style.fontSize = "0.75rem";
      altInput.disabled = !isUnlocked();
      altInput.addEventListener("input", function () {
        attachment.alt = altInput.value;
        persistDraftForCurrent();
      });

      const removeButton = document.createElement("button");
      removeButton.type = "button";
      removeButton.textContent = "Remove";
      removeButton.style.padding = "0.3rem";
      removeButton.style.borderRadius = "0.5rem";
      removeButton.style.border = "1px solid rgba(255,255,255,0.2)";
      removeButton.style.background = "rgba(255,255,255,0.1)";
      removeButton.style.color = "white";
      removeButton.style.cursor = "pointer";
      removeButton.style.fontSize = "0.75rem";
      removeButton.disabled = !isUnlocked();
      removeButton.addEventListener("click", function () {
        removeAttachmentAt(index);
      });

      item.appendChild(img);
      item.appendChild(altInput);
      item.appendChild(removeButton);
      attachmentsPreview.appendChild(item);
    });
    updateAttachmentControls();
  }

  function updateCharacterCount() {
    if (!charCounter) {
      return;
    }
    const textLength = composer ? composer.value.length : 0;
    charCounter.textContent = textLength + " / " + POST_CHARACTER_LIMIT;
    charCounter.style.color = textLength > POST_CHARACTER_LIMIT ? "#fca5a5" : "rgba(255,255,255,0.75)";
  }

  function ensureWebAuthnAvailable() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error("WebAuthn is not available in this browser");
    }
  }

  function wrapVaultKeyWithDevice(deviceKeyBytes, credentialIdBase64) {
    return crypto.subtle.exportKey("raw", vaultKey).then(function (rawKey) {
      return crypto.subtle.importKey("raw", deviceKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]).then(function (deviceKey) {
        const iv = randomBytes(12);
        return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, deviceKey, rawKey).then(function (wrapped) {
          const config = {
            credentialId: credentialIdBase64 || (deviceUnlockConfig && deviceUnlockConfig.credentialId) || null,
            iv: bufferToBase64(iv.buffer),
            wrappedKey: bufferToBase64(wrapped)
          };
          if (!config.credentialId) {
            throw new Error("Missing credential identifier");
          }
          deviceUnlockConfig = config;
          return saveDeviceUnlockConfig(config).then(function () {
            updateDeviceUnlockButton();
          });
        });
      });
    });
  }

  function unwrapVaultKeyWithDevice(deviceKeyBytes) {
    if (!deviceUnlockConfig) {
      return Promise.reject(new Error("Device unlock not configured"));
    }
    const iv = new Uint8Array(base64ToBuffer(deviceUnlockConfig.iv));
    const wrapped = base64ToBuffer(deviceUnlockConfig.wrappedKey);
    return crypto.subtle.importKey("raw", deviceKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]).then(function (deviceKey) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, deviceKey, wrapped);
    }).then(function (rawKey) {
      return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    });
  }

  function performDeviceAssertion() {
    ensureWebAuthnAvailable();
    if (!deviceUnlockConfig || !deviceUnlockConfig.credentialId) {
      return Promise.reject(new Error("Device unlock not configured"));
    }
    const challenge = randomBytes(32);
    const allowId = new Uint8Array(base64ToBuffer(deviceUnlockConfig.credentialId));
    return navigator.credentials.get({
      publicKey: {
        challenge: challenge,
        allowCredentials: [
          {
            type: "public-key",
            id: allowId
          }
        ],
        userVerification: "preferred",
        timeout: 60000
      }
    }).then(function (assertion) {
      if (!assertion || !assertion.response || !assertion.response.userHandle) {
        throw new Error("Device did not provide user handle");
      }
      return new Uint8Array(assertion.response.userHandle);
    });
  }

  function unlockWithDevice() {
    ensureWebAuthnAvailable();
    return refreshDeviceUnlockConfig().then(function (config) {
      if (!config) {
        throw new Error("Device unlock not configured");
      }
      return performDeviceAssertion();
    }).then(function (deviceKeyBytes) {
      return unwrapVaultKeyWithDevice(deviceKeyBytes);
    }).then(function (key) {
      return loadVaultMeta().then(function (meta) {
        if (!meta) {
          throw new Error("Vault not initialized");
        }
        vaultMeta = meta;
        return verifyVaultKey(key, meta).then(function () {
          vaultKey = key;
          setUnlockedState(true);
          setStatus("Vault unlocked", "success");
          return reloadAccounts();
        });
      });
    });
  }

  function enableDeviceUnlock() {
    if (!isUnlocked()) {
      return Promise.reject(new Error("Unlock vault first"));
    }
    ensureWebAuthnAvailable();
    const challenge = randomBytes(32);
    const userId = randomBytes(32);
    return navigator.credentials.create({
      publicKey: {
        challenge: challenge,
        rp: { name: "Alt Composer" },
        user: {
          id: userId,
          name: "alts",
          displayName: "Alt vault"
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
        timeout: 60000,
        attestation: "none"
      }
    }).then(function (credential) {
      if (!credential || !credential.rawId) {
        throw new Error("Device registration failed");
      }
      const credentialIdBase64 = bufferToBase64(credential.rawId);
      return wrapVaultKeyWithDevice(userId, credentialIdBase64).then(function () {
        setStatus("Device unlock enabled", "success");
      });
    });
  }

  function disableDeviceUnlock() {
    return clearDeviceUnlockConfig().then(function () {
      deviceUnlockConfig = null;
      updateDeviceUnlockButton();
      setStatus("Device unlock disabled", "success");
    });
  }

  function rewrapDeviceUnlockKey() {
    if (!deviceUnlockConfig) {
      return Promise.resolve();
    }
    return performDeviceAssertion().then(function (deviceKeyBytes) {
      return wrapVaultKeyWithDevice(deviceKeyBytes, deviceUnlockConfig.credentialId);
    });
  }

  function parsePostReference(input) {
    const trimmed = (input || "").trim();
    if (!trimmed) {
      return null;
    }
    if (trimmed.startsWith("at://")) {
      return trimmed;
    }
    try {
      const parsed = new URL(trimmed);
      const parts = parsed.pathname.split("/").filter(Boolean);
      const profileIndex = parts.indexOf("profile");
      const postIndex = parts.indexOf("post");
      if (profileIndex !== -1 && postIndex !== -1 && postIndex === profileIndex + 2) {
        const handle = parts[profileIndex + 1];
        const rkey = parts[postIndex + 1];
        if (handle && rkey) {
          return "at://" + handle + "/app.bsky.feed.post/" + rkey;
        }
      }
    } catch (error) {
      throw new Error("Invalid post URL");
    }
    throw new Error("Unsupported post reference");
  }

  function fetchPostDetails(atUri) {
    const endpoint = "https://public.api.bsky.app/xrpc/app.bsky.feed.getPosts?" + new URLSearchParams({ uris: atUri }).toString();
    return fetch(endpoint, { headers: { accept: "application/json" } }).then(function (response) {
      if (!response.ok) {
        throw new Error("Failed to resolve post");
      }
      return response.json();
    }).then(function (payload) {
      const post = payload && Array.isArray(payload.posts) ? payload.posts[0] : null;
      if (!post || !post.uri || !post.cid) {
        throw new Error("Post not found");
      }
      return post;
    });
  }

  function resolveQuote(input) {
    return Promise.resolve().then(function () {
      const atUri = parsePostReference(input);
      if (!atUri) {
        return null;
      }
      return fetchPostDetails(atUri).then(function (post) {
        return { uri: post.uri, cid: post.cid };
      });
    });
  }

  function resolveReplyTarget(input) {
    return Promise.resolve().then(function () {
      const atUri = parsePostReference(input);
      if (!atUri) {
        return null;
      }
      return fetchPostDetails(atUri).then(function (post) {
        const parent = { uri: post.uri, cid: post.cid };
        const rootCandidate = post.reply && post.reply.root ? post.reply.root : null;
        const root = rootCandidate && rootCandidate.uri && rootCandidate.cid ? { uri: rootCandidate.uri, cid: rootCandidate.cid } : parent;
        return { parent: parent, root: root };
      });
    });
  }

  function resolveHandleToDid(handle) {
    const normalized = (handle || "").toLowerCase();
    if (!normalized) {
      return Promise.reject(new Error("Handle required"));
    }
    if (handleDidCache[normalized]) {
      return Promise.resolve(handleDidCache[normalized]);
    }
    const endpoint = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?" + new URLSearchParams({ actor: normalized }).toString();
    return fetch(endpoint, { headers: { accept: "application/json" } }).then(function (response) {
      if (!response.ok) {
        throw new Error("Handle lookup failed");
      }
      return response.json();
    }).then(function (profile) {
      if (!profile || !profile.did) {
        throw new Error("Handle not found");
      }
      handleDidCache[normalized] = profile.did;
      return profile.did;
    });
  }

  function buildFacets(text) {
    if (!text) {
      return Promise.resolve([]);
    }
    const facets = [];
    const mentionMatches = [];
    const mentionRegex = /@([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)/gi;
    let match;
    while ((match = mentionRegex.exec(text)) !== null) {
      const start = match.index;
      if (start > 0) {
        const prev = text.charAt(start - 1);
        if (prev && /[\w.@-]/.test(prev)) {
          continue;
        }
      }
      const handle = match[1];
      const end = start + match[0].length;
      mentionMatches.push({ handle: handle, start: start, end: end });
    }

    const urlRegex = /https?:\/\/[^\s]+/gi;
    const urlMatches = [];
    while ((match = urlRegex.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;
      urlMatches.push({ url: match[0], start: start, end: end });
    }

    function byteRange(start, end) {
      const prefix = encoder.encode(text.slice(0, start)).length;
      const size = encoder.encode(text.slice(start, end)).length;
      return { byteStart: prefix, byteEnd: prefix + size };
    }

    const uniqueHandles = {};
    mentionMatches.forEach(function (mention) {
      const key = mention.handle.toLowerCase();
      if (!uniqueHandles[key]) {
        uniqueHandles[key] = [];
      }
      uniqueHandles[key].push(mention);
    });

    const handlePromises = Object.keys(uniqueHandles).map(function (handle) {
      return resolveHandleToDid(handle).then(function (did) {
        uniqueHandles[handle].forEach(function (mention) {
          const range = byteRange(mention.start, mention.end);
          facets.push({
            index: range,
            features: [
              {
                $type: "app.bsky.richtext.facet#mention",
                did: did
              }
            ]
          });
        });
      }).catch(function (error) {
        console.warn("Mention resolution failed", handle, error);
      });
    });

    urlMatches.forEach(function (match) {
      const range = byteRange(match.start, match.end);
      facets.push({
        index: range,
        features: [
          {
            $type: "app.bsky.richtext.facet#link",
            uri: match.url
          }
        ]
      });
    });

    return Promise.all(handlePromises).then(function () {
      return facets;
    });
  }

  function createElement(tag, options) {
    const element = document.createElement(tag);
    if (options) {
      if (options.className) {
        element.className = options.className;
      }
      if (options.text) {
        element.textContent = options.text;
      }
      if (options.type) {
        element.type = options.type;
      }
      if (options.placeholder) {
        element.placeholder = options.placeholder;
      }
      if (options.rows) {
        element.rows = options.rows;
      }
    }
    return element;
  }

  const root = document.createElement("div");
  root.id = UI_ID;
  root.style.position = "fixed";
  root.style.right = "1.25rem";
  root.style.bottom = "1.25rem";
  root.style.width = "340px";
  root.style.maxWidth = "90vw";
  root.style.background = "rgba(22, 24, 35, 0.95)";
  root.style.color = "white";
  root.style.padding = "1rem";
  root.style.borderRadius = "1rem";
  root.style.fontFamily = "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
  root.style.boxShadow = "0 20px 45px rgba(0, 0, 0, 0.35)";
  root.style.zIndex = "2147483647";
  root.style.backdropFilter = "blur(10px)";
  root.style.display = "flex";
  root.style.flexDirection = "column";
  root.style.gap = "0.75rem";

  const heading = document.createElement("div");
  heading.style.display = "flex";
  heading.style.justifyContent = "space-between";
  heading.style.alignItems = "center";
  const title = document.createElement("strong");
  title.textContent = "Alt composer";
  title.style.fontSize = "1rem";
  const collapseButton = createElement("button", { text: "−" });
  collapseButton.style.background = "transparent";
  collapseButton.style.border = "none";
  collapseButton.style.color = "white";
  collapseButton.style.cursor = "pointer";
  collapseButton.style.fontSize = "1.25rem";
  collapseButton.style.lineHeight = "1";
  collapseButton.setAttribute("aria-expanded", "true");

  heading.appendChild(title);
  heading.appendChild(collapseButton);

  const body = document.createElement("div");
  body.style.display = "flex";
  body.style.flexDirection = "column";
  body.style.gap = "0.75rem";

  const securityNote = document.createElement("div");
  securityNote.textContent = "Use Bluesky app passwords only. Never store your main password.";
  securityNote.style.fontSize = "0.75rem";
  securityNote.style.opacity = "0.75";

  const securityActions = document.createElement("div");
  securityActions.style.display = "flex";
  securityActions.style.gap = "0.5rem";

  function createActionButton(text) {
    const button = createElement("button", { text: text });
    button.style.flex = "1";
    button.style.padding = "0.45rem";
    button.style.borderRadius = "0.75rem";
    button.style.border = "1px solid rgba(255,255,255,0.2)";
    button.style.background = "rgba(255,255,255,0.08)";
    button.style.color = "white";
    button.style.cursor = "pointer";
    button.style.fontSize = "0.85rem";
    button.style.fontWeight = "500";
    button.style.transition = "background 0.2s";
    button.addEventListener("mouseenter", function () {
      button.style.background = "rgba(255,255,255,0.15)";
    });
    button.addEventListener("mouseleave", function () {
      button.style.background = "rgba(255,255,255,0.08)";
    });
    return button;
  }

  const unlockButton = createActionButton("Unlock vault");
  const lockButton = createActionButton("Lock now");
  const clearButton = createActionButton("Clear vault");
  deviceUnlockButton = createActionButton("Unlock with device");

  securityActions.appendChild(unlockButton);
  securityActions.appendChild(lockButton);
  securityActions.appendChild(deviceUnlockButton);
  securityActions.appendChild(clearButton);

  const accountRow = document.createElement("div");
  accountRow.style.display = "flex";
  accountRow.style.flexDirection = "column";
  accountRow.style.gap = "0.5rem";

  const accountLabel = document.createElement("label");
  accountLabel.textContent = "Account";
  accountLabel.style.fontSize = "0.875rem";
  accountLabel.style.opacity = "0.85";

  const accountSelect = document.createElement("select");
  accountSelect.style.width = "100%";
  accountSelect.style.padding = "0.5rem";
  accountSelect.style.borderRadius = "0.75rem";
  accountSelect.style.border = "1px solid rgba(255,255,255,0.2)";
  accountSelect.style.background = "rgba(255,255,255,0.08)";
  accountSelect.style.color = "white";
  accountSelect.style.fontSize = "0.95rem";

  const accountActions = document.createElement("div");
  accountActions.style.display = "flex";
  accountActions.style.gap = "0.5rem";

  accountSelect.addEventListener("change", function () {
    if (!isUnlocked()) {
      return;
    }
    rememberCurrentDraft();
    activeAccountDid = accountSelect.value || null;
    if (activeAccountDid) {
      restoreDraftForDid(activeAccountDid);
    } else {
      resetComposerState();
    }
  });

  const addAccountButton = createActionButton("Add account");
  const refreshTokenButton = createActionButton("Refresh token");
  const removeAccountButton = createActionButton("Remove");

  accountActions.appendChild(addAccountButton);
  accountActions.appendChild(refreshTokenButton);
  accountActions.appendChild(removeAccountButton);

  accountRow.appendChild(accountLabel);
  accountRow.appendChild(accountSelect);
  accountRow.appendChild(accountActions);

  composer = createElement("textarea", { rows: 4 });
  composer.placeholder = "Compose as your selected account...";
  composer.style.width = "100%";
  composer.style.padding = "0.75rem";
  composer.style.borderRadius = "0.75rem";
  composer.style.border = "1px solid rgba(255,255,255,0.2)";
  composer.style.background = "rgba(255,255,255,0.08)";
  composer.style.color = "white";
  composer.style.fontSize = "0.95rem";
  composer.style.resize = "vertical";

  charCounter = document.createElement("div");
  charCounter.style.display = "flex";
  charCounter.style.justifyContent = "flex-end";
  charCounter.style.fontSize = "0.75rem";
  charCounter.style.opacity = "0.75";

  attachmentsPreview = document.createElement("div");
  attachmentsPreview.style.display = "none";
  attachmentsPreview.style.flexWrap = "wrap";
  attachmentsPreview.style.gap = "0.5rem";

  const attachmentActions = document.createElement("div");
  attachmentActions.style.display = "flex";
  attachmentActions.style.justifyContent = "space-between";
  attachmentActions.style.alignItems = "center";

  addImageButton = createActionButton("Add images");
  addImageButton.style.flex = "0";
  addImageButton.style.alignSelf = "flex-start";

  attachmentActions.appendChild(addImageButton);

  fileInput = document.createElement("input");
  fileInput.type = "file";
  fileInput.accept = "image/*";
  fileInput.multiple = true;
  fileInput.style.display = "none";

  quoteInput = createElement("input");
  quoteInput.placeholder = "Quote URL (optional)";
  quoteInput.style.width = "100%";
  quoteInput.style.padding = "0.6rem";
  quoteInput.style.borderRadius = "0.75rem";
  quoteInput.style.border = "1px solid rgba(255,255,255,0.2)";
  quoteInput.style.background = "rgba(255,255,255,0.08)";
  quoteInput.style.color = "white";
  quoteInput.style.fontSize = "0.9rem";

  replyInput = createElement("input");
  replyInput.placeholder = "Reply to URL (optional)";
  replyInput.style.width = "100%";
  replyInput.style.padding = "0.6rem";
  replyInput.style.borderRadius = "0.75rem";
  replyInput.style.border = "1px solid rgba(255,255,255,0.2)";
  replyInput.style.background = "rgba(255,255,255,0.08)";
  replyInput.style.color = "white";
  replyInput.style.fontSize = "0.9rem";

  postButton = createActionButton("Post");
  postButton.style.padding = "0.75rem";
  postButton.style.borderRadius = "0.75rem";
  postButton.style.border = "none";
  postButton.style.background = "linear-gradient(135deg, #4f46e5, #6366f1)";
  postButton.style.color = "white";
  postButton.style.fontSize = "1rem";
  postButton.style.fontWeight = "600";

  const addAccountForm = document.createElement("form");
  addAccountForm.style.display = "none";
  addAccountForm.style.flexDirection = "column";
  addAccountForm.style.gap = "0.5rem";
  addAccountForm.style.padding = "0.75rem";
  addAccountForm.style.borderRadius = "0.75rem";
  addAccountForm.style.background = "rgba(255,255,255,0.08)";

  function createFormInput(type, placeholder, autocomplete) {
    const input = document.createElement("input");
    input.type = type;
    input.placeholder = placeholder;
    input.autocomplete = autocomplete || "off";
    input.required = type !== "text" || placeholder.toLowerCase().indexOf("optional") === -1;
    input.style.width = "100%";
    input.style.padding = "0.6rem";
    input.style.borderRadius = "0.6rem";
    input.style.border = "1px solid rgba(0,0,0,0.15)";
    input.style.fontSize = "0.9rem";
    return input;
  }

  const handleInput = createFormInput("text", "Handle (e.g. myalt.bsky.social)", "username");
  const appPasswordInput = createFormInput("password", "App password", "current-password");
  const serviceInput = createFormInput("text", "PDS service (https://... optional)", "url");
  serviceInput.required = false;

  const formActions = document.createElement("div");
  formActions.style.display = "flex";
  formActions.style.gap = "0.5rem";

  const saveAccountButton = createActionButton("Save");
  const cancelAccountButton = createActionButton("Cancel");

  formActions.appendChild(saveAccountButton);
  formActions.appendChild(cancelAccountButton);

  addAccountForm.appendChild(handleInput);
  addAccountForm.appendChild(appPasswordInput);
  addAccountForm.appendChild(serviceInput);
  addAccountForm.appendChild(formActions);

  const status = document.createElement("div");
  status.style.fontSize = "0.85rem";
  status.style.minHeight = "1.25rem";

  body.appendChild(securityNote);
  body.appendChild(securityActions);
  body.appendChild(accountRow);
  body.appendChild(composer);
  body.appendChild(charCounter);
  body.appendChild(attachmentsPreview);
  body.appendChild(attachmentActions);
  body.appendChild(replyInput);
  body.appendChild(quoteInput);
  body.appendChild(postButton);
  body.appendChild(addAccountForm);
  body.appendChild(status);

  root.appendChild(heading);
  root.appendChild(body);
  root.appendChild(fileInput);
  document.body.appendChild(root);

  function setStatus(message, tone) {
    status.textContent = message || "";
    status.style.color = tone === "error" ? "#fca5a5" : tone === "success" ? "#bbf7d0" : "rgba(255,255,255,0.85)";
  }

  function setBusy(isBusy) {
    postingInProgress = isBusy;
    postButton.disabled = isBusy || !isUnlocked();
    postButton.style.opacity = postButton.disabled ? "0.6" : "1";
    updateAttachmentControls();
  }

  function populateAccounts(accounts) {
    rememberCurrentDraft();
    accountSelect.innerHTML = "";
    if (!accounts.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = isUnlocked() ? "Add an account to start" : "Unlock vault to load accounts";
      accountSelect.appendChild(option);
      accountSelect.disabled = true;
      refreshTokenButton.disabled = true;
      removeAccountButton.disabled = true;
    } else {
      accountSelect.disabled = false;
      refreshTokenButton.disabled = false;
      removeAccountButton.disabled = false;
      accounts.forEach(function (account) {
        const option = document.createElement("option");
        option.value = account.did;
        option.textContent = account.handle;
        option.dataset.service = account.service;
        accountSelect.appendChild(option);
      });
      const selected = accounts.find(function (account) {
        return account.did === accountSelect.value;
      });
      accountSelect.value = selected ? selected.did : accounts[0].did;
    }
    if (accountSelect.disabled || !accountSelect.value) {
      activeAccountDid = null;
      resetComposerState();
    } else {
      activeAccountDid = accountSelect.value;
      restoreDraftForDid(activeAccountDid);
    }
  }

  function setUnlockedState(unlocked) {
    addAccountButton.disabled = !unlocked;
    refreshTokenButton.disabled = !unlocked;
    removeAccountButton.disabled = !unlocked;
    composer.disabled = !unlocked;
    quoteInput.disabled = !unlocked;
    replyInput.disabled = !unlocked;
    postButton.disabled = !unlocked;
    unlockButton.textContent = unlocked ? "Change passphrase" : "Unlock vault";
    lockButton.disabled = !unlocked;
    updateAttachmentControls();
    updateDeviceUnlockButton();
    if (!unlocked) {
      setStatus("Vault locked. Unlock to compose.", "info");
    }
  }

  function currentAccount() {
    const did = accountSelect.value;
    for (let i = 0; i < knownAccounts.length; i += 1) {
      if (knownAccounts[i].did === did) {
        return knownAccounts[i];
      }
    }
    return null;
  }

  function toggleForm(visible) {
    addAccountForm.style.display = visible ? "flex" : "none";
    if (visible) {
      handleInput.focus();
    } else {
      if (typeof addAccountForm.reset === "function") {
        addAccountForm.reset();
      }
      handleInput.value = "";
      appPasswordInput.value = "";
      serviceInput.value = "";
    }
  }

  collapseButton.addEventListener("click", function () {
    const expanded = collapseButton.getAttribute("aria-expanded") === "true";
    collapseButton.setAttribute("aria-expanded", expanded ? "false" : "true");
    collapseButton.textContent = expanded ? "+" : "−";
    body.style.display = expanded ? "none" : "flex";
  });

  unlockButton.addEventListener("click", function () {
    if (isUnlocked()) {
      changePassphrase().catch(function (error) {
        console.error("Passphrase update failed", error);
        setStatus(error.message || "Failed to update passphrase", "error");
      });
      return;
    }
    unlockVault().catch(function (error) {
      console.error("Unlock failed", error);
      setStatus(error.message || "Failed to unlock", "error");
    });
  });

  deviceUnlockButton.addEventListener("click", function () {
    if (isUnlocked()) {
      if (deviceUnlockConfig) {
        if (!window.confirm("Disable device unlock for this browser?")) {
          return;
        }
        disableDeviceUnlock().catch(function (error) {
          console.error("Disable device unlock failed", error);
          setStatus(error.message || "Failed to disable device unlock", "error");
        });
        return;
      }
      enableDeviceUnlock().catch(function (error) {
        console.error("Enable device unlock failed", error);
        setStatus(error.message || "Failed to enable device unlock", "error");
      });
      return;
    }
    unlockWithDevice().catch(function (error) {
      console.error("Device unlock failed", error);
      setStatus(error.message || "Device unlock failed", "error");
    });
  });

  lockButton.addEventListener("click", function () {
    lockVault();
  });

  clearButton.addEventListener("click", function () {
    if (!window.confirm("Clear all stored accounts?")) {
      return;
    }
    clearVault().then(function () {
      setStatus("Vault cleared", "success");
    }).catch(function (error) {
      console.error("Clear vault failed", error);
      setStatus(error.message || "Failed to clear vault", "error");
    });
  });

  addAccountButton.addEventListener("click", function () {
    if (!isUnlocked()) {
      setStatus("Unlock the vault first", "error");
      return;
    }
    const isVisible = addAccountForm.style.display !== "none";
    toggleForm(!isVisible);
  });

  cancelAccountButton.addEventListener("click", function (event) {
    event.preventDefault();
    toggleForm(false);
  });

  addAccountForm.addEventListener("submit", function (event) {
    event.preventDefault();
  });

  composer.addEventListener("input", function () {
    updateCharacterCount();
    persistDraftForCurrent();
  });

  quoteInput.addEventListener("input", function () {
    persistDraftForCurrent();
  });

  replyInput.addEventListener("input", function () {
    persistDraftForCurrent();
  });

  addImageButton.addEventListener("click", function () {
    if (!isUnlocked()) {
      setStatus("Unlock the vault first", "error");
      return;
    }
    if (currentAttachments.length >= MAX_ATTACHMENTS) {
      setStatus("Maximum images attached", "error");
      return;
    }
    fileInput.click();
  });

  fileInput.addEventListener("change", function () {
    if (!isUnlocked()) {
      fileInput.value = "";
      return;
    }
    addAttachmentsFromFiles(fileInput.files);
    fileInput.value = "";
  });

  function ensureUnlocked() {
    if (isUnlocked()) {
      return Promise.resolve();
    }
    setStatus("Unlock the vault first", "error");
    return Promise.reject(new Error("Vault locked"));
  }

  function createSession(service, identifier, password) {
    return fetch(service + "/xrpc/com.atproto.server.createSession", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: identifier, password: password })
    }).then(function (response) {
      if (!response.ok) {
        return response.json().catch(function () {
          return {};
        }).then(function (error) {
          const message = error && (error.message || error.errorDescription || error.error) ? error.message || error.errorDescription || error.error : "Session creation failed";
          throw new Error(message);
        });
      }
      return response.json();
    });
  }

  function refreshSession(service, refreshJwt) {
    return fetch(service + "/xrpc/com.atproto.server.refreshSession", {
      method: "POST",
      headers: { "content-type": "application/json", Authorization: "Bearer " + refreshJwt }
    }).then(function (response) {
      if (!response.ok) {
        return response.json().catch(function () {
          return {};
        }).then(function (error) {
          const message = error && (error.message || error.errorDescription || error.error) ? error.message || error.errorDescription || error.error : "Refresh failed";
          throw new Error(message);
        });
      }
      return response.json();
    });
  }

  function createRecord(service, accessJwt, did, record) {
    return fetch(service + "/xrpc/com.atproto.repo.createRecord", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        Authorization: "Bearer " + accessJwt
      },
      body: JSON.stringify({
        repo: did,
        collection: "app.bsky.feed.post",
        record: record
      })
    });
  }

  function resolveQuote(quoteInput) {
    const trimmed = (quoteInput || "").trim();
    if (!trimmed) {
      return Promise.resolve(null);
    }
    let atUri = null;
    if (trimmed.startsWith("at://")) {
      atUri = trimmed;
    } else {
      try {
        const parsed = new URL(trimmed);
        const parts = parsed.pathname.split("/").filter(Boolean);
        const profileIndex = parts.indexOf("profile");
        const postIndex = parts.indexOf("post");
        if (profileIndex !== -1 && postIndex !== -1 && postIndex === profileIndex + 2) {
          const handle = parts[profileIndex + 1];
          const rkey = parts[postIndex + 1];
          if (handle && rkey) {
            atUri = "at://" + handle + "/app.bsky.feed.post/" + rkey;
          }
        }
      } catch (error) {
        return Promise.reject(new Error("Invalid quote URL"));
      }
    }
    if (!atUri) {
      return Promise.reject(new Error("Unsupported quote URL"));
    }
    const endpoint = "https://public.api.bsky.app/xrpc/app.bsky.feed.getPosts?" + new URLSearchParams({ uris: atUri }).toString();
    return fetch(endpoint, {
      headers: { "accept": "application/json" }
    }).then(function (response) {
      if (!response.ok) {
        throw new Error("Failed to resolve quote");
      }
      return response.json();
    }).then(function (payload) {
      const post = payload && Array.isArray(payload.posts) ? payload.posts[0] : null;
      if (!post || !post.uri || !post.cid) {
        throw new Error("Quote target not found");
      }
      return {
        uri: post.uri,
        cid: post.cid
      };
    });
  }

  function refreshAccountSession(account) {
    return refreshSession(account.service, account.refreshJwt).then(function (session) {
      account.accessJwt = session.accessJwt;
      account.refreshJwt = session.refreshJwt;
      account.lastRefreshedAt = new Date().toISOString();
      return saveAccount(account).then(function () {
        return account;
      });
    });
  }

  function sendPost(account, text, quoteTarget, replyTarget, facets, images) {
    const now = new Date().toISOString();
    const record = {
      $type: "app.bsky.feed.post",
      text: text,
      createdAt: now
    };
    if (facets && facets.length) {
      record.facets = facets;
    }
    if (replyTarget) {
      record.reply = replyTarget;
    }
    if (images && images.length) {
      const imageEmbed = {
        $type: "app.bsky.embed.images",
        images: images.map(function (image) {
          return {
            image: image.blob,
            alt: image.alt || ""
          };
        })
      };
      if (quoteTarget) {
        record.embed = {
          $type: "app.bsky.embed.recordWithMedia",
          record: {
            $type: "app.bsky.embed.record",
            record: quoteTarget
          },
          media: imageEmbed
        };
      } else {
        record.embed = imageEmbed;
      }
    } else if (quoteTarget) {
      record.embed = {
        $type: "app.bsky.embed.record",
        record: quoteTarget
      };
    }
    function attempt(hasRetried) {
      return createRecord(account.service, account.accessJwt, account.did, record).then(function (response) {
        if (response.status === 401 && !hasRetried) {
          return refreshAccountSession(account).then(function () {
            return attempt(true);
          });
        }
        return response;
      });
    }
    return attempt(false).then(function (response) {
      if (!response.ok) {
        return response.json().catch(function () {
          return {};
        }).then(function (error) {
          const message = error && (error.message || error.errorDescription || error.error) ? error.message || error.errorDescription || error.error : "Post failed";
          throw new Error(message);
        });
      }
      return response.json();
    });
  }

  function uploadSingleImage(account, attachment, hasRetried) {
    const endpoint = account.service + "/xrpc/com.atproto.repo.uploadBlob";
    return fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + account.accessJwt,
        "content-type": attachment.file.type || "application/octet-stream",
        accept: "application/json"
      },
      body: attachment.file
    }).then(function (response) {
      if (response.status === 401 && !hasRetried) {
        return refreshAccountSession(account).then(function () {
          return uploadSingleImage(account, attachment, true);
        });
      }
      if (!response.ok) {
        return response.json().catch(function () {
          return {};
        }).then(function (error) {
          const message = error && (error.message || error.errorDescription || error.error) ? error.message || error.errorDescription || error.error : "Image upload failed";
          throw new Error(message);
        });
      }
      return response.json();
    }).then(function (payload) {
      if (!payload || !payload.blob) {
        throw new Error("Image upload failed");
      }
      return { blob: payload.blob, alt: attachment.alt || "" };
    });
  }

  function uploadImages(account, attachments) {
    if (!attachments || !attachments.length) {
      return Promise.resolve([]);
    }
    const results = [];
    return attachments.reduce(function (chain, attachment) {
      return chain.then(function () {
        return uploadSingleImage(account, attachment, false).then(function (result) {
          results.push(result);
        });
      });
    }, Promise.resolve()).then(function () {
      return results;
    });
  }

  saveAccountButton.addEventListener("click", function (event) {
    event.preventDefault();
    ensureUnlocked().then(function () {
      const handle = handleInput.value.trim();
      const password = appPasswordInput.value.trim();
      const service = normalizeService(serviceInput.value);
      if (!handle || !password) {
        setStatus("Handle and app password required", "error");
        return;
      }
      setStatus("Creating session...", "info");
      setBusy(true);
      createSession(service, handle, password).then(function (session) {
        if (!session || !session.did) {
          throw new Error("Session missing DID");
        }
        const account = {
          did: session.did,
          handle: session.handle || handle,
          service: service,
          accessJwt: session.accessJwt,
          refreshJwt: session.refreshJwt,
          lastRefreshedAt: new Date().toISOString()
        };
        return saveAccount(account).then(function () {
          toggleForm(false);
          setStatus("Account saved", "success");
          return reloadAccounts();
        });
      }).catch(function (error) {
        console.error("Failed to add account", error);
        setStatus(error.message || "Failed to add account", "error");
      }).finally(function () {
        setBusy(false);
      });
    }).catch(function () {
    });
  });

  refreshTokenButton.addEventListener("click", function () {
    ensureUnlocked().then(function () {
      const account = currentAccount();
      if (!account) {
        setStatus("No account selected", "error");
        return;
      }
      setStatus("Refreshing session...", "info");
      setBusy(true);
      refreshSession(account.service, account.refreshJwt).then(function (session) {
        account.accessJwt = session.accessJwt;
        account.refreshJwt = session.refreshJwt;
        account.lastRefreshedAt = new Date().toISOString();
        return saveAccount(account).then(function () {
          setStatus("Session refreshed", "success");
        });
      }).catch(function (error) {
        console.error("Refresh failed", error);
        setStatus(error.message || "Failed to refresh", "error");
      }).finally(function () {
        setBusy(false);
      });
    }).catch(function () {
    });
  });

  removeAccountButton.addEventListener("click", function () {
    ensureUnlocked().then(function () {
      const account = currentAccount();
      if (!account) {
        setStatus("No account to remove", "error");
        return;
      }
      if (!window.confirm("Remove " + account.handle + "?")) {
        return;
      }
      deleteAccount(account.did).then(function () {
        setStatus("Account removed", "success");
        return reloadAccounts();
      }).catch(function (error) {
        console.error("Removal failed", error);
        setStatus("Failed to remove account", "error");
      });
    }).catch(function () {
    });
  });

  postButton.addEventListener("click", function () {
    ensureUnlocked().then(function () {
      const account = currentAccount();
      const text = composer.value.trim();
      const quoteUrl = quoteInput.value.trim();
      const replyUrl = replyInput.value.trim();
      if (!account) {
        setStatus("Select an account", "error");
        return;
      }
      if (!text) {
        setStatus("Write something to post", "error");
        composer.focus();
        return;
      }
      if (text.length > POST_CHARACTER_LIMIT) {
        setStatus("Post exceeds " + POST_CHARACTER_LIMIT + " characters", "error");
        return;
      }
      setBusy(true);
      setStatus("Posting...", "info");
      Promise.all([
        quoteUrl ? resolveQuote(quoteUrl) : Promise.resolve(null),
        replyUrl ? resolveReplyTarget(replyUrl) : Promise.resolve(null),
        buildFacets(text),
        uploadImages(account, currentAttachments)
      ]).then(function (results) {
        const quoteTarget = results[0];
        const replyTarget = results[1];
        const facets = results[2];
        const images = results[3];
        return sendPost(account, text, quoteTarget, replyTarget, facets, images);
      }).then(function () {
        setBusy(false);
        setStatus("Posted!", "success");
        composer.value = "";
        quoteInput.value = "";
        replyInput.value = "";
        currentAttachments.forEach(function (attachment) {
          if (attachment && attachment.previewUrl) {
            try {
              URL.revokeObjectURL(attachment.previewUrl);
            } catch (error) {
            }
          }
        });
        currentAttachments = [];
        renderAttachments();
        updateCharacterCount();
        persistDraftForCurrent();
      }).catch(function (error) {
        console.error("Post failed", error);
        setBusy(false);
        setStatus(error.message || "Failed to post", "error");
      });
    }).catch(function () {
    });
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "c" && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const target = event.target;
      if (!target || !(target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT" || target.isContentEditable)) {
        event.preventDefault();
        composer.focus();
      }
    }
  });

  refreshDeviceUnlockConfig().catch(function (error) {
    console.warn("Failed to load device unlock config", error);
  });

  lockVault();
})();`;
