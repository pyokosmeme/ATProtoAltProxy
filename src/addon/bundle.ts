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
  const PBKDF2_ITERATIONS = 150000;

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
      const request = stores[STORE_META].get("vault");
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
      stores[STORE_META].put({ key: "vault", value: meta });
    });
  }

  function clearVaultMeta() {
    return withStore(STORE_META, "readwrite", function (stores) {
      stores[STORE_META].delete("vault");
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
        false,
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
  let knownAccounts = [];

  function isUnlocked() {
    return !!vaultKey;
  }

  function lockVault() {
    vaultKey = null;
    vaultMeta = null;
    knownAccounts = [];
    populateAccounts([]);
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
      setStatus("Passphrase updated", "success");
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
    return Promise.all([clearAccountStore(), clearVaultMeta()]).then(function () {
      lockVault();
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

  securityActions.appendChild(unlockButton);
  securityActions.appendChild(lockButton);
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

  const addAccountButton = createActionButton("Add account");
  const refreshTokenButton = createActionButton("Refresh token");
  const removeAccountButton = createActionButton("Remove");

  accountActions.appendChild(addAccountButton);
  accountActions.appendChild(refreshTokenButton);
  accountActions.appendChild(removeAccountButton);

  accountRow.appendChild(accountLabel);
  accountRow.appendChild(accountSelect);
  accountRow.appendChild(accountActions);

  const composer = createElement("textarea", { rows: 4 });
  composer.placeholder = "Compose as your selected account...";
  composer.style.width = "100%";
  composer.style.padding = "0.75rem";
  composer.style.borderRadius = "0.75rem";
  composer.style.border = "1px solid rgba(255,255,255,0.2)";
  composer.style.background = "rgba(255,255,255,0.08)";
  composer.style.color = "white";
  composer.style.fontSize = "0.95rem";
  composer.style.resize = "vertical";

  const quoteInput = createElement("input");
  quoteInput.placeholder = "Quote URL (optional)";
  quoteInput.style.width = "100%";
  quoteInput.style.padding = "0.6rem";
  quoteInput.style.borderRadius = "0.75rem";
  quoteInput.style.border = "1px solid rgba(255,255,255,0.2)";
  quoteInput.style.background = "rgba(255,255,255,0.08)";
  quoteInput.style.color = "white";
  quoteInput.style.fontSize = "0.9rem";

  const postButton = createActionButton("Post");
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
  body.appendChild(quoteInput);
  body.appendChild(postButton);
  body.appendChild(addAccountForm);
  body.appendChild(status);

  root.appendChild(heading);
  root.appendChild(body);
  document.body.appendChild(root);

  function setStatus(message, tone) {
    status.textContent = message || "";
    status.style.color = tone === "error" ? "#fca5a5" : tone === "success" ? "#bbf7d0" : "rgba(255,255,255,0.85)";
  }

  function setBusy(isBusy) {
    postButton.disabled = isBusy || !isUnlocked();
    postButton.style.opacity = postButton.disabled ? "0.6" : "1";
  }

  function populateAccounts(accounts) {
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
  }

  function setUnlockedState(unlocked) {
    addAccountButton.disabled = !unlocked;
    refreshTokenButton.disabled = !unlocked;
    removeAccountButton.disabled = !unlocked;
    composer.disabled = !unlocked;
    quoteInput.disabled = !unlocked;
    postButton.disabled = !unlocked;
    unlockButton.textContent = unlocked ? "Change passphrase" : "Unlock vault";
    lockButton.disabled = !unlocked;
    if (!unlocked) {
      populateAccounts([]);
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

  function ensureFreshSession(account) {
    return Promise.resolve().then(function () {
      if (!account) {
        throw new Error("Select an account first");
      }
      return account;
    });
  }

  function sendPost(account, text, quoteTarget) {
    const now = new Date().toISOString();
    const record = {
      $type: "app.bsky.feed.post",
      text: text,
      createdAt: now
    };
    if (quoteTarget) {
      record.embed = {
        $type: "app.bsky.embed.record",
        record: quoteTarget
      };
    }
    return createRecord(account.service, account.accessJwt, account.did, record).then(function (response) {
      if (response.status === 401) {
        return refreshSession(account.service, account.refreshJwt).then(function (session) {
          account.accessJwt = session.accessJwt;
          account.refreshJwt = session.refreshJwt;
          account.lastRefreshedAt = new Date().toISOString();
          return saveAccount(account).then(function () {
            return createRecord(account.service, account.accessJwt, account.did, record);
          });
        });
      }
      return response;
    }).then(function (response) {
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
      if (!account) {
        setStatus("Select an account", "error");
        return;
      }
      if (!text) {
        setStatus("Write something to post", "error");
        composer.focus();
        return;
      }
      setBusy(true);
      setStatus("Posting...", "info");
      Promise.resolve().then(function () {
        if (!quoteUrl) {
          return null;
        }
        return resolveQuote(quoteUrl);
      }).then(function (quoteTarget) {
        return ensureFreshSession(account).then(function (acct) {
          return sendPost(acct, text, quoteTarget);
        });
      }).then(function () {
        setBusy(false);
        setStatus("Posted!", "success");
        composer.value = "";
        quoteInput.value = "";
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

  lockVault();
})();`;
