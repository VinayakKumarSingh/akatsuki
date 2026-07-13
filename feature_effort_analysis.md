# Akatsuki Feature Implementation & Codebase Impact Analysis

This document categorizes your proposed features by the level of effort and codebase modification required to implement them. The features are sorted into three categories: **Low Effort (Minimally Invasive)**, **Medium Effort (Moderate Changes)**, and **High Effort (Major Architectural Changes)**.

---

## Category 1: Low Effort (Minimally Invasive)
These features require no database schema migrations or core cryptographic architecture changes. They are largely additions to the frontend UI, simple configuration tweaks, or minor backend validation logic.

| Feature | Impact & Implementation Detail |
| :--- | :--- |
| **Dark / Light Theme Toggle** | **Frontend:** Define a CSS class hierarchy or update the CSS custom properties (`--bg-color`, `--text-color`, etc.) in [index.css](file:///d:/akatsuki/frontend/src/index.css). Persist the user's theme preference in browser `localStorage`. |
| **Client‑Side Search** | **Frontend:** Once the vault is unlocked, perform in-memory string matching over the already decrypted filenames array in [Dashboard.jsx](file:///d:/akatsuki/frontend/src/pages/Dashboard.jsx). No server calls are needed. |
| **Drag‑and‑Drop Upload** | **Frontend:** Integrate a library like `react-dropzone` in the [UploadModal.jsx](file:///d:/akatsuki/frontend/src/components/UploadModal.jsx) to accept files, iterate over them, and fire off parallel `uploadEncryptedDocument` promises. |
| **Batch Operations** | **Frontend/Backend:** Update UI to track selected document checkboxes. Map client actions (delete, download) to sequentially dispatch API calls to `/api/documents/`. |
| **Backup & Restore of Keys** | **Frontend:** Provide a simple "Export Security Kit" button in [ProfileModal.jsx](file:///d:/akatsuki/frontend/src/components/ProfileModal.jsx) that downloads a JSON file containing the user's `salt` and `encrypted_rsa_private_key`. Add an import screen to load them during emergency account recovery. |
| **External Storage Backends** | **Backend:** Simply install `django-storages` and configure it in [settings.py](file:///d:/akatsuki/backend/settings.py) to map `FileField` uploads to an AWS S3, MinIO, or GCS bucket. Django handles this natively. |

---

## Category 2: Medium Effort (Moderate Changes)
These features require database schema migrations, updates to standard API views, or additions to the local cryptographic helpers, but do not alter the fundamental zero-knowledge security model.

| Feature | Impact & Implementation Detail |
| :--- | :--- |
| **Multi‑Recipient with Granular Permissions** | **Schema Change:** Add a permissions column (e.g., `permissions = models.CharField(...)`) to `DocumentAccessKey` specifying access flags (`VIEW_ONLY`, `DOWNLOAD`, `SHARE`).<br>**API/Frontend:** Update the viewsets to verify these flags before serving the encrypted file blob, and enforce permissions dynamically in the React dashboard. |
| **Request Access Workflow** | **Schema Change:** Create a `DocumentAccessRequest` model representing pending access requests.<br>**Backend/Frontend:** Implement endpoints for requesting access, sending dashboard notifications, and allowing document owners to approve requests (which triggers fetching the requester's public RSA key to wrap the file's AES key). |
| **Two‑Factor Authentication (2FA)** | **Backend:** Use `django-otp` or custom TOTP generation. The server stores the encrypted secret and verifies the client-provided OTP during login token exchange.<br>**Security Note:** Safe for zero-knowledge, as authentication factors remain separate from keys. |
| **Audit Trail (Encrypted)** | **Schema Change:** Create an `AuditLog` model to store encrypted JSON log payloads.<br>**Frontend/Backend:** Critical actions (sharing, downloads) generate signed JSON records client-side, encrypted using the user's public key before upload. Decryption occurs only in the client's audit dashboard. |
| **Tagging and Custom Metadata** | **Schema Change:** Add an `encrypted_metadata` text field to `Document` (similar to `encrypted_filename`).<br>**Frontend/Backend:** Pack tags (e.g., labels, projects) into a JSON string, encrypt it client-side with the document's AES key, and update the API payload to submit this encrypted metadata. |
| **Version History** | **Schema Change:** Transition `Document` to have a one-to-many relationship with a new `DocumentVersion` model (holding unique `file_path`, `iv`, and version IDs).<br>**API/Frontend:** Modify the upload flow to append versions and create corresponding version-specific `DocumentAccessKey` mappings. |
| **File Preview (Limited)** | **Frontend:** Download the encrypted document bytes to browser memory, decrypt the array buffer using the cached AES key, convert it to a Blob with the correct MIME type (e.g., image, pdf), and generate an Object URL (`URL.createObjectURL(blob)`) to render in an `<iframe>` or popup. |
| **PWA & Offline Caching** | **Frontend:** Add a service worker (`sw.js`) and manifest. Cache the app shell for offline use, and implement local caching of decrypted filenames/metadata in `IndexedDB` (using an encryption key derived from the user's password) to enable secure offline reading. |
| **Internationalization (i18n)** | **Frontend:** Set up `react-i18next` and replace static text strings with translator functions (`t('label')`). Add translation JSON dictionary files. |
| **Webhooks / API for Automation** | **Backend:** Implement custom Token Authentication (API Keys) for non-interactive scripts, and write a webhook delivery system to notify external endpoints about document events. |

---

## Category 3: High Effort (Major Architectural Changes)
These features require significant restructuring of the cryptographic engine, importing specialized libraries (e.g., WASM-based cryptographic engines), changing how key exchanges are calculated, or implementing complex re-encryption protocols.

| Feature | Impact & Implementation Detail |
| :--- | :--- |
| **Expiring Share Links** | **Architecture Change:** To allow non-account holders to decrypt files, you cannot use their public RSA keys (since they don't have them).<br>**Cryptographic Protocol:** Generate a one-time random AES wrapper key. Wrap the document's AES key with this one-time key. Send the one-time key as a URL hash fragment (e.g., `#key_material`). The server stores the wrapped file key and its expiration timestamp. When a guest accesses the URL, the server sends the wrapped key, and client-side JavaScript decrypts it entirely using the hash fragment (which is never sent to the server). |
| **Shared Vaults (Teams/Groups)** | **Architecture Change:** Introduces a complex group hierarchy.<br>**Cryptographic Protocol:** A group must have a group-level RSA keypair or symmetric vault key. Every time a user is added to the group, the group's key must be wrapped with the user's public RSA key. When a document is shared with the group, the document's AES key is wrapped with the group's key. This requires careful local key orchestration. |
| **Revocation of Access** | **Architecture Change:** In end-to-end encrypted systems, once a user has decrypted a file key, they can keep it. True revocation requires **re-encrypting the underlying file content**.<br>**Workflow:** The client must download the document, decrypt it, generate a new AES key/IV, re-encrypt the document, upload the new ciphertext, and re-wrap the new AES key for the remaining authorized recipients. |
| **Active Directory / SSO** | **Architecture Change:** SSO providers handle authentication but do not manage client-side decryption key derivation.<br>**Integration:** Requires implementing a hybrid protocol where SSO handles user identity, but a local password/passphrase or browser-based key management API (e.g., WebAuthn PRF) is still used to derive the encryption key material. |
| **Hardware Key / HSM (YubiKey)** | **Architecture Change:** Browsers cannot access raw PKCS#11 HSMs directly due to sandboxing.<br>**Cryptographic Protocol:** Leverage the modern WebAuthn PRF (Pseudo-Random Function) extension, allowing users to touch a YubiKey to derive a consistent cryptographic seed. This seed replaces or bolsters the PBKDF2 password derivation process. |
| **Chunked / Resumable Uploads** | **Architecture/Cryptographic Change:** Large files cannot be fully buffered in browser memory for single-blob encryption.<br>**Cryptographic Protocol:** Must implement a chunked GCM encryption scheme (e.g., encrypting 1MB slices at a time, keeping a running HMAC/hash chain, or using unique counters for chunk IVs) and upload them sequentially. The server must handle chunk reassembly or store chunks separately. |
| **Attribute-Based Encryption** | **Core Cryptographic Change:** The Web Crypto API does not natively support Attribute-Based Encryption (CP-ABE) primitives like pairing-friendly elliptic curves.<br>**Cryptographic Protocol:** Must compile and run a pairing-based cryptography library (written in Rust or C) to WebAssembly (WASM) and load it in the browser. Build an Attribute Authority (Key Generation Center) on the backend to issue user attribute-based decryption keys. |
| **Proxy Re-Encryption (PRE)** | **Core Cryptographic Change:** Server-side transformation of keys without revealing plaintext.<br>**Cryptographic Protocol:** Requires a specialized PRE library (like Umbral) loaded as WebAssembly in the browser and backend. The uploader creates re-encryption keys, which the server uses to transform ciphertexts targeted for recipient public keys. |
