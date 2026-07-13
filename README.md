# Akatsuki 暁

Akatsuki is a privacy-first, end-to-end encrypted document vault and secure file-sharing application built to protect sensitive documents before they ever leave the user’s device. The project combines a modern React frontend with a Django backend to deliver a polished, secure experience for storing, sharing, and retrieving encrypted files without exposing plaintext content to the server.

At its core, Akatsuki is designed around a simple but powerful idea: users should be able to upload, store, and share private files with confidence, even when the underlying infrastructure is not fully trusted. Instead of relying on server-side encryption alone, the application performs the most important cryptographic operations locally in the browser using the Web Crypto API. That means file contents, filenames, and decryption keys are handled in a way that keeps the service provider from seeing the actual data.

---

## What the project does

Akatsuki provides a complete workflow for secure document handling:

- Users can create an account with a username and master password.
- During registration, a cryptographic key pair is generated in the browser.
- The user’s private key is protected locally and stored in an encrypted form on the server.
- Files can be uploaded through the dashboard and encrypted before being sent to the backend.
- The backend stores ciphertext and metadata only; it does not receive the decrypted content.
- A recipient can be chosen for each upload, and the AES file key is wrapped for that recipient using their public RSA key.
- Documents can later be decrypted and downloaded only by the authorized user who has the correct password and private key.
- The interface also supports viewing encrypted metadata in a vault-style experience, where filenames remain hidden until the vault is unlocked.

In short, Akatsuki acts as a secure digital vault for private documents, with encryption and decryption happening locally so that confidentiality is preserved end-to-end.

---

## Main purpose

The project exists to demonstrate and implement a practical zero-knowledge-style document sharing platform. It focuses on three main goals:

1. Preserve privacy by ensuring files are encrypted before upload.
2. Protect metadata, including filenames, from being exposed in plain text.
3. Offer a user-friendly interface for encrypted storage and secure sharing without making cryptography feel overly technical.

The platform is especially suited to scenarios where sensitive information must be shared securely between users, such as legal files, personal records, internal documentation, confidential contracts, or private media.

---

## Key features

### 1. True zero-knowledge style architecture
The most important feature of Akatsuki is that encryption and decryption happen locally in the browser. The server never receives plaintext files, plaintext passwords, or plaintext private keys. It stores only encrypted data and cryptographic artifacts.

### 2. Hybrid cryptography
The application uses a combination of modern cryptographic primitives:

- AES-256-GCM for encrypting file contents and filenames.
- RSA-OAEP for wrapping and sharing the AES key safely between users.
- PBKDF2 to derive a password-based key for protecting the RSA private key.

This combination gives the app both strong confidentiality and practical key exchange support.

### 3. Encrypted filenames and metadata protection
Unlike many normal document platforms, Akatsuki does not leave filenames exposed in plaintext. File names are encrypted locally before upload, and the user’s vault can remain protected until the correct password is supplied. This prevents the server and casual observers from learning the names of stored files.

### 4. Secure user authentication
The application uses Django REST Framework with JWT-based authentication. Users can register, sign in, and access protected APIs using access tokens, while their password and key material remain protected through the app’s encryption workflow.

### 5. Secure document upload flow
When a file is uploaded:

- A fresh AES key is generated.
- The file bytes are encrypted with that AES key.
- The filename is also encrypted.
- The AES key is wrapped for the selected recipient and for the sender so the original uploader can decrypt later.
- The encrypted file and cryptographic metadata are sent to the backend.

This makes the upload experience seamless while still preserving strong confidentiality.

### 6. Vault-style dashboard experience
The dashboard presents uploaded and received documents in a clean interface. Until the vault is unlocked, the visible metadata remains reduced to timestamps or obscured labels. Once the vault is unlocked, the dashboard can reveal more meaningful information, such as the original filenames.

### 7. Secure decryption and download
At download time, the user supplies their master password, the browser unwraps the private key locally, and the AES key is decrypted. The document contents are then decrypted in-browser and downloaded as a normal file. This keeps the actual file content accessible only to the authorized party.

### 8. Recipient-based sharing
Users can choose a recipient during upload. The system uses the recipient’s public key to encrypt the AES key so that only that person can decrypt the file. The same file can also be made readable by the uploader, allowing the sender to keep access to their own uploads.

### 9. Profile and security management
The frontend includes a security-focused profile experience where users can manage account-related security actions and update their credentials in a protected context.

### 10. Modern, polished interface
The product is not only secure but also visually refined. The frontend uses a glassmorphism-inspired UI, animated panels, and a dark, premium visual design that makes the experience feel modern and intuitive.

---

## How the system works

Akatsuki follows a clear end-to-end encryption workflow:

1. Registration
   - The browser generates an RSA key pair for the user.
   - The private key is wrapped with a key derived from the user’s master password.
   - The encrypted private key and public key are sent to the backend.

2. Upload
   - The browser generates a random AES key.
   - The file content is encrypted using AES-256-GCM.
   - The filename is also encrypted.
   - The AES key is encrypted with the recipient’s public RSA key.
   - The encrypted file and metadata are stored on the backend.

3. Unlock and decrypt
   - The user enters their master password.
   - The browser derives the password key and unwraps the private key locally.
   - The private key decrypts the stored AES key.
   - The AES key decrypts the file contents and filename.
   - The original file is downloaded locally to the user’s machine.

This design ensures that the application can store documents safely without ever needing to expose the plaintext data to the server.

---

## Architecture overview

### Backend
The backend is built with Django and Django REST Framework. It handles:

- User account creation and authentication.
- JWT-based API access.
- Storage of encrypted document metadata.
- Retrieval of public keys for sharing.
- Management of access keys associated with each document.

### Frontend
The frontend is built with React and Vite. It provides:

- Authentication screens for sign-in and registration.
- A dashboard for browsing documents.
- Upload and decryption modals.
- A vault-unlock experience for revealing file names.
- A polished, secure-looking interface built with modern CSS and component-based UI architecture.

### Cryptography layer
The cryptography logic is implemented in the browser using the Web Crypto API. This is the heart of the application’s privacy-preserving behavior.

---

## Technology stack

- Frontend: React, Vite, JavaScript, Axios, CSS
- Backend: Django, Django REST Framework, SimpleJWT
- Cryptography: Web Crypto API, AES-GCM, RSA-OAEP, PBKDF2
- Storage: SQLite by default for local development

---

## Project structure

- backend/: Django project configuration, URL routing, and API logic.
- core/: Models, serializers, views, and database entities for users, keys, and documents.
- frontend/: React application, pages, components, API wrappers, and cryptography helpers.

---

## Security considerations

Akatsuki is designed as a secure and privacy-conscious application, but it is still important to understand its boundaries:

- The server does not see plaintext files or plaintext private keys.
- The user’s master password is the gateway to private-key recovery.
- If the password is lost, access to the encrypted private key may be lost as well.
- The project is a strong demonstration of end-to-end encryption in a web app, but production-grade deployments should include additional hardening, auditing, backup strategies, and operational security measures.

---

## How to run locally

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Start the backend

```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install django djangorestframework djangorestframework-simplejwt django-cors-headers
python manage.py migrate
python manage.py runserver
```

The Django API will run on http://127.0.0.1:8000.

### 2. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will run on http://localhost:5173.

---

## Summary

Akatsuki is a secure, modern, and thoughtfully designed encrypted document-sharing platform that puts user privacy first. It combines strong browser-side cryptography, a clean user experience, and a practical vault-like workflow to make encrypted file storage and sharing feel accessible while still remaining technically robust.

The project demonstrates how a web application can protect sensitive documents in a way that is both practical and privacy-preserving, making it a strong example of end-to-end encrypted document sharing in action.
