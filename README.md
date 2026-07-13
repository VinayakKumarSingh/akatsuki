# Akatsuki 暁

Akatsuki is a privacy-first, end-to-end encrypted document vault and secure file-sharing application built to protect sensitive documents before they ever leave the user’s device. The project combines a modern React frontend with a Django backend to deliver a polished, secure experience for storing, sharing, and retrieving encrypted files without exposing plaintext content to the server.

At its core, Akatsuki is designed around a simple but powerful idea: users should be able to upload, store, and share private files with confidence, even when the underlying infrastructure is not fully trusted. Instead of relying on server-side encryption alone, the application performs the most important cryptographic operations locally in the browser using the Web Crypto API. That means file contents, filenames, and decryption keys are handled in a way that keeps the service provider from seeing the actual data.

---

## Key Features

Akatsuki provides a complete workflow for secure document handling:

- **E2E Zero-Knowledge Storage**: All file encryption (AES-256-GCM) and key wrapping (RSA-OAEP) happen client-side. The server only sees and stores ciphertext.
- **Two-Factor Authentication (2FA)**: Native SHA-1 based Time-based One-Time Password (TOTP) verification for secure login token exchange.
- **Encrypted Audit Trail**: Critical user actions are logged into cryptographically signed JSON payloads, encrypted with the user's public key client-side, and decrypted only on the user's audit dashboard.
- **Shared Team Vaults (Groups)**: Complex group hierarchy support using group symmetric keys wrapped with members' public RSA keys, allowing seamless document sharing within teams.
- **Cryptographic Access Revocation**: True revocation of access. The client downloads, decrypts, generates a new AES key/IV, re-encrypts the file content, re-wraps it for remaining users/groups, and uploads the new version while purging old access keys.
- **Version History & File Preview**: Lossless version history tracking with dynamic client-side decrypt previews using browser blob URLs inside an iframe.
- **Master Key Recovery**: Account recovery mechanism with security questions/answers and recovery salt to safely reset passwords and re-wrap RSA keypairs.

---

## Technology Stack

- **Frontend**: React, Vite, JavaScript, Axios, Vanilla CSS
- **Backend**: Django, Django REST Framework, SimpleJWT
- **Cryptography**: Web Crypto API, AES-GCM, RSA-OAEP, PBKDF2
- **Storage**: SQLite by default for local development

---

## Architecture & Security Flow

1. **Registration**: Your browser generates an RSA-OAEP key pair. The private key is encrypted with a PBKDF2 derivative of your password. Only the public key and the encrypted private key are sent to the server.
2. **Uploading**: A random AES-256-GCM key is generated. The file and filename are encrypted with this AES key. The AES key is then encrypted with the recipient's RSA Public Key (and your own, so you can read it later).
3. **Downloading**: You enter your Master Password to locally unwrap your RSA Private Key. Your RSA Private Key decrypts the AES key. The AES key decrypts the file bytes and triggers a secure local browser download.

---

## Project Structure

- `backend/`: Django project configuration, URL routing, and API settings.
- `core/`: Models, serializers, views, and database entities for users, keys, and documents.
- `frontend/`: React application, pages, components, API wrappers, and cryptography helpers.

---

## How to Run Locally

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Start the backend

```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install django djangorestframework djangorestframework-simplejwt django-cors-headers django-otp pyotp qrcode
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
