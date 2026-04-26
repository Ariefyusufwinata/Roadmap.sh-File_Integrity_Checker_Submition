# Roadmap.sh-File_Integrity_Checker_Submition

# File Integrity Checker

Simple Python tool to detect file changes using SHA-256 hashing and AES encryption.
Designed for learning cybersecurity and digital forensics concepts.

---

## Features

* Encrypted file state (AES)
* SHA-256 integrity check
* Detect file modifications
* Multiple file input support
---

## 📦 Requirements

* Python ≥ 3.12
* `cryptography`

Install with uv:

```bash
uv sync
```

---

## ▶️ Usage

### Save file state

```bash
uv run main.py save
```

### Check file integrity

```bash
uv run main.py check
```

---

## 📚 Use Case

* Cybersecurity learning
* File integrity monitoring
* Digital forensics practice

Part of this challenge: https://roadmap.sh/projects/file-integrity-checker