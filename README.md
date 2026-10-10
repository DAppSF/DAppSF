# DAppSF - Desktop Application Security Framework

DAppSF (Desktop Application Security Framework) is a lightweight, web-based static analysis platform tailored for macOS and desktop application security assessments. It allows security analysts and developers to upload application bundles and binaries to inspect code signing, Mach-O binary hardening, embedded strings, entitlements, and potential security weaknesses.

---

## Features

- **Upload & Automated Inspection**: Easily upload `.app` packages, archives, or binaries via an intuitive web interface.
- **Static Analysis Checks**:
  - **Code Signing & Notarization**: Validate digital signatures and Gatekeeper compliance.
  - **Mach-O Protections**: Inspect binary hardening flags (PIE, ARC, stack canaries, restrict sections).
  - **Entitlements**: Extract and evaluate macOS application sandbox permissions and dangerous entitlements.
  - **Strings & Secrets**: Automated extraction of embedded strings, hardcoded secrets, and network endpoints.
  - **Structural Verification**: Inspect bundle layouts, helper tools, and plist configurations.
- **Collapsible Reporting UI**: Responsive, dark-mode aware web dashboard designed to present verbose analysis output cleanly.
- **Docker-Ready**: Packaged with a slim Python base container and standard binary analysis utilities (`binutils`, `file`).

---

## Architecture & Project Structure

