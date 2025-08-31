# Quantum Aegis: Quantum-Resilient Cryptographic Framework

This project demonstrates a hybrid cryptographic stack using AES-256-GCM, Kyber-768, Dilithium-3, and SHA3-256 for quantum-safe secure communication.

## Structure
- `demo.py`: Demo app entry point
- `main.py`: App entry point
- `key_exchange.py`: Kyber key exchange
- `signature.py`: Dilithium digital signatures
- `encryption.py`: AES-256-GCM encryption/decryption
- `hashing.py`: SHA3-256 hashing

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ## Quantum Aegis

   Quantum Aegis is an open-source, hybrid cryptographic demo that combines classical and post-quantum primitives to demonstrate a quantum-resistant secure communication flow. It pairs AES-256-GCM for symmetric confidentiality, SHA3-256 for hashing, and PQC algorithms (Kyber for KEM, Dilithium for signatures) for key exchange and authentication.

   This repository is intended for developers and researchers who want a simple, runnable example of hybrid crypto primitives on Linux (recommended) and other platforms.

   ## Highlights
   - Hybrid stack: AES-256-GCM + Kyber (KEM) + Dilithium (signatures) + SHA3-256
   - Small, well-segregated modules: `key_exchange.py`, `signature.py`, `encryption.py`, `hashing.py`, and `main.py`
   - Focused on being easy to run inside a Python virtual environment (venv)

   ## Quick checklist (what this README provides)
   - System prerequisites for Linux (Debian/Ubuntu/Derivatives)
   - Steps to create and activate a `venv` and install Python deps from `requirements.txt`
   - Optional instructions to build/install liboqs when prebuilt wheels are not available
   - How to run the demo and the CLI
   - Configuration options and environment variables
   - Contributing, testing, and licensing guidance for open-source use

   ## Assumptions
   - You want the project to be runnable on Linux (Ubuntu/Debian are referenced). If you need explicit Windows or macOS steps, open an issue or PR and I will add them.

   ## Prerequisites (Linux)
   Install basic build tools and libraries (Debian/Ubuntu example):

   ```bash
   sudo apt update; sudo apt install -y python3 python3-venv python3-pip build-essential cmake git libssl-dev pkg-config
   ```

   Notes:
   - On many Linux distributions, `pip install -r requirements.txt` will work and will install the Python `oqs` wheel. If a wheel for your platform/Python isn't available, see the "Optional: Build liboqs from source" section.

   ## Python virtual environment (recommended) — Linux
   All development and demo runs should happen inside a Python virtual environment on Linux (bash/zsh).

   Create, activate, install dependencies, and verify (Linux):

   ```bash
   # create the virtual environment
   python3 -m venv venv

   # activate it (bash / zsh)
   source venv/bin/activate

   pip install --upgrade pip
   pip install oqs

   # when finished, deactivate
   deactivate
   ```

   If `pip install -r requirements.txt` fails on `oqs`, follow the "Optional: Build and install liboqs" section below.

   ## Optional: Build and install liboqs (if pip wheel not available)
   Use this only if `pip install oqs` fails due to missing wheels on your platform. These steps clone and build liboqs and then install the Python bindings.

   ```bash
   git clone --branch main https://github.com/open-quantum-safe/liboqs.git
   cd liboqs
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j"$(nproc)"
   sudo cmake --install build
   cd ..
   pip install oqs --no-binary oqs
   ```

   Depending on your distro, you may need to install additional -dev packages for OpenSSL or GMP.

   ## Installable dependencies
   The Python dependencies used by this project are listed in `requirements.txt`. At time of writing they include:

   - `oqs` — Python bindings to Open Quantum Safe (Kyber/Dilithium)
   - `cryptography` — general cryptography primitives used for AES/GCM helpers
   - `pycryptodome` — utility crypto primitives

   Always prefer `pip install -r requirements.txt` inside the activated venv.

   ## Run the demo
   With the venv activated and dependencies installed, run the demo entry point:

   ```bash
   python main.py
   ```

   What to expect: `main.py` exercises the key exchange, signature and encryption modules to demonstrate end-to-end hybrid encryption and verification flows. The output is printed to stdout and minimal example files/keys (if any) will be created in the working directory.

   ## Files and responsibilities
   - `demo.py` — demo / example runner
   - `main.py` — (if present) CLI wrapper for common operations
   - `key_exchange.py` — Kyber-based KEM operations (keygen, encaps, decaps)
   - `signature.py` — Dilithium signature generation & verification
   - `encryption.py` — AES-256-GCM encryption/decryption helpers
   - `hashing.py` — SHA3-256 helpers and test vectors
   - `requirements.txt` — Python dependency manifest

   When changing code, keep the public functions stable, and add tests for behavior changes.

   ## Configuration
   You can control runtime behavior with environment variables.
   Recommended variables:

   - `QA_LOG_LEVEL` — logging level (e.g., `INFO`, `DEBUG`, default: `INFO`)
   - `QA_OQS_PROVIDER` — (optional) which OQS provider/binding to use if the code supports multiple providers

   ## Developing & testing
   - Create a feature branch for any change: `git checkout -b feat/your-change`
   - Add unit tests next to modules or in a `tests/` directory. Keep tests small and deterministic.
   - Run tests (add a test runner depending on your test framework; if none included, add `pytest` to `requirements-dev.txt`):

   ```bash
   # example when pytest is added
   pip install pytest
   pytest -q
   ```

   ## Security and notes
   - This project is a demo and should not be used as-is for production secrets management. Use it as a reference or learning tool.
   - Keep private keys off source-control. If you add example key files, add them to `.gitignore`.
   - Follow responsible disclosure for security issues by opening an issue or emailing the maintainer.

   ## Contact / Maintainer

   Maintainer: Bharath Honakatti

   Portfolio: https://bharathhonakatti26.github.io/portfolio/

   ## References
   - Open Quantum Safe: https://github.com/open-quantum-safe/liboqs
   - NIST PQC competition: https://csrc.nist.gov/projects/post-quantum-cryptography

   ---

   Enjoy experimenting with Quantum Aegis.
