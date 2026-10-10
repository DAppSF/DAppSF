
---

## About

> Note: This is vibe coded shit.

## Getting Started

### Prerequisites

- **Python 3.12+**
- **System Utilities**: `binutils` (providing `strings`), `file`
- *(Optional)* **Docker**

### Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/dappsf.git
   cd dappsf
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the development server:**
   ```bash
   python app.py
   ```
   Open your browser at `http://localhost:8000`.

---

## Running with Docker

### Using the Pre-configured Container

1. **Build the Docker image:**
   ```bash
   docker build -t dappsf:latest .
   ```

2. **Run the container:**
   ```bash
   docker run -d \
     -p 8000:8000 \
     -v dappsf_uploads:/data/uploads \
     --name dappsf \
     dappsf:latest
   ```

Access the dashboard at `http://localhost:8000`.

---

## Configuration

DAppSF can be configured via environment variables:

| Variable | Description | Default |
|---|---|---|
| `UPLOAD_DIR` | Directory where uploaded files and analysis results are stored | `/data/uploads` |
| `RESULT_FILE` | Default filename for aggregated summary text | `analysis.txt` |
| `PYTHONPATH` | Python import path | `/app` |

---

## Usage Workflow

1. Navigate to `http://localhost:8000/`.
2. Choose a binary file or application archive (up to 1 GB) and click **Upload**.
3. Once processed, you will be redirected to `/result/<job_id>`.
4. Review individual report sections such as **Code Signing**, **Entitlements**, **Mach-O Protections**, and **Strings**. Sections can be expanded or collapsed to focus on relevant findings.

---

## CI/CD & Releases

The repository contains an automated GitHub Actions workflow in `.github/workflows/release.yml` that builds multi-architecture Docker images (`linux/amd64`, `linux/arm64`) and publishes them to the GitHub Container Registry (`ghcr.io`) upon pushing to the `release` branch.

---

## License

This project is licensed under the terms of the MIT License.
