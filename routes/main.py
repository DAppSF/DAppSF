import os, uuid, subprocess
from flask import Blueprint, current_app, render_template, request, redirect, url_for, abort
from werkzeug.utils import secure_filename
from services.analysis import Analyzer
import logging

logger = logging.getLogger(__name__)

bp = Blueprint("main", __name__)

# main site of the app
@bp.get("/")
def home():
    upload_dir = current_app.config["UPLOAD_DIR"]
    previous_scans = []
    if os.path.exists(upload_dir):
        for job_id in os.listdir(upload_dir):
            job_path = os.path.join(upload_dir, job_id)
            if os.path.isdir(job_path):
                files = os.listdir(job_path)
                app_name = "Unknown"
                for f in files:
                    if not f.endswith(".txt") and not f.endswith(".xml"):
                        app_name = f
                        break
                previous_scans.append({
                    "job_id": job_id,
                    "app_name": app_name
                })
    return render_template("upload.html", previous_scans=previous_scans)

# upload site of the app
@bp.post("/upload")
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        abort(400, "No file provided")
    job_id = str(uuid.uuid4())
    job_path = os.path.join(current_app.config["UPLOAD_DIR"], job_id)
    os.makedirs(job_path, exist_ok=True)
    safe_name = secure_filename(f.filename)
    file_path = os.path.join(job_path, safe_name)
    f.save(file_path)
    analyzer = Analyzer(job_id=job_id, job_path=job_path)
    analyzer.analyze(file_path)
    return redirect(url_for("main.result", job_id=job_id))

@bp.post("/delete/<job_id>")
def delete_scan(job_id: str):
    job_path = os.path.join(current_app.config["UPLOAD_DIR"], job_id)
    if os.path.isdir(job_path):
        import shutil
        shutil.rmtree(job_path, ignore_errors=True)
    return redirect(url_for("main.home"))

@bp.get("/pdf/<job_id>")
def download_pdf(job_id: str):
    job_path = os.path.join(current_app.config["UPLOAD_DIR"], job_id)
    if not os.path.isdir(job_path):
        abort(404)
    
    analysis_path = os.path.join(job_path, "analysis.txt")
    content = f"Security Analysis Report for Job ID: {job_id}\n\n"
    if os.path.exists(analysis_path):
        with open(analysis_path, "r", encoding="utf-8", errors="replace") as f:
            content += f.read()

    from flask import Response
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename=report_{job_id}.txt"}
    )

@bp.get("/result/<job_id>")
def result(job_id: str):
    def _read(job_path: str, relname: str) -> str:
        p = os.path.join(job_path, relname)
        if os.path.exists(p):
            with open(p, "r", errors="replace") as fh:
                return fh.read()
        return ""

    job_path = os.path.join(current_app.config["UPLOAD_DIR"], job_id)
    if not os.path.isdir(job_path):
        abort(404)

    # load files written by Analyzer
    analysis          = _read(job_path, "analysis.txt")
    codesign          = _read(job_path, "codesign.txt")
    hardened          = _read(job_path, "hardened.txt")
    entitlements      = _read(job_path, "entitlements.xml")
    strings_out       = _read(job_path, "strings.txt")
    vulnerabilities   = _read(job_path, "vulnerabilities.txt")
    binary_protections= _read(job_path, "binary_protections.txt")
    secrets           = _read(job_path, "secrets.txt")
    network           = _read(job_path, "network.txt")
    keychain          = _read(job_path, "keychain.txt")
    sensitive         = _read(job_path, "sensitive.txt")
    dylib_injection   = _read(job_path, "dylib_injection.txt")
    dynamic_tracing   = _read(job_path, "dynamic_tracing.txt")
    ipc               = _read(job_path, "ipc.txt")
    privacy           = _read(job_path, "privacy.txt")
    url_schemes       = _read(job_path, "url_schemes.txt")
    helpers           = _read(job_path, "helpers.txt")
    plugins           = _read(job_path, "plugins.txt")
    updates           = _read(job_path, "updates.txt")
    persistence       = _read(job_path, "persistence.txt")
    notarization      = _read(job_path, "notarization.txt")
    crash_handling    = _read(job_path, "crash_handling.txt")

    return render_template(
        "result.html",
        job_id=job_id,
        analysis=analysis,
        code_signing=codesign,
        hardened_runtime=hardened,
        entitlements=entitlements,
        strings=strings_out,
        vulnerabilities=vulnerabilities,
        binary_protections=binary_protections,
        secrets=secrets,
        network=network,
        keychain=keychain,
        sensitive=sensitive,
        dylib_injection=dylib_injection,
        dynamic_tracing=dynamic_tracing,
        ipc=ipc,
        privacy=privacy,
        url_schemes=url_schemes,
        helpers=helpers,
        plugins=plugins,
        updates=updates,
        persistence=persistence,
        notarization=notarization,
        crash_handling=crash_handling,
    )
