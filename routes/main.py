import os, uuid, subprocess
from flask import Blueprint, current_app, render_template, request, redirect, url_for, abort
from werkzeug.utils import secure_filename
from ..services.analysis import Analyzer

bp = Blueprint("main", __name__)

@bp.get("/")
def home():
    return render_template("upload.html")

@bp.post("/upload")
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        abort(400, "No file provided.")
    job_id = str(uuid.uuid4())
    job_path = os.path.join(current_app.config["UPLOAD_DIR"], job_id)
    os.makedirs(job_path, exist_ok=True)
    safe_name = secure_filename(f.filename)
    file_path = os.path.join(job_path, safe_name)
    f.save(file_path)
    analyzer = Analyzer(job_id=job_id, job_path=job_path)
    analyzer.analyze(file_path)
    return redirect(url_for("main.result", job_id=job_id))

def _read(job_path: str, relname: str) -> str:
    p = os.path.join(job_path, relname)
    if os.path.exists(p):
        with open(p, "r", errors="replace") as fh:
            return fh.read()
    return ""
    
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
    analysis     = _read(job_path, "analysis.txt")
    codesign     = _read(job_path, "codesign.txt")
    hardened     = _read(job_path, "hardened.txt")
    entitlements = _read(job_path, "entitlements.xml")
    strings_out  = _read(job_path, "strings.txt")

    # placeholders for not-yet-implemented cards
    otool               = ""
    nm                  = ""
    lldb                = ""
    binary_protections  = ""
    notarization        = ""
    persistence         = ""
    keychain            = ""
    sensitive           = ""
    network             = ""
    ipc                 = ""
    dynamic_tracing     = ""
    dylib_injection     = ""
    privacy             = ""
    helpers             = ""
    url_schemes         = ""
    crash_handling      = ""
    plugins             = ""

    return render_template(
        "result.html",
        job_id=job_id,
        analysis=analysis,
        code_signing=codesign,
        hardened_runtime=hardened,
        entitlements=entitlements,
        strings=strings_out,
        otool=otool,
        nm=nm,
        lldb=lldb,
        binary_protections=binary_protections,
        notarization=notarization,
        persistence=persistence,
        keychain=keychain,
        sensitive=sensitive,
        network=network,
        ipc=ipc,
        dynamic_tracing=dynamic_tracing,
        dylib_injection=dylib_injection,
        privacy=privacy,
        helpers=helpers,
        url_schemes=url_schemes,
        crash_handling=crash_handling,
        plugins=plugins,
    )
