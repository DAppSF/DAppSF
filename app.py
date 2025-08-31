import os, uuid, subprocess
from flask import Flask, request, render_template_string, Response
from werkzeug.utils import secure_filename

UPLOAD_DIR = "/data/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

@app.get("/")
def home():
    return render_template_string("""
    <h1>DAppSF File Upload MVP (HEORFlask)</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
    <input type="file" id="file" name="file" accept=".dmg">
      <input type="submit" value="Upload">
    </form>
    """)

@app.post("/upload")
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        return Response("No file provided.", status=400)

    job_id = str(uuid.uuid4())
    job_path = os.path.join(UPLOAD_DIR, job_id)
    os.makedirs(job_path, exist_ok=True)

    safe_name = secure_filename(f.filename)
    file_path = os.path.join(job_path, safe_name)
    f.save(file_path)

    # Run `ls -l` on the uploaded folder
    result = subprocess.run(["ls", "-l", job_path], capture_output=True, text=True)
    output = f"File saved to {file_path}\n\nls -l output:\n{result.stdout}"
    return Response(output, mimetype="text/plain")
