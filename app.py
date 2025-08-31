from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
import os, uuid, subprocess

app = FastAPI()

UPLOAD_DIR = "/data/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h1>DAppSF File Upload MVP</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
      <input type="file" name="file"><br><br>
      <input type="submit" value="Upload">
    </form>
    """

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    job_id = str(uuid.uuid4())
    job_path = os.path.join(UPLOAD_DIR, job_id)
    os.makedirs(job_path, exist_ok=True)

    file_path = os.path.join(job_path, file.filename)
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Run `ls -l` on the uploaded folder
    result = subprocess.run(["ls", "-l", job_path], capture_output=True, text=True)
    return PlainTextResponse(f"File saved to {file_path}\n\nls -l output:\n{result.stdout}")
