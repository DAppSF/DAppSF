import os
class Config:
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/data/uploads")
    RESULT_FILE = os.environ.get("RESULT_FILE", "analysis.txt")
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB
