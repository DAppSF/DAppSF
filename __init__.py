from flask import Flask
from .config import Config
from .routes.main import bp as main_bp

def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(Config)
    app.config.setdefault("UPLOAD_DIR", "/data/uploads")
    app.config.setdefault("RESULT_FILE", "analysis.txt")
    app.register_blueprint(main_bp)
    return app
