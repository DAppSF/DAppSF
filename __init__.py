from flask import Flask
import config
from routes.main import bp as main_bp

def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(config.Config)
    app.config.setdefault("UPLOAD_DIR", "/data/uploads")
    app.config.setdefault("RESULT_FILE", "analysis.txt")
    app.register_blueprint(main_bp)
    return app