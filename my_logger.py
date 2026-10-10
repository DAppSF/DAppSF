import logging
from flask import Flask

def create_app() -> Flask:
    # Set your custom format: [TIME] [LEVEL] Message
    logging.basicConfig(
        level=logging.INFO,
        format="\033[1m%(asctime)s\033[0m [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        force=True
    )
    
    app = Flask(__name__, static_folder="static", template_folder="templates")
    return app