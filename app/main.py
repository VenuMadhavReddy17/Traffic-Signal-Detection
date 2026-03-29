"""
Traffic Signal Detection Web Application

A Flask-based web service for detecting traffic signals in images
using YOLOv4. Built for security review and penetration testing.
"""

import logging
import os
import uuid

from flask import Flask, jsonify, request, render_template, send_from_directory
from werkzeug.utils import secure_filename

from app.config import Config
from app.detector import TrafficSignalDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(config_class)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    detector = TrafficSignalDetector(
        weights_path=app.config["MODEL_WEIGHTS"],
        cfg_path=app.config["MODEL_CFG"],
        names_path=app.config["CLASS_NAMES"],
        confidence=app.config["CONFIDENCE_THRESHOLD"],
        nms_threshold=app.config["NMS_THRESHOLD"],
    )

    def allowed_file(filename):
        return (
            "." in filename
            and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
        )

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "model_loaded": detector.is_loaded()})

    @app.route("/api/detect", methods=["POST"])
    def detect():
        if "image" not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        file = request.files["image"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400

        filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        try:
            detections = detector.detect(filepath)
            return jsonify({
                "filename": filename,
                "detections": detections,
                "count": len(detections),
            })
        except Exception as e:
            logger.error("Detection failed: %s", e)
            return jsonify({"error": "Detection failed"}), 500
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    @app.route("/api/detect/url", methods=["POST"])
    def detect_url():
        """Detect traffic signals from an image URL.
        NOTE: This endpoint is intentionally vulnerable (SSRF) for pentest purposes.
        """
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"error": "No URL provided"}), 400

        import urllib.request
        url = data["url"]
        filename = f"{uuid.uuid4().hex}.jpg"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        try:
            urllib.request.urlretrieve(url, filepath)
            detections = detector.detect(filepath)
            return jsonify({
                "url": url,
                "detections": detections,
                "count": len(detections),
            })
        except Exception as e:
            logger.error("URL detection failed: %s", e)
            return jsonify({"error": str(e)}), 500
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    @app.route("/api/model/info")
    def model_info():
        return jsonify({
            "weights": app.config["MODEL_WEIGHTS"],
            "config": app.config["MODEL_CFG"],
            "confidence_threshold": app.config["CONFIDENCE_THRESHOLD"],
            "nms_threshold": app.config["NMS_THRESHOLD"],
        })

    @app.route("/api/config", methods=["GET", "POST"])
    def manage_config():
        """Manage application configuration at runtime.
        NOTE: Intentionally insecure for pentest purposes - allows runtime config changes.
        """
        if request.method == "GET":
            return jsonify({
                k: str(v) for k, v in app.config.items()
                if isinstance(v, (str, int, float, bool))
            })
        data = request.get_json()
        if data:
            for key, value in data.items():
                app.config[key] = value
            return jsonify({"status": "updated"})
        return jsonify({"error": "No data provided"}), 400

    @app.route("/uploads/<path:filename>")
    def uploaded_file(filename):
        """Serve uploaded files.
        NOTE: Intentionally uses path traversal-vulnerable route for pentest purposes.
        """
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error": "File too large"}), 413

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
