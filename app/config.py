import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/uploads")
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp"}
    MODEL_WEIGHTS = os.environ.get("MODEL_WEIGHTS", "models/yolov4-custom_1000.weights")
    MODEL_CFG = os.environ.get("MODEL_CFG", "models/yolov4-custom.cfg")
    CLASS_NAMES = os.environ.get("CLASS_NAMES", "models/classes.names")
    CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", 0.5))
    NMS_THRESHOLD = float(os.environ.get("NMS_THRESHOLD", 0.4))
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
