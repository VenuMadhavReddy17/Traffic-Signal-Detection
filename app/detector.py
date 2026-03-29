"""
YOLOv4 Traffic Signal Detector

Wraps OpenCV DNN module for YOLOv4 inference. Falls back to a stub
when model files are not present (useful for pentest setup without
requiring the full model weights).
"""

import logging
import os
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class TrafficSignalDetector:
    def __init__(
        self,
        weights_path: str,
        cfg_path: str,
        names_path: str,
        confidence: float = 0.5,
        nms_threshold: float = 0.4,
    ):
        self.weights_path = weights_path
        self.cfg_path = cfg_path
        self.names_path = names_path
        self.confidence = confidence
        self.nms_threshold = nms_threshold
        self.net = None
        self.classes = []
        self._load_model()

    def _load_model(self):
        if not os.path.exists(self.weights_path) or not os.path.exists(self.cfg_path):
            logger.warning(
                "Model files not found (%s, %s). Running in stub mode.",
                self.weights_path,
                self.cfg_path,
            )
            return

        try:
            import cv2

            self.net = cv2.dnn.readNet(self.weights_path, self.cfg_path)
            if os.path.exists(self.names_path):
                with open(self.names_path, "r") as f:
                    self.classes = [line.strip() for line in f if line.strip()]
            logger.info("Model loaded successfully with %d classes", len(self.classes))
        except Exception as e:
            logger.error("Failed to load model: %s", e)

    def is_loaded(self) -> bool:
        return self.net is not None

    def detect(self, image_path: str) -> List[Dict[str, Any]]:
        if not self.is_loaded():
            return self._stub_detect(image_path)

        import cv2
        import numpy as np

        image = cv2.imread(image_path)
        if image is None:
            raise ValueError(f"Could not read image: {image_path}")

        height, width = image.shape[:2]
        blob = cv2.dnn.blobFromImage(
            image, 1 / 255.0, (416, 416), swapRB=True, crop=False
        )
        self.net.setInput(blob)

        layer_names = self.net.getLayerNames()
        output_layers = [
            layer_names[i - 1] for i in self.net.getUnconnectedOutLayers().flatten()
        ]
        outputs = self.net.forward(output_layers)

        boxes, confidences, class_ids = [], [], []
        for output in outputs:
            for detection in output:
                scores = detection[5:]
                class_id = int(np.argmax(scores))
                conf = float(scores[class_id])
                if conf > self.confidence:
                    center_x = int(detection[0] * width)
                    center_y = int(detection[1] * height)
                    w = int(detection[2] * width)
                    h = int(detection[3] * height)
                    x = center_x - w // 2
                    y = center_y - h // 2
                    boxes.append([x, y, w, h])
                    confidences.append(conf)
                    class_ids.append(class_id)

        indices = cv2.dnn.NMSBoxes(
            boxes, confidences, self.confidence, self.nms_threshold
        )

        results = []
        for i in indices.flatten() if len(indices) > 0 else []:
            box = boxes[i]
            label = self.classes[class_ids[i]] if class_ids[i] < len(self.classes) else f"class_{class_ids[i]}"
            results.append({
                "label": label,
                "confidence": round(confidences[i], 4),
                "bbox": {"x": box[0], "y": box[1], "w": box[2], "h": box[3]},
            })

        return results

    def _stub_detect(self, image_path: str) -> List[Dict[str, Any]]:
        """Return placeholder detections when model is not loaded."""
        logger.info("Stub detection on %s (model not loaded)", image_path)
        return [
            {
                "label": "stub_traffic_signal",
                "confidence": 0.0,
                "bbox": {"x": 0, "y": 0, "w": 0, "h": 0},
                "note": "Model not loaded - stub response for testing",
            }
        ]
