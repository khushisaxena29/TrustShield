"""
modules/qr_scanner.py
------------------------
STEP 4 of the build order.

Decodes QR codes from an uploaded image. Uses OpenCV's built-in
QRCodeDetector (no external 'zbar' system library required, which
makes it much more reliable to install on Windows than pyzbar).

This module ONLY decodes the QR code and tells you whether the
result looks like a URL or plain text. app.py then routes the
decoded content to url_analyzer.py or text_analyzer.py.

Used by: app.py
"""

import numpy as np
import cv2
from PIL import Image


def decode_qr_from_image(uploaded_file):
    """
    Decode a QR code from a Streamlit UploadedFile (or any file-like
    object / PIL Image). Returns the decoded string, or None if no
    QR code was found or the image couldn't be read.

    Never raises - always returns None on failure so the UI can
    show a friendly "no QR code found" message instead of crashing.
    """
    try:
        # Accept either a Streamlit UploadedFile, a file path, or a PIL Image
        if isinstance(uploaded_file, Image.Image):
            pil_image = uploaded_file
        else:
            pil_image = Image.open(uploaded_file)

        # Convert PIL -> OpenCV (RGB -> BGR) format
        rgb_image = pil_image.convert("RGB")
        cv_image = cv2.cvtColor(np.array(rgb_image), cv2.COLOR_RGB2BGR)

        detector = cv2.QRCodeDetector()
        decoded_text, points, _ = detector.detectAndDecode(cv_image)

        if decoded_text:
            return decoded_text.strip()
        return None

    except Exception as e:
        print(f"[qr_scanner.py] Failed to decode QR code: {e}")
        return None


def is_url_like(text):
    """
    Very small heuristic: does the decoded QR payload look like a
    link rather than plain text? Kept local to avoid a circular
    import with url_analyzer.py.
    """
    if not text:
        return False
    text = text.strip().lower()
    return text.startswith("http://") or text.startswith("https://") or text.startswith("www.")

