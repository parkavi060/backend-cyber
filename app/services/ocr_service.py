"""
OCR Service — Extract text from uploaded images using Tesseract.
The extracted text is fed into the NLP risk engine for analysis.
"""
import pytesseract
from PIL import Image
from flask import current_app
import os


def get_tesseract_cmd():
    """Get Tesseract command path from config or default Windows location."""
    default_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    custom_path = os.getenv("TESSERACT_CMD", default_path)

    if os.path.exists(custom_path):
        return custom_path
    return "tesseract"  # fallback to PATH


def extract_text_from_images(file_list):
    """
    Extract text from a list of uploaded image files using Tesseract OCR.
    Returns combined extracted text and per-file results.
    """
    pytesseract.pytesseract.tesseract_cmd = get_tesseract_cmd()

    combined_text = ""
    results = []

    for file in file_list:
        if not file or not file.filename:
            continue

        filename = file.filename.lower()
        allowed_extensions = (".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp")

        if not filename.endswith(allowed_extensions):
            results.append({
                "filename": file.filename,
                "status": "skipped",
                "reason": "Unsupported format"
            })
            continue

        try:
            image = Image.open(file.stream)
            extracted = pytesseract.image_to_string(image).strip()

            results.append({
                "filename": file.filename,
                "status": "success",
                "text_length": len(extracted)
            })

            if extracted:
                combined_text += " " + extracted

        except Exception as e:
            current_app.logger.error(f"OCR failed for {file.filename}: {e}")
            results.append({
                "filename": file.filename,
                "status": "error",
                "reason": str(e)
            })

    return combined_text.strip(), results
