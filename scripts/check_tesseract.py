import pytesseract
import os
from PIL import Image, ImageDraw, ImageFont

def check_tesseract():
    tesseract_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    
    print(f"--- Tesseract Verification ---")
    
    # 1. Check if binary exists
    if os.path.exists(tesseract_path):
        print(f"✅ Tesseract binary found at: {tesseract_path}")
        pytesseract.pytesseract.tesseract_cmd = tesseract_path
    else:
        print(f"❌ Tesseract binary NOT found at: {tesseract_path}")
        print(f"   (It might still be installing or in a different location)")
        return

    # 2. Check version
    try:
        version = pytesseract.get_tesseract_version()
        print(f"✅ Tesseract Version: {version}")
    except Exception as e:
        print(f"❌ Could not get Tesseract version: {e}")
        return

    # 3. Simple OCR test
    try:
        # Create a simple image with text
        img = Image.new('RGB', (200, 100), color = (255, 255, 255))
        d = ImageDraw.Draw(img)
        d.text((10,10), "OCR TEST SUCCESS", fill=(0,0,0))
        
        extracted = pytesseract.image_to_string(img).strip()
        print(f"✅ OCR Test Extraction: '{extracted}'")
        
        if "OCR TEST" in extracted.upper():
            print("\n🎉 TESSERACT IS WORKING CORRECTLY!")
        else:
            print("\n⚠️ Tesseract is running but extraction was not perfect.")
            
    except Exception as e:
        print(f"❌ OCR test failed: {e}")

if __name__ == "__main__":
    check_tesseract()
