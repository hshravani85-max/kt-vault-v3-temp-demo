"""
Khanna Travels Vault V3 - Cross-Platform Document Media & PDF Rasterization Utilities
Non-OCR helper module preserving Poppler, Pillow, and pypdf rendering support
for AZAPI cloud OCR preparation and image orientation utilities.
Contains zero local OCR engines or Tesseract dependencies.
"""

import os
import sys
import io
import glob
import shutil
import tempfile
import subprocess
import logging
from typing import Optional, Tuple

logger = logging.getLogger("kt_vault.media")

DEFAULT_POPPLER_EXE = r"C:\Program Files\Poppler\bin\pdftoppm.exe"
LINUX_POPPLER_PATHS = ["/usr/bin/pdftoppm", "/usr/local/bin/pdftoppm"]
MAX_PDF_RENDER_SIZE = 20 * 1024 * 1024
DEFAULT_PDF_RENDER_DPI = 200


def get_pdftoppm_path() -> Optional[str]:
    """
    Resolves the Poppler pdftoppm executable path across Linux and Windows.
    1. Environment variables KT_POPPLER_PATH / PDFTOPPM_PATH.
    2. System PATH via shutil.which.
    3. Standard Linux and Windows install locations.
    4. Windows WinGet / Registry PATH lookup strictly on win32.
    """
    env_path = os.environ.get("KT_POPPLER_PATH") or os.environ.get("PDFTOPPM_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    which_path = shutil.which("pdftoppm") or shutil.which("pdftoppm.exe")
    if which_path and os.path.isfile(which_path):
        return which_path

    standard_paths = LINUX_POPPLER_PATHS + [
        DEFAULT_POPPLER_EXE,
        r"C:\Program Files (x86)\Poppler\bin\pdftoppm.exe",
    ]
    for p in standard_paths:
        if os.path.isfile(p):
            return p

    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            pattern = os.path.join(local_app_data, "Microsoft", "WinGet", "Packages", "*poppler*", "**", "pdftoppm.exe")
            for match in glob.glob(pattern, recursive=True):
                if os.path.isfile(match):
                    return match

        try:
            import winreg
            for root, subkey in [
                (winreg.HKEY_CURRENT_USER, r"Environment"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
            ]:
                try:
                    with winreg.OpenKey(root, subkey) as k:
                        val, _ = winreg.QueryValueEx(k, "Path")
                        for part in str(val).split(";"):
                            part = part.strip()
                            if part:
                                candidate = os.path.join(part, "pdftoppm.exe")
                                if os.path.isfile(candidate):
                                    return candidate
                except Exception:
                    pass
        except Exception:
            pass

    return None


def is_pdf_renderer_available() -> Tuple[bool, str]:
    """
    Checks if Poppler pdftoppm executable is available to rasterize PDF pages
    for AZAPI extraction.
    """
    pdftoppm_path = get_pdftoppm_path()
    if pdftoppm_path:
        return True, f"Poppler pdftoppm available at {pdftoppm_path}"

    return False, (
        "No approved local PDF renderer (Poppler pdftoppm) is currently available "
        "to convert PDF pages into images for AZAPI extraction."
    )


def rasterize_pdf_page_to_jpeg(
    pdf_bytes: bytes,
    page_num: int = 1,
    dpi: int = DEFAULT_PDF_RENDER_DPI,
    max_bytes: int = MAX_PDF_RENDER_SIZE,
    timeout: int = 12,
) -> Tuple[bytes, str]:
    """
    Renders a single PDF page into JPEG or PNG image bytes in memory for AZAPI upload.
    Tries Poppler pdftoppm first, then embedded pypdf/Pillow image extraction.
    Always cleans temporary files in finally.
    """
    if not pdf_bytes:
        raise ValueError("Empty PDF bytes provided.")
    if len(pdf_bytes) > max_bytes:
        raise ValueError(f"PDF size exceeds maximum limit of {max_bytes // (1024 * 1024)}MB.")

    pdftoppm_path = get_pdftoppm_path()
    if pdftoppm_path:
        temp_dir = tempfile.mkdtemp(prefix="kt_pdf_render_")
        try:
            pdf_path = os.path.join(temp_dir, "doc.pdf")
            with open(pdf_path, "wb") as f:
                f.write(pdf_bytes)

            out_prefix = os.path.join(temp_dir, f"page_{page_num}")
            cmd = [
                pdftoppm_path,
                "-jpeg",
                "-f", str(int(page_num)),
                "-l", str(int(page_num)),
                "-r", str(int(dpi)),
                pdf_path,
                out_prefix,
            ]
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
            if proc.returncode == 0:
                candidates = sorted(
                    os.path.join(temp_dir, f)
                    for f in os.listdir(temp_dir)
                    if f.startswith(f"page_{page_num}") and f.lower().endswith((".jpg", ".jpeg", ".png"))
                )
                if candidates:
                    with open(candidates[0], "rb") as pf:
                        ext = os.path.splitext(candidates[0])[1].lower()
                        mime = "image/jpeg" if ext in (".jpg", ".jpeg") else "image/png"
                        return pf.read(), mime
        except Exception as e:
            logger.warning("Poppler rasterization failed: %s", type(e).__name__)
        finally:
            for root_d, _, fnames in os.walk(temp_dir):
                for fn in fnames:
                    fp = os.path.join(root_d, fn)
                    try:
                        sz = os.path.getsize(fp)
                        with open(fp, "r+b") as wf:
                            wf.write(b"\x00" * sz)
                            wf.flush()
                    except Exception:
                        pass
            shutil.rmtree(temp_dir, ignore_errors=True)

    # Embedded image fallback using pypdf + Pillow
    try:
        import pypdf
        from PIL import Image
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        idx = int(page_num) - 1
        if 0 <= idx < len(reader.pages):
            page = reader.pages[idx]
            if page.images:
                raw_img = page.images[0].data
                with Image.open(io.BytesIO(raw_img)) as im:
                    if im.mode in ("RGBA", "P"):
                        im = im.convert("RGB")
                    out_buf = io.BytesIO()
                    im.save(out_buf, format="JPEG", quality=95)
                    return out_buf.getvalue(), "image/jpeg"
    except Exception:
        pass

    raise RuntimeError("No PDF rasterizer available to convert PDF page into image for AZAPI extraction.")


def rotate_image_file_pillow(in_path: str, out_path: str, degrees: int) -> bool:
    """
    Rotates an image file (JPG, PNG, BMP) clockwise by 90, 180, or 270 degrees using Pillow.
    Cross-platform (Linux & Windows).
    """
    try:
        from PIL import Image
        norm_deg = degrees % 360
        transpose_map = {
            90: Image.Transpose.ROTATE_270,
            180: Image.Transpose.ROTATE_180,
            270: Image.Transpose.ROTATE_90,
        }
        method = transpose_map.get(norm_deg)
        if method is None:
            return False
        with Image.open(in_path) as im:
            rotated = im.transpose(method)
            rotated.save(out_path)
        return os.path.exists(out_path)
    except Exception:
        return False


def rotate_image_file(in_path: str, out_path: str, degrees: int) -> bool:
    """Cross-platform image rotation powered by Pillow."""
    return rotate_image_file_pillow(in_path, out_path, degrees)
