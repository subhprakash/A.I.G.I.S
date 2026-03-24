import os
import zipfile
import tempfile
import shutil
from backend.utils.logger import get_logger

logger = get_logger(__name__)

MAX_EXTRACT_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB
MAX_FILE_COUNT = 100

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".rb", ".go", ".php",
    ".exe", ".elf", ".bin", ".so", ".dll",
}


def extract_zip(zip_path: str) -> tuple:
    """
    Safely extract a zip archive to a temporary directory.
    Returns (extract_dir, list_of_scannable_file_paths)
    Raises ValueError on zip bomb, ZipSlip, or bad archive.
    """
    extract_dir = tempfile.mkdtemp(prefix="aigis_zip_")

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:

            # Zip bomb check
            total_size = sum(info.file_size for info in zf.infolist())
            if total_size > MAX_EXTRACT_SIZE_BYTES:
                raise ValueError(
                    f"Zip would extract to "
                    f"{total_size // 1024 // 1024} MB — "
                    f"exceeds {MAX_EXTRACT_SIZE_BYTES // 1024 // 1024} MB limit. "
                    "Possible zip bomb."
                )

            # File count cap
            members = zf.infolist()
            if len(members) > MAX_FILE_COUNT:
                logger.warning(
                    f"[AIGIS] Zip has {len(members)} files — "
                    f"capping at {MAX_FILE_COUNT}"
                )
                members = members[:MAX_FILE_COUNT]

            # ZipSlip prevention + extraction
            extracted_paths = []
            extract_dir_real = os.path.realpath(extract_dir)

            for member in members:
                member_path = os.path.realpath(
                    os.path.join(extract_dir, member.filename)
                )
                if not member_path.startswith(extract_dir_real + os.sep):
                    logger.warning(
                        f"[AIGIS] ZipSlip blocked: {member.filename}"
                    )
                    continue
                if member.filename.endswith("/"):
                    continue
                zf.extract(member, extract_dir)
                extracted_paths.append(member_path)

        # Filter to scannable only
        scannable = [
            p for p in extracted_paths
            if os.path.splitext(p)[1].lower() in SCANNABLE_EXTENSIONS
        ]

        logger.info(
            f"[AIGIS] Extracted {len(extracted_paths)} files, "
            f"{len(scannable)} scannable"
        )
        return extract_dir, scannable

    except zipfile.BadZipFile:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise ValueError("File is not a valid zip archive or is corrupted.")
    except ValueError:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise
    except Exception:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise