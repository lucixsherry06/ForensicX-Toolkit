import typer
from pathlib import Path
import json

# Metadata modules
from metadata.image_clear import clear_image_metadata
from metadata.image_extract import extract_image_metadata
from metadata.pdf_clear import clear_pdf_metadata
from metadata.docx_extract import extract_docx_metadata

# File recovery
from recovery.file_recovery import recover_files

# Steganography
from stego.stego import encode_message, decode_message


app = typer.Typer(help="🔍 ForensicX Toolkit — use --help with any command", no_args_is_help=True)

metadata_app = typer.Typer(help="Metadata operations")
recovery_app = typer.Typer(help="File recovery utilities")
stego_app = typer.Typer(help="Steganography tools")

app.add_typer(metadata_app, name="metadata")
app.add_typer(recovery_app, name="recovery")
app.add_typer(stego_app, name="stego")


# ------------------------- VALIDATORS -------------------------

def check_file_exists(path: str, expected: str):
    p = Path(path)
    if not p.exists():
        typer.secho(f"[ERROR] {expected} file not found: {path}", fg=typer.colors.RED)
        raise typer.Exit()
    return p


def safe_exec(func, *args, **kwargs):
    """Centralized safe executor with error reporting."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        typer.secho(f"[FAILED] {e}", fg=typer.colors.RED)
        raise typer.Exit()


def save_metadata(metadata: dict, output: Path):
    with open(output, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    typer.secho(f"[SUCCESS] Metadata saved to {output}", fg=typer.colors.GREEN)


# ------------------------- GLOBAL HELP -------------------------

@app.command("help")
def full_help():
    """Display full tool usage guide."""
    typer.echo("""
========================================
        ForensicX Toolkit
========================================

COMMAND GROUPS:
  metadata       → Image/PDF/DOCX metadata extract/clean
  recovery       → Basic file recovery from directory
  stego          → Steganography encode/decode

USE:
  python main.py <group> <command> [options]

EXAMPLES:
  python main.py metadata image-extract sample.jpg
  python main.py metadata pdf-clear report.pdf
  python main.py recovery run C:\\recyclebin_dump --output recovered
  python main.py stego encode image.png "secret"
  python main.py stego decode image_encoded.png

For detailed help:
  python main.py <group> --help
  python main.py <group> <command> --help
""")


# ------------------------- METADATA COMMANDS -------------------------

@metadata_app.command("image-clear")
def cmd_image_clear(image_path: str, output: str = None):
    """Remove all metadata from an image."""
    img = check_file_exists(image_path, "Image")
    if output is None:
        p = Path(image_path)
        output = str(p.with_name(p.stem + "_cleaned" + p.suffix))
    safe_exec(clear_image_metadata, str(img), output)
    typer.secho(f"[SUCCESS] Cleaned image saved to {output}", fg=typer.colors.GREEN)


@metadata_app.command("image-extract")
def cmd_image_extract(image_path: str, output: str = None):
    """Extract metadata from an image."""
    img = check_file_exists(image_path, "Image")
    metadata = safe_exec(extract_image_metadata, str(img))
    if output is None:
        p = Path(image_path)
        output = str(p.with_name(p.stem + "_metadata.json"))
    save_metadata(metadata, Path(output))


@metadata_app.command("pdf-clear")
def cmd_pdf_clear(pdf_path: str, output: str = None):
    """Remove all metadata from a PDF."""
    pdf = check_file_exists(pdf_path, "PDF")
    if output is None:
        p = Path(pdf_path)
        output = str(p.with_name(p.stem + "_cleaned" + p.suffix))
    safe_exec(clear_pdf_metadata, str(pdf), output)
    typer.secho(f"[SUCCESS] Cleaned PDF saved to {output}", fg=typer.colors.GREEN)


@metadata_app.command("docx-extract")
def cmd_docx_extract(docx_path: str, output: str = None):
    """Extract metadata from a DOCX file."""
    docx = check_file_exists(docx_path, "DOCX")
    metadata = safe_exec(extract_docx_metadata, str(docx))
    if output is None:
        p = Path(docx_path)
        output = str(p.with_name(p.stem + "_metadata.json"))
    save_metadata(metadata, Path(output))


# ------------------------- FILE RECOVERY -------------------------

@recovery_app.command("run")
def cmd_recovery(source_dir: str, output: str = None):
    """Recover deleted/lost files from a directory."""
    src = check_file_exists(source_dir, "Source directory")
    if output is None:
        output = str(Path(source_dir) / "recovered_files")
    safe_exec(recover_files, str(src), output)
    typer.secho(f"[SUCCESS] Recovered files saved to {output}", fg=typer.colors.GREEN)


# ------------------------- STEGANOGRAPHY -------------------------

@stego_app.command("encode")
def cmd_stego_encode(
    image_path: str,
    message: str,
    output_path: str = typer.Option(None, help="Output file path")
):
    """Encode hidden message into an image."""
    img = check_file_exists(image_path, "Image")
    if output_path is None:
        p = Path(image_path)
        output_path = str(p.with_name(p.stem + "_encoded" + p.suffix))
    safe_exec(encode_message, str(img), message, output_path)
    typer.secho(f"[SUCCESS] Encoded image saved to {output_path}", fg=typer.colors.GREEN)


@stego_app.command("decode")
def cmd_stego_decode(image_path: str):
    """Decode hidden message from an image."""
    img = check_file_exists(image_path, "Image")
    msg = safe_exec(decode_message, str(img))
    typer.secho(f"[DECODED MESSAGE] {msg}", fg=typer.colors.GREEN)


# ------------------------- ENTRY POINT -------------------------

if __name__ == "__main__":
    app()
