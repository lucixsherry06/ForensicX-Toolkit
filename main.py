import typer
from pathlib import Path

# Metadata modules
from metadata.image_clear import clear_image_metadata
from metadata.image_extract import extract_image_metadata
from metadata.pdf_clear import clear_pdf_metadata
from metadata.docx_extract import extract_docx_metadata

# File recovery
from recovery.file_recovery import recover_files

# Steganography
from stego.stego import encode_message, decode_message

app = typer.Typer(help="Digital Forensics Toolkit", no_args_is_help=True)

metadata_app = typer.Typer(help="Metadata operations")
recovery_app = typer.Typer(help="File recovery")
stego_app = typer.Typer(help="Image Steganography")

app.add_typer(metadata_app, name="metadata")
app.add_typer(recovery_app, name="recovery")
app.add_typer(stego_app, name="stego")


# ------------------------- METADATA COMMANDS -------------------------

@metadata_app.command("image-clear")
def cmd_image_clear(image_path: str):
    """Remove all metadata from an image."""
    clear_image_metadata(image_path)


@metadata_app.command("image-extract")
def cmd_image_extract(image_path: str):
    """Extract metadata from an image."""
    extract_image_metadata(image_path)


@metadata_app.command("pdf-clear")
def cmd_pdf_clear(pdf_path: str):
    """Remove all metadata from a PDF."""
    clear_pdf_metadata(pdf_path)


@metadata_app.command("docx-extract")
def cmd_docx_extract(docx_path: str):
    """Extract metadata from a DOCX file."""
    extract_docx_metadata(docx_path)


# ------------------------- FILE RECOVERY -------------------------

@recovery_app.command("run")
def cmd_recovery(source_dir: str):
    """Recover deleted/lost files from a directory."""
    recover_files(source_dir)


# ------------------------- STEGANOGRAPHY -------------------------

@stego_app.command("encode")
def cmd_stego_encode(
    image_path: str,
    message: str,
    output_path: str = typer.Option(None, help="Output file path")
):
    """Encode hidden message into an image."""
    if output_path is None:
        p = Path(image_path)
        output_path = str(p.with_name(p.stem + "_encoded" + p.suffix))

    encode_message(image_path, message, output_path)


@stego_app.command("decode")
def cmd_stego_decode(image_path: str):
    """Decode hidden message from an image."""
    msg = decode_message(image_path)
    typer.echo(f"[DECODED MESSAGE] {msg}")


# ------------------------- ENTRY POINT -------------------------

if __name__ == "__main__":
    app()
