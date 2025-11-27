import PyPDF2

def clear_pdf_metadata(pdf_file: str):
    with open(pdf_file, "rb") as file:
        reader = PyPDF2.PdfReader(file)

        if reader.metadata is None:
            print("[INFO] No metadata found.")
            return

        print("[OK] Metadata detected. Creating clean PDF...")

        writer = PyPDF2.PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        out_file = f"{pdf_file.rsplit('.', 1)[0]}_clean.pdf"

        with open(out_file, "wb") as f:
            writer.write(f)

        print(f"[OK] Clean PDF saved as: {out_file}")
