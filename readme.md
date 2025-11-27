# ForensicX-Toolkit 🔍

[![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python-based digital forensics toolkit for metadata analysis, file recovery, and image steganography.

---

## Table of Contents
- [Overview](#overview)  
- [Features](#features)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Commands](#commands)  
- [Examples](#examples)  
- [Contributing](#contributing)  
- [License](#license)  

---

## Overview
ForensicX-Toolkit provides tools for:
- Extracting and cleaning metadata from images, PDFs, and DOCX files  
- Recovering deleted or lost files from directories  
- Encoding and decoding secret messages in images using steganography

Ideal for digital forensics labs, investigations, or hands-on learning.

---

## Features

### Metadata
- `image-extract` — Extract metadata from images (`.jpg`, `.png`, etc.)  
- `image-clear`   — Remove metadata from images  
- `pdf-clear`     — Remove metadata from PDF files  
- `docx-extract`  — Extract metadata from DOCX files  

### File Recovery
- `run` — Recover deleted files from a specified directory  

### Steganography
- `encode` — Hide secret messages in images  
- `decode` — Reveal hidden messages from images  

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/lucixsherry06/ForensicX-Toolkit.git
cd ForensicX-Toolkit
```

2. Create a virtual environment:
```bash
python -m venv dfenv
```

3. Activate the environment:

- Windows
```bash
dfenv\Scripts\activate
```

- Linux / macOS
```bash
source dfenv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

---

## Usage

Run the toolkit:
```bash
python main.py
```

Display the full help menu:
```bash
python main.py help
```

---

## Commands

### Metadata
```bash
# Extract metadata from an image
python main.py metadata image-extract <image_path>

# Remove metadata from an image
python main.py metadata image-clear <image_path>

# Remove metadata from a PDF
python main.py metadata pdf-clear <pdf_path>

# Extract metadata from a DOCX
python main.py metadata docx-extract <docx_path>
```

### File Recovery
```bash
# Recover deleted/lost files from a directory
python main.py recovery run <source_directory>
```

### Steganography
```bash
# Encode a message in an image
python main.py stego encode <image_path> "<message>" [--output-path <output_path>]

# Decode a hidden message from an image
python main.py stego decode <image_path>
```

---

## Examples

### Extract image metadata
```bash
python main.py metadata image-extract "sample.jpg"
```

### Encode a message in an image
```bash
python main.py stego encode "cover_image.png" "Secret message"
```

### Recover files
```bash
python main.py recovery run "E:\DeletedFiles"
```

---

## Contributing

1. Fork the repository  
2. Create a feature branch:
```bash
git checkout -b feature/new-feature
```
3. Commit your changes:
```bash
git commit -m "Add new feature"
```
4. Push to your branch:
```bash
git push origin feature/new-feature
```
5. Open a Pull Request

---

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
