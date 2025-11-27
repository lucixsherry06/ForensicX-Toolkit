from PIL import Image

def clear_image_metadata(img_path: str):
    img = Image.open(img_path)
    data = list(img.getdata())

    img_no_meta = Image.new(img.mode, img.size)
    img_no_meta.putdata(data)

    img_no_meta.save(img_path)
    print(f"[OK] Metadata cleared from: {img_path}")
