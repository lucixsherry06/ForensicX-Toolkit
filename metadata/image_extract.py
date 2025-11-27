from PIL import Image
from PIL.ExifTags import TAGS

def extract_image_metadata(img_path: str):
    image = Image.open(img_path)

    info_dict = {
        "Filename": image.filename,
        "Image Size": image.size,
        "Image Height": image.height,
        "Image Width": image.width,
        "Image Format": image.format,
        "Image Mode": image.mode,
        "Image is Animated": getattr(image, "is_animated", False),
        "Frames in Image": getattr(image, "n_frames", 1),
    }

    print("\n=== BASIC METADATA ===")
    for k, v in info_dict.items():
        print(f"{k:25}: {v}")

    print("\n=== EXIF DATA ===")
    exifdata = image.getexif()
    for tag_id in exifdata:
        tag = TAGS.get(tag_id, tag_id)
        data = exifdata.get(tag_id)
        if isinstance(data, bytes):
            data = data.decode(errors="ignore")
        print(f"{tag:25}: {data}")
