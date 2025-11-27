import cv2
import numpy as np

def _to_bin(data):
    """Convert data to binary string."""
    if isinstance(data, str):
        return ''.join(format(ord(i), "08b") for i in data)

    if isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(i, "08b") for i in data]

    if isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")

    raise TypeError("Unsupported type.")


def encode_message(image_path: str, message: str, output_path: str):
    """Embed a secret message into an image using LSB steganography."""
    image = cv2.imread(image_path)

    if image is None:
        raise ValueError("Invalid image path.")

    max_bytes = (image.size * 3) // 8
    if len(message) > max_bytes:
        raise ValueError("Message too large for image.")

    message += "====="
    binary_data = _to_bin(message)
    data_len = len(binary_data)
    data_index = 0

    print(f"[INFO] Capacity: {max_bytes} bytes")
    print("[INFO] Encoding message...")

    for row in image:
        for pixel in row:
            r, g, b = _to_bin(pixel)

            if data_index < data_len:
                pixel[0] = int(r[:-1] + binary_data[data_index], 2)
                data_index += 1

            if data_index < data_len:
                pixel[1] = int(g[:-1] + binary_data[data_index], 2)
                data_index += 1

            if data_index < data_len:
                pixel[2] = int(b[:-1] + binary_data[data_index], 2)
                data_index += 1

            if data_index >= data_len:
                break

        if data_index >= data_len:
            break

    cv2.imwrite(output_path, image)
    print(f"[OK] Encoded image saved as: {output_path}")


def decode_message(image_path: str) -> str:
    """Extract hidden message from an image encoded with LSB."""
    print("[INFO] Decoding message...")
    image = cv2.imread(image_path)

    if image is None:
        raise ValueError("Invalid image path.")

    binary_data = ""

    for row in image:
        for pixel in row:
            r, g, b = _to_bin(pixel)
            binary_data += r[-1] + g[-1] + b[-1]

    bytes_list = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]

    decoded = ""
    for byte in bytes_list:
        decoded += chr(int(byte, 2))
        if decoded.endswith("====="):
            break

    return decoded[:-5]
