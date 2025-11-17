from PIL import Image
import os

# константи
MAGIC = b"STEG"
HEADER_LEN = 4 + 4
DEFAULT_OUT = "stego_output.png"
DIFF_OUT = "stego_diff.png"

# утиліти
def bytes_to_bits(data: bytes):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise ValueError("Довжина бітів не кратна 8.")
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i+8]:
            b = (b << 1) | (bit & 1)
        out.append(b)
    return bytes(out)

def int_to_4bytes_be(n: int) -> bytes:
    return n.to_bytes(4, byteorder="big", signed=False)

def bytes4_be_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)

def xor_bytes(data: bytes, key: str | None) -> bytes:
    if not key:
        return data
    k = key.encode("utf-8")
    return bytes([data[i] ^ k[i % len(k)] for i in range(len(data))])

def ensure_rgb(img: Image.Image) -> Image.Image:
    return img if img.mode == "RGB" else img.convert("RGB")

# lsb логіка
def capacity_bits(img: Image.Image) -> int:
    w, h = img.size
    return w * h * 3

def embed_bits_into_image(img: Image.Image, bits):
    img = ensure_rgb(img)
    w, h = img.size
    px = img.load()
    max_bits = capacity_bits(img)
    if len(bits) > max_bits:
        raise ValueError(f"Недостатня місткість зображення: потрібно {len(bits)} біт, доступно {max_bits}.")
    bit_idx = 0
    for y in range(h):
        for x in range(w):
            if bit_idx >= len(bits):
                return img
            r, g, b = px[x, y]
            if bit_idx < len(bits):
                r = (r & ~1) | bits[bit_idx]; bit_idx += 1
            if bit_idx < len(bits):
                g = (g & ~1) | bits[bit_idx]; bit_idx += 1
            if bit_idx < len(bits):
                b = (b & ~1) | bits[bit_idx]; bit_idx += 1
            px[x, y] = (r, g, b)
    return img

def extract_bits_from_image(img: Image.Image, total_bits: int):
    img = ensure_rgb(img)
    w, h = img.size
    px = img.load()
    bits = []
    for y in range(h):
        for x in range(w):
            if len(bits) >= total_bits:
                return bits
            r, g, b = px[x, y]
            if len(bits) < total_bits:
                bits.append(r & 1)
            if len(bits) < total_bits:
                bits.append(g & 1)
            if len(bits) < total_bits:
                bits.append(b & 1)
    return bits

# аналіз відмінностей (побудова видимої diff-карти)
def generate_diff_map(img_before: Image.Image, img_after: Image.Image, out_path: str):
    a = ensure_rgb(img_before)
    b = ensure_rgb(img_after)
    if a.size != b.size:
        b = b.resize(a.size)
    w, h = a.size
    pa, pb = a.load(), b.load()
    diff = Image.new("L", (w, h), 0)
    pd = diff.load()
    changed = 0
    for y in range(h):
        for x in range(w):
            r1, g1, b1 = pa[x, y]
            r2, g2, b2 = pb[x, y]
            # якщо хоч один канал змінився по lsb — фарбуємо білим
            if ((r1 ^ r2) & 1) or ((g1 ^ g2) & 1) or ((b1 ^ b2) & 1):
                pd[x, y] = 255
                changed += 1
    diff.save(out_path, format="PNG")
    total = w * h
    return {"changed_pixels": changed, "changed_pixels_percent": (changed / total * 100.0) if total else 0.0}

# публічні функції
def hide_message(image_path: str, message: str, out_path: str = DEFAULT_OUT, key: str | None = None):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Файл '{image_path}' не знайдено.")
    payload = xor_bytes(message.encode("utf-8"), key)
    header = MAGIC + int_to_4bytes_be(len(payload))
    full = header + payload
    bits = bytes_to_bits(full)

    # робимо копію оригіналу для коректного diff
    img = Image.open(image_path)
    img = ensure_rgb(img)
    orig = img.copy()

    stego_img = embed_bits_into_image(img, bits)
    stego_img.save(out_path, format="PNG")

    original_size_bytes = os.path.getsize(image_path)
    stego_size_bytes = os.path.getsize(out_path)

    # будуємо diff по lsb між orig і stego_img
    diff_info = generate_diff_map(orig, stego_img, DIFF_OUT)

    return {
        "input_file": image_path,
        "input_format": orig.format if hasattr(orig, "format") else None,
        "output_file": out_path,
        "diff_file": DIFF_OUT,
        "original_size_bytes": original_size_bytes,
        "stego_size_bytes": stego_size_bytes,
        "capacity_bits": capacity_bits(orig),
        "used_bits": len(bits),
        "changed_pixels": diff_info["changed_pixels"],
        "changed_pixels_percent": diff_info["changed_pixels_percent"],
        "note": "рекомендовано використовувати png як вхід для стабільності lsb."
    }

def extract_message(image_path: str, key: str | None = None):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Файл '{image_path}' не знайдено.")
    img = Image.open(image_path)
    cap = capacity_bits(img)
    header_bits_need = (len(MAGIC) + 4) * 8
    if header_bits_need > cap:
        raise ValueError("Зображення занадто мале навіть для заголовка.")
    header_bits = extract_bits_from_image(img, header_bits_need)
    header_bytes = bits_to_bytes(header_bits)
    if header_bytes[:4] != MAGIC:
        raise ValueError("Повідомлення не знайдено (MAGIC відсутній).")
    length = bytes4_be_to_int(header_bytes[4:8])
    payload_bits_need = length * 8
    total_bits_need = header_bits_need + payload_bits_need
    if total_bits_need > cap:
        raise ValueError("Заявлена довжина повідомлення більша за місткість зображення.")
    rest_bits = extract_bits_from_image(img, total_bits_need)[header_bits_need:]
    payload = bits_to_bytes(rest_bits)
    payload = xor_bytes(payload, key)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = payload.decode("utf-8", errors="replace")
    return {"extracted_text": text, "length_bytes": length}


def main():
    print("=== LSB стеганографія ===")
    image_name = input("введіть назву файлу зображення (напр., photo.png): ").strip()
    if not image_name:
        print("не вказано файл. завершення.")
        return
    if not os.path.exists(image_name):
        print(f"файл '{image_name}' не знайдено.")
        return
    print("оберіть режим:")
    print("  1 — сховати повідомлення у зображення")
    print("  2 — витягти повідомлення із зображення")
    mode = input("ваш вибір (1/2): ").strip()
    if mode == "1":
        msg = input("введіть текст повідомлення для приховування: ")
        use_key = input("застосувати xor-ключ (так/ні)? ").strip().lower()
        key = None
        if use_key in ("так", "t", "yes", "y"):
            key = input("введіть ключ (рядок): ").strip()
        out_name = input(f"назва вихідного файлу (png) [{DEFAULT_OUT}]: ").strip() or DEFAULT_OUT
        try:
            info = hide_message(image_name, msg, out_name, key)
            print("\n[ok] повідомлення сховане.")
            print(f"- вхідний розмір: {info['original_size_bytes']} байт")
            print(f"- вихідний розмір: {info['stego_size_bytes']} байт")
            print(f"- використано біт: {info['used_bits']} із {info['capacity_bits']}")
            print(f"- змінено пікселів (lsb): {info['changed_pixels']} ({info['changed_pixels_percent']:.4f}%)")
            print(f"- diff-карта: {info['diff_file']}")
        except Exception as e:
            print(f"[помилка] {e}")
    elif mode == "2":
        use_key = input("повідомлення могло бути з ключем. ввести ключ (так/ні)? ").strip().lower()
        key = None
        if use_key in ("так", "t", "yes", "y"):
            key = input("введіть ключ (рядок): ").strip()
        try:
            result = extract_message(image_name, key)
            print("\n[ok] повідомлення витягнуте.")
            print(f"- довжина (байт): {result['length_bytes']}")
            print("- текст:")
            print(result["extracted_text"])
        except Exception as e:
            print(f"[помилка] {e}")
    else:
        print("невірний вибір.")

if __name__ == "__main__":
    main()
