import os
import time
import hashlib
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image



# ГЛОБАЛЬНИЙ AES-КЛЮЧ СЕСІЇ

AES_KEY: bytes | None = None  # буде згенерований один раз на старті
analytics_records = []

#  АНАЛІТИЧНИЙ МОДУЛЬ

def log_analytics(operation: str, size_before: int, size_after: int, duration: float):
    # додає запис до аналітичного звіту.
    analytics_records.append({
        "operation": operation,
        "size_before": size_before,
        "size_after": size_after,
        "duration": duration
    })


def show_report():
    # виводить аналітичний звіт у табличному форматі.
    if not analytics_records:
        print("\nАналітичних даних поки немає.\n")
        return

    print("\n" + "=" * 80)
    print(f"{'АНАЛІТИЧНИЙ ЗВІТ':^80}")
    print("=" * 80)
    header = f"{'Операція':<35} | {'Розмір до, байт':>15} | {'Розмір після, байт':>18} | {'Час, с':>8}"
    print(header)
    print("-" * 80)
    for r in analytics_records:
        print(
            f"{r['operation']:<35} | "
            f"{r['size_before']:>15} | "
            f"{r['size_after']:>18} | "
            f"{r['duration']:>8.4f}"
        )
    print("=" * 80 + "\n")


# КЛЮЧ НА ОСНОВІ ПЕРСОНАЛЬНИХ ДАНИХ

def derive_aes_key(full_name: str, birthdate: str, secret_phrase: str) -> bytes:
    # генерує AES-ключ (32 байти для AES-256) з персональних даних
    base = f"{full_name.strip()}|{birthdate.strip()}|{secret_phrase.strip()}"
    return hashlib.sha256(base.encode("utf-8")).digest()


def init_session_key():
    # один раз на початку програми запитує персональні дані та генерує глобальний AES_KEY
    global AES_KEY
    print("=== СТВОРЕННЯ КЛЮЧА ===")
    full_name = input("Введіть ПІБ: ")
    birthdate = input("Введіть дату народження (наприклад, 24.02.2005): ")
    secret_phrase = input("Введіть секретну фразу: ")

    AES_KEY = derive_aes_key(full_name, birthdate, secret_phrase)
    print("AES-ключ для сесії успішно згенеровано.\n")

# AES-ШИФРУВАННЯ/РОЗШИФРУВАННЯ


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = get_random_bytes(16)  # блок AES = 16 байт
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, iv


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# LSB-СТЕГАНОГРАФІЯ

def hide_data_in_image(cover_image_path: Path, data: bytes, output_image_path: Path) -> int:
    img = Image.open(cover_image_path).convert("RGB")
    pixels = list(img.getdata())

    data_len = len(data)
    full_data = data_len.to_bytes(4, byteorder="big") + data

    bits = "".join(f"{byte:08b}" for byte in full_data)
    total_bits = len(bits)

    if total_bits > len(pixels) * 3:
        raise ValueError(
            "Файл завеликий для цього зображення. "
            f"Потрібно щонайменше {total_bits // 3 + 1} пікселів."
        )

    new_pixels = []
    bit_idx = 0

    for r, g, b in pixels:
        if bit_idx >= total_bits:
            new_pixels.append((r, g, b))
            continue

        r_bin = f"{r:08b}"
        g_bin = f"{g:08b}"
        b_bin = f"{b:08b}"

        if bit_idx < total_bits:
            r_bin = r_bin[:-1] + bits[bit_idx]
            bit_idx += 1
        if bit_idx < total_bits:
            g_bin = g_bin[:-1] + bits[bit_idx]
            bit_idx += 1
        if bit_idx < total_bits:
            b_bin = b_bin[:-1] + bits[bit_idx]
            bit_idx += 1

        new_pixels.append((int(r_bin, 2), int(g_bin, 2), int(b_bin, 2)))

    img.putdata(new_pixels)
    img.save(output_image_path, "PNG")
    return output_image_path.stat().st_size


def extract_data_from_image(stego_image_path: Path) -> bytes:
    img = Image.open(stego_image_path).convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for r, g, b in pixels:
        bits.append(str(r & 1))
        bits.append(str(g & 1))
        bits.append(str(b & 1))

    bits_str = "".join(bits)
    header_bits = bits_str[:32]
    length_bytes = int(header_bits, 2).to_bytes(4, byteorder="big")
    payload_len = int.from_bytes(length_bytes, byteorder="big")

    payload_bits = bits_str[32:32 + payload_len * 8]
    if len(payload_bits) < payload_len * 8:
        raise ValueError("Некоректний стегоконтейнер або пошкоджені дані.")

    payload_bytes = bytes(
        int(payload_bits[i:i + 8], 2) for i in range(0, len(payload_bits), 8)
    )
    return payload_bytes


def build_payload(iv: bytes, ciphertext: bytes, file_hash: bytes) -> bytes:
    return iv + ciphertext + file_hash


def parse_payload(payload: bytes) -> tuple[bytes, bytes, bytes]:
    if len(payload) < 16 + 32:
        raise ValueError("Payload занадто короткий для IV і хеша.")
    iv = payload[:16]
    file_hash = payload[-32:]
    ciphertext = payload[16:-32]
    return iv, ciphertext, file_hash


# ПОВНИЙ ЦИКЛ: ЗАХИСТ

def protect_file():
    global AES_KEY
    if AES_KEY is None:
        print("AES-ключ ще не ініціалізований. Перезапустіть програму.")
        return

    print("\n=== ЕТАП ЗАХИСТУ (AES + LSB) ===")
    src_path_str = input("Введіть шлях до файлу, який потрібно захистити: ").strip('" ')
    img_path_str = input("Введіть шлях до зображення-контейнера (наприклад, cover.png): ").strip('" ')
    out_stego_str = input("Введіть ім'я стего-файлу (наприклад, protected.png): ").strip('" ')

    src_path = Path(src_path_str)
    img_path = Path(img_path_str)
    out_stego = Path(out_stego_str)

    if not src_path.exists():
        print("Помилка: вихідний файл не знайдено.")
        return
    if not img_path.exists():
        print("Помилка: зображення-контейнер не знайдено.")
        return

    # читання вихідного файлу
    original_data = src_path.read_bytes()
    original_size = len(original_data)

    # хеш оригіналу для перевірки цілісності
    file_hash = hashlib.sha256(original_data).digest()

    # етап 1: AES-шифрування
    t1 = time.perf_counter()
    ciphertext, iv = aes_encrypt(original_data, AES_KEY)
    t2 = time.perf_counter()
    enc_time = t2 - t1
    log_analytics("AES шифрування", original_size, len(ciphertext), enc_time)
    print(f"\n[1/2] AES-шифрування успішне. Час: {enc_time:.4f} с.")

    payload = build_payload(iv, ciphertext, file_hash)

    # етап 2: LSB-стеганографія
    t3 = time.perf_counter()
    stego_size = hide_data_in_image(img_path, payload, out_stego)
    t4 = time.perf_counter()
    stego_time = t4 - t3
    log_analytics("LSB-стеганографія", len(payload), stego_size, stego_time)
    print(f"[2/2] Дані приховано у стего-файл {out_stego}. Час: {stego_time:.4f} с.")

    print("\n✅ Повний етап захисту завершено.")


# ПОВНИЙ ЦИКЛ: ВІДНОВЛЕННЯ

def restore_file():
    global AES_KEY
    if AES_KEY is None:
        print("AES-ключ ще не ініціалізований. Перезапустіть програму.")
        return

    print("\n=== ЕТАП ВІДНОВЛЕННЯ (Extract + AES) ===")
    stego_path_str = input("Введіть шлях до стего-файлу (protected.png): ").strip('" ')
    out_file_str = input("Введіть ім'я відновленого файлу (наприклад, restored.txt): ").strip('" ')

    stego_path = Path(stego_path_str)
    out_path = Path(out_file_str)

    if not stego_path.exists():
        print("Помилка: стего-файл не знайдено.")
        return

    # етап 1: витягування payload зі стего
    stego_size = stego_path.stat().st_size
    t1 = time.perf_counter()
    payload = extract_data_from_image(stego_path)
    t2 = time.perf_counter()
    extract_time = t2 - t1
    log_analytics("LSB-екстракція", stego_size, len(payload), extract_time)
    print(f"\n[1/2] Дані витягнуто з зображення. Час: {extract_time:.4f} с.")

    iv, ciphertext, saved_hash = parse_payload(payload)

    # етап 2: AES-розшифрування ---
    t3 = time.perf_counter()
    try:
        restored_data = aes_decrypt(ciphertext, AES_KEY, iv)
    except Exception as e:
        t4 = time.perf_counter()
        log_analytics("AES розшифрування (помилка)", len(ciphertext), 0, t4 - t3)
        print(f"\nПомилка розшифрування (можливо, інша сесія або невірний ключ): {e}")
        return
    t4 = time.perf_counter()
    dec_time = t4 - t3
    log_analytics("AES розшифрування", len(ciphertext), len(restored_data), dec_time)
    print(f"[2/2] Дані розшифровано. Час: {dec_time:.4f} с.")

    # зберігаємо файл
    out_path.write_bytes(restored_data)
    print(f"\nВідновлений файл збережено як: {out_path}")

    # перевірка цілісності
    current_hash = hashlib.sha256(restored_data).digest()
    if current_hash == saved_hash:
        print("Перевірка цілісності: хеш співпадає, файл не було змінено.")
    else:
        print("Перевірка цілісності: хеш НЕ співпадає, файл пошкоджено або інший ключ.")


# МЕНЮ

def main():
    init_session_key()

    while True:
        print("\n=== ДВОЕТАПНИЙ ЗАХИСТ З АНАЛІТИКОЮ ===")
        print("1. Виконати захист файлу (AES шифрування + LSB стеганографія)")
        print("2. Відновити файл (витягування + AES розшифрування + перевірка цілісності)")
        print("3. Показати аналітичний звіт")
        print("4. Вихід")

        choice = input("Оберіть дію: ").strip()

        if choice == "1":
            protect_file()
        elif choice == "2":
            restore_file()
        elif choice == "3":
            show_report()
        elif choice == "4":
            print("Завершення роботи.")
            break
        else:
            print("Некоректний вибір, спробуйте ще раз.")


if __name__ == "__main__":
    main()
