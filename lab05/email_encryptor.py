import base64
import hashlib
import os
from cryptography.fernet import Fernet

# глобальна змінна для зберігання поточного ключа в пам'яті
current_key = None


def generate_key_from_data(email: str, secret_phrase: str) -> bytes:
    # генерація ключа на основі персональних даних
    # ключ = SHA256(email + секретна фраза) -> Base64
    raw_data = email + secret_phrase
    # робимо хеш SHA-256
    sha = hashlib.sha256(raw_data.encode()).digest()
    return base64.urlsafe_b64encode(sha[:32])


def save_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)
    print(f"Файл збережено: {filename}")


def load_file(filename):
    if not os.path.exists(filename):
        print(f"Файл {filename} не знайдено.")
        return None
    with open(filename, 'rb') as f:
        return f.read()


def menu():
    global current_key

    while True:
        print("\n" + "=" * 40)
        print("            EMAIL-ШИФРАТОР")
        print("=" * 40)

        status = "Ключ АКТИВНИЙ" if current_key else "Ключ ВІДСУТНІЙ"
        print(f"Статус системи: {status}")
        if current_key:
            print(f"Поточний ключ (Base64): {current_key.decode()}")

        print("\n--- Керування ключами ---")
        print("1. Згенерувати ключ")
        print("2. Експортувати поточний ключ у файл (передати другу)")
        print("3. Імпортувати ключ з файлу (отримати від друга)")

        print("\n--- Робота з повідомленнями ---")
        print("4. Зашифрувати повідомлення (Текст -> Файл)")
        print("5. Розшифрувати повідомлення (Файл -> Текст)")
        print("6. Вихід")

        choice = input("\nВаш вибір: ")

        # 1. ГЕНЕРАЦІЯ
        if choice == "1":
            print("\n>> Генерація ключа")
            email = input("Введіть Email (напр. ivan@gmail.com): ")
            secret = input("Введіть секретну фразу: ")
            current_key = generate_key_from_data(email, secret)
            print("Ключ успішно створено на основі ваших даних!")

        # 2. ЕКСПОРТ
        elif choice == "2":
            if not current_key:
                print("Спочатку створіть ключ!")
                continue
            filename = input("Назва файлу для ключа (напр. key.key): ")
            save_file(filename, current_key)

        # 3. ІМПОРТ
        elif choice == "3":
            filename = input("Введіть назву файлу ключа: ")
            loaded_key = load_file(filename)
            if loaded_key:
                current_key = loaded_key
                print("Ключ завантажено! Тепер ви можете читати повідомлення друга.")

        # 4. ШИФРУВАННЯ
        elif choice == "4":
            if not current_key:
                print("Немає ключа! Згенеруйте або завантажте його.")
                continue

            msg = input("Введіть текст повідомлення: ")
            f = Fernet(current_key)
            encrypted_data = f.encrypt(msg.encode())

            print("\nЗашифровані дані:")
            print(f"\"{encrypted_data.decode()[:50]}...\"")

            save = input("Зберегти у файл для відправки? (y/n): ")
            if save.lower() == 'y':
                fname = input("Назва файлу повідомлення (напр. msg.txt): ")
                save_file(fname, encrypted_data)

        # 5. РОЗШИФРУВАННЯ
        elif choice == "5":
            if not current_key:
                print("Немає ключа! Завантажте ключ від відправника.")
                continue

            fname = input("Назва файлу повідомлення (напр. msg.txt): ")
            enc_data = load_file(fname)

            if enc_data:
                try:
                    f = Fernet(current_key)
                    decrypted_msg = f.decrypt(enc_data).decode()
                    print("\n📩 ВХІДНЕ ПОВІДОМЛЕННЯ:")
                    print("-" * 20)
                    print(decrypted_msg)
                    print("-" * 20)
                except Exception:
                    print("ПОМИЛКА: Ключ не підходить до цього повідомлення!")

        elif choice == "6":
            print("Роботу завершено.")
            break
        else:
            print("Невірний вибір.")


if __name__ == "__main__":
    menu()