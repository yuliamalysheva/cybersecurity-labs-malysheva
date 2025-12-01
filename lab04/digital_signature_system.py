import hashlib
import json
import os
import random
import math

KEY_FILE = "keys.json"

class DigitalSignatureSystem:
    def __init__(self):
        self.keys = []          # список ключів
        self.active_key = None  # поточний обраний ключ
        self.load_keys()

    # РОБОТА З ФАЙЛОМ КЛЮЧІВ
    def load_keys(self):
    # читає список ключів із файлу keys.json (якщо існує)
        if os.path.exists(KEY_FILE):
            try:
                with open(KEY_FILE, "r", encoding="utf-8") as f:
                    self.keys = json.load(f)
                print(f"Завантажено {len(self.keys)} ключ(ів).\n")
            except Exception as e:
                print("Неможливо прочитати keys.json:", e)
                print("Ключі буде створено заново.\n")
                self.keys = []
        else:
            print("Файл ключів не знайдено. Створіть новий ключ.\n")
            self.keys = []

    def save_keys(self):
        # зберігає всі ключі у keys.json
        with open(KEY_FILE, "w", encoding="utf-8") as f:
            json.dump(self.keys, f, indent=4, ensure_ascii=False)
        print("Ключі збережено у", KEY_FILE, "\n")

    # ВИБІР, СТВОРЕННЯ, ВИДАЛЕННЯ КЛЮЧІВ
    def select_key(self):
        # меню вибору активного ключа
        if not self.keys:
            print("Ключів поки немає. Буде створено новий.\n")
            self.create_new_key()
            return

        while True:
            print("=== ВИБІР КЛЮЧА ===")
            for i, key in enumerate(self.keys, 1):
                active_mark = " (активний)" if self.active_key == key else ""
                print(f"{i} — {key['name']}{active_mark}")
            print(f"{len(self.keys) + 1} — Створити новий ключ")
            print("====================")

            choice = input("Ваш вибір: ")
            if not choice.isdigit():
                print("Потрібно ввести число.\n")
                continue

            choice = int(choice)

            if 1 <= choice <= len(self.keys):
                self.active_key = self.keys[choice - 1]
                print(f"Обрано ключ: {self.active_key['name']}\n")
                return
            elif choice == len(self.keys) + 1:
                self.create_new_key()
                return
            else:
                print("Невірний вибір. Спробуйте ще.\n")

    def create_new_key(self):
        # створює новий асиметричний ключ (спрощений RSA) на основі персональних даних
        print("\n=== Генерація нового ключа (RSA-подібний) ===")
        name = input("Назва ключа (для списку, наприклад: Petrenko_main): ")
        surname = input("Прізвище: ")
        birthdate = input("Дата народження (наприклад 15031995): ")
        secret = input("Секретне слово: ")

        personal = surname + birthdate + secret
        seed = int(hashlib.sha256(personal.encode()).hexdigest(), 16)
        rnd = random.Random(seed)

        # генерація двох простих чисел p, q
        p = self._generate_prime(rnd, 2000, 10000)
        q = self._generate_prime(rnd, 2000, 10000)
        while q == p:
            q = self._generate_prime(rnd, 2000, 10000)

        n = p * q
        phi = (p - 1) * (q - 1)

        # вибираємо публічний експонент e
        e_candidates = [65537, 257, 17, 5, 3]
        e = None
        for cand in e_candidates:
            if math.gcd(cand, phi) == 1:
                e = cand
                break
        if e is None:
            # якщо раптом не підійшло — беремо випадкове непарне
            while True:
                cand = rnd.randrange(3, phi - 1, 2)
                if math.gcd(cand, phi) == 1:
                    e = cand
                    break

        # d — мультиплікативно обернене до e за модулем phi
        d = self._modinv(e, phi)

        new_key = {
            "name": name,
            "n": n,
            "e": e,  # публічний експонент
            "d": d   # приватний експонент
        }

        self.keys.append(new_key)
        self.save_keys()

        self.active_key = new_key

        print("Створено новий ключ.")
        print(f"p = {p}")
        print(f"q = {q}")
        print(f"n = {n}")
        print(f"e (public)  = {e}")
        print(f"d (private) = {d}\n")

    def delete_key(self):
        # видаляє ключ зі списку
        if not self.keys:
            print("Немає ключів для видалення.\n")
            return

        print("\n=== ВИДАЛЕННЯ КЛЮЧА ===")
        for i, key in enumerate(self.keys, 1):
            active_mark = " (активний)" if self.active_key == key else ""
            print(f"{i} — {key['name']}{active_mark}")
        print("==========================")

        choice = input("Виберіть номер ключа для видалення: ")
        if not choice.isdigit():
            print("Помилка: потрібно ввести число.\n")
            return

        choice = int(choice)
        if not (1 <= choice <= len(self.keys)):
            print("Невірний номер ключа.\n")
            return

        key_to_delete = self.keys[choice - 1]
        confirm = input(f"Справді видалити ключ '{key_to_delete['name']}'? (y/n): ").lower()
        if confirm not in ("y", "yes", "д", "так"):
            print("Скасовано.\n")
            return

        self.keys.remove(key_to_delete)
        self.save_keys()
        print(f"Ключ '{key_to_delete['name']}' видалено.\n")

        if self.active_key == key_to_delete:
            self.active_key = None
            if self.keys:
                print("Оберіть новий активний ключ.\n")
                self.select_key()
            else:
                print("Ключів більше немає. Створіть новий.\n")

    # ДОПОМІЖНІ ФУНКЦІЇ ДЛЯ RSA
    def _is_prime(self, n: int) -> bool:
        if n < 2:
            return False
        if n % 2 == 0:
            return n == 2
        r = int(n ** 0.5) + 1
        for i in range(3, r, 2):
            if n % i == 0:
                return False
        return True

    def _generate_prime(self, rnd: random.Random, low: int, high: int) -> int:
        # простий генератор випадкового простого числа в діапазоні
        while True:
            candidate = rnd.randrange(low, high)
            # робимо непарним
            if candidate % 2 == 0:
                candidate += 1
            if self._is_prime(candidate):
                return candidate

    def _egcd(self, a, b):
        # розширений алгоритм Евкліда
        if a == 0:
            return b, 0, 1
        g, y, x = self._egcd(b % a, a)
        return g, x - (b // a) * y, y

    def _modinv(self, a, m):
        # обчислює обернене за модулем m (a^-1 mod m)
        g, x, _ = self._egcd(a, m)
        if g != 1:
            raise Exception("modular inverse does not exist")
        return x % m

    # ХЕШУВАННЯ ТА ФАЙЛИ
    def sha256_file(self, path: str) -> int:
        # повертає SHA256-хеш файлу як ціле число
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            sha.update(f.read())
        return int(sha.hexdigest(), 16)

    def resolve_path(self, user_input: str) -> str:
        # дозволяє вводити або повний шлях, або просто назву файлу
        if os.path.exists(user_input):
            return user_input
        local = os.path.join(os.getcwd(), user_input)
        if os.path.exists(local):
            return local
        raise FileNotFoundError("Файл не знайдено!")

    # ПІДПИС І ПЕРЕВІРКА (АСИМЕТРИЧНІ)
    def sign(self, file_path: str):
        # створює цифровий підпис файлу:
        # підпис автоматично зберігається у file_path + ".sig".

        if not self.active_key:
            print("Спочатку оберіть або створіть ключ!\n")
            return

        n = self.active_key["n"]
        d = self.active_key["d"]

        file_hash = self.sha256_file(file_path) % n
        signature = pow(file_hash, d, n)

        sig_path = file_path + ".sig"
        with open(sig_path, "w", encoding="utf-8") as f:
            f.write(str(signature))

        print(f"\nХеш файлу (mod n): {file_hash}")
        print(f"Підпис (hash^d mod n): {signature}")
        print(f"Підпис збережено у: {sig_path}\n")

    def verify(self, file_path: str):
        # перевіряє підпис файлу:
        # порівнюємо з поточним хешем файлу (mod n).
        if not self.active_key:
            print("Спочатку оберіть ключ!\n")
            return

        n = self.active_key["n"]
        e = self.active_key["e"]

        sig_path = file_path + ".sig"
        if not os.path.exists(sig_path):
            print("Підпис для цього файлу не знайдено:", sig_path, "\n")
            return

        with open(sig_path, "r", encoding="utf-8") as f:
            signature = int(f.read().strip())

        current_hash = self.sha256_file(file_path) % n
        hash_from_signature = pow(signature, e, n)

        print(f"\nПоточний хеш файлу (mod n): {current_hash}")
        print(f"Хеш, відновлений з підпису (sig^e mod n): {hash_from_signature}")

        if current_hash == hash_from_signature:
            print("\n[✔] Підпис ДІЙСНИЙ. Файл не змінено.\n")
        else:
            print("\n[✖] Підпис НЕДІЙСНИЙ або файл змінено!\n")


# МЕНЮ
def main_menu():
    system = DigitalSignatureSystem()
    system.select_key()  # одразу обираємо/створюємо активний ключ

    while True:
        print("========= МЕНЮ =========")
        print("1 — Обрати інший ключ")
        print("2 — Створити цифровий підпис файлу")
        print("3 — Перевірити підпис файлу")
        print("4 — Видалити ключ")
        print("0 — Вихід")
        print("========================")

        choice = input("Ваш вибір: ")

        if choice == "1":
            system.select_key()

        elif choice == "2":
            file_input = input("Шлях або назва файлу: ")
            try:
                path = system.resolve_path(file_input)
                system.sign(path)
            except Exception as e:
                print("Помилка:", e, "\n")

        elif choice == "3":
            file_input = input("Шлях або назва файлу: ")
            try:
                path = system.resolve_path(file_input)
                system.verify(path)
            except Exception as e:
                print("Помилка:", e, "\n")

        elif choice == "4":
            system.delete_key()

        elif choice == "0":
            print("Вихід...")
            break

        else:
            print("Невірний вибір! Спробуйте ще.\n")


if __name__ == "__main__":
    main_menu()
