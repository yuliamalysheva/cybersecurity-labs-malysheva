ukr_lower = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
ukr_upper = 'АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ'

def caesar_encrypt(text, shift):
    result = ''
    for char in text:
        if char.isupper():
            if char in ukr_upper:
                idx = (ukr_upper.index(char) + shift) % 33
                result += ukr_upper[idx]
            else:
                result += char
        elif char.islower():
            if char in ukr_lower:
                idx = (ukr_lower.index(char) + shift) % 33
                result += ukr_lower[idx]
            else:
                result += char
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift % 33)

def vigenere_encrypt(text, key):
    key = ''.join(c for c in key.lower() if c in ukr_lower)
    if not key:
        return text
    key_idx = 0
    result = ''
    for char in text:
        if char.isupper():
            if char in ukr_upper:
                shift = ukr_lower.index(key[key_idx % len(key)])
                idx = (ukr_upper.index(char) + shift) % 33
                result += ukr_upper[idx]
                key_idx += 1
            else:
                result += char
        elif char.islower():
            if char in ukr_lower:
                shift = ukr_lower.index(key[key_idx % len(key)])
                idx = (ukr_lower.index(char) + shift) % 33
                result += ukr_lower[idx]
                key_idx += 1
            else:
                result += char
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    key = ''.join(c for c in key.lower() if c in ukr_lower)
    if not key:
        return text
    key_idx = 0
    result = ''
    for char in text:
        if char.isupper():
            if char in ukr_upper:
                shift = ukr_lower.index(key[key_idx % len(key)])
                idx = (ukr_upper.index(char) - shift) % 33
                result += ukr_upper[idx]
                key_idx += 1
            else:
                result += char
        elif char.islower():
            if char in ukr_lower:
                shift = ukr_lower.index(key[key_idx % len(key)])
                idx = (ukr_lower.index(char) - shift) % 33
                result += ukr_lower[idx]
                key_idx += 1
            else:
                result += char
        else:
            result += char
    return result

#введення даних
print("Введіть день народження (число дня, 1-31):")
try:
    birth_day = int(input().strip())
    while birth_day < 1 or birth_day > 31:
        print("Неправильне число. Введіть від 1 до 31:")
        birth_day = int(input().strip())
except ValueError:
    print("Помилка: введіть ціле число від 1 до 31.")
    exit(1)
shift = birth_day

print("Введіть ім'я для ключа Віженера (лише літери українського алфавіту):")
name = input().strip()
if not any(c in ukr_lower + ukr_upper for c in name):
    print("Помилка: ім'я має містити хоча б одну літеру українського алфавіту.")
    exit(1)

print("Введіть текст для шифрування:")
text = input().strip()

#шифрування та розшифрування
caesar_enc = caesar_encrypt(text, shift)
caesar_dec = caesar_decrypt(caesar_enc, shift)
vig_enc = vigenere_encrypt(text, name)
vig_dec = vigenere_decrypt(vig_enc, name)

#вивід результатів
print("\nРезультати:")
print("Оригінальний текст:", text)
print("Шифр Цезаря (зашифрований):", caesar_enc)
print("Шифр Цезаря (розшифрований):", caesar_dec)
print("Шифр Віженера (зашифрований):", vig_enc)
print("Шифр Віженера (розшифрований):", vig_dec)

#таблиця порівняння
print("\nТаблиця порівняння:")
print("Параметр\t\t\tЦезар\t\t\tВіженер")
print("Довжина результату\t\t", len(caesar_enc), "\t\t\t", len(vig_enc))
print("Читабельність\t\t\tЧастково\t\tНе читабельна")
print("Складність ключа\t\tНизька\t\t\tСередня")

#висновки
print("\nВисновки про стійкість:")
print("Шифр Цезаря: Простий і вразливий до brute force атаки через обмежену кількість зсувів (33 для українського алфавіту).")
print("Шифр Віженера: Стійкіший, оскільки використовує ключ-слово, але вразливий до частотного аналізу, особливо при короткому ключі.")

#brute-force атака
print("\nДемонстрація brute force атаки для шифру Цезаря:")
for s in range(33):
    dec_attempt = caesar_decrypt(caesar_enc, s)
    print(f"Зсув {s}: {dec_attempt}")