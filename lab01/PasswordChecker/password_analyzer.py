import re


def analyze_password(password, name, birth_date):
    # Нормалізація вводу до нижнього регістру для перевірки без врахування регістру
    password_lower = password.lower()
    name_lower = name.lower()

    # Витягування частин дати народження
    try:
        day, month, year = birth_date.split('.')
        # Перевірка формату дати
        if not (len(day) == 2 and len(month) == 2 and len(
                year) == 4 and day.isdigit() and month.isdigit() and year.isdigit()):
            return "Помилка: Дата народження має бути у форматі DD.MM.YYYY.", 0, "Виправте формат дати народження."
    except ValueError:
        return "Помилка: Дата народження має бути у форматі DD.MM.YYYY.", 0, "Виправте формат дати народження."

    # 1. Перевірка наявності персональних даних у паролі
    personal_links = []
    if name_lower in password_lower:
        personal_links.append(f"Пароль містить ім'я '{name}'")
    if year in password:
        personal_links.append(f"Пароль містить рік народження '{year}'")
    if month in password:
        personal_links.append(f"Пароль містить місяць народження '{month}'")
    if day in password:
        personal_links.append(f"Пароль містить день народження '{day}'")

    # Формування результату у вигляді нумерованого списку
    if personal_links:
        analysis_result = "Виявлені зв'язки з особистими даними:\n" + "\n".join(
            f"{i + 1}. {link}" for i, link in enumerate(personal_links))
    else:
        analysis_result = "Зв'язків з особистими даними не виявлено."

    # 2. Оцінка складності пароля
    score = 0

    # Довжина пароля (не накопичувальна)
    length = len(password)
    if length >= 16:
        score += 4
    elif length >= 12:
        score += 3
    elif length >= 8:
        score += 2
    elif length >= 6:
        score += 1

    # Різноманітність символів
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    diversity_count = sum([has_upper, has_lower, has_digit, has_special])
    score += diversity_count  # До 4 балів

    # Унікальність символів
    if len(set(password)) == len(password):
        score += 2  # Додаткові бали, якщо всі символи унікальні

    # Перевірка на поширені словникові слова
    common_words = ['password', '123456', 'qwerty', 'letmein', 'welcome', 'admin']
    if any(word in password_lower for word in common_words):
        score -= 1  # Штраф за використання поширених слів

    # Штраф за наявність персональних даних у паролі: -1 за кожен зв'язок
    score -= len(personal_links)

    # Обмеження оцінки від 0 до 10
    score = max(0, min(10, score))

    # 3. Формування рекомендацій
    recommendations = []
    if personal_links:
        recommendations.append("Уникайте використання особистих даних у паролі (імена, дати народження тощо).")
    if length < 16:
        recommendations.append("Збільште довжину пароля до щонайменше 16 символів для максимальної безпеки.")
    if diversity_count < 4:
        missing = []
        if not has_upper: missing.append("великі літери")
        if not has_lower: missing.append("малі літери")
        if not has_digit: missing.append("цифри")
        if not has_special: missing.append("спеціальні символи")
        recommendations.append(f"Додайте {', '.join(missing)} для підвищення різноманітності.")
    if len(set(password)) != len(password):
        recommendations.append("Використовуйте унікальні символи без повторень для підвищення безпеки.")
    if score < 10:
        recommendations.append("Використовуйте менеджер паролів для генерації сильних, унікальних паролів.")

    # Формування рекомендацій у вигляді нумерованого списку
    if recommendations:
        recommendations_str = "Рекомендації:\n" + "\n".join(f"{i + 1}. {rec}" for i, rec in enumerate(recommendations))
    else:
        recommendations_str = "Пароль достатньо безпечний, вітаємо!"

    return analysis_result, score, recommendations_str


# Введення даних користувача через консоль
password = input("Введіть пароль: ")
name = input("Введіть ім'я: ")
birth_date = input("Введіть дату народження (DD.MM.YYYY): ")

# Аналіз та вивід результатів
analysis, score, recs = analyze_password(password, name, birth_date)
print("\nАналіз:", analysis)
print("\nОцінка (від 1 до 10):", score)
print("\n" + recs)