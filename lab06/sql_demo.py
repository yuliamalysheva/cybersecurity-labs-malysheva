import sqlite3
import os
from textwrap import dedent

DB_NAME = "sql_demo.db"


def init_db():
    # створює нову БД з тестовими користувачами (перезаписує попередню)
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            password TEXT NOT NULL
        );
        """
    )

    users = [
        ("admin", "System Administrator", "admin@example.com", "admin", "admin123"),
        ("student1", "Yulia Malysheva", "yulia@example.com", "student", "password1"),
        ("student2", "Ivan Petrenko", "ivan@example.com", "student", "qwerty"),
        ("teacher", "Anna Kuznetsova", "anna@example.com", "teacher", "secret"),
    ]

    cur.executemany(
        "INSERT INTO users (username, full_name, email, role, password) VALUES (?, ?, ?, ?, ?);",
        users,
    )

    conn.commit()
    conn.close()


def connect_db():
    return sqlite3.connect(DB_NAME)


# ВРАЗЛИВІ ФУНКЦІЇ


def vulnerable_login(conn, username: str, password: str):
    # вразливий логін: пряме підставлення введення користувача в SQL
    query = (
        "SELECT id, username, role, full_name "
        f"FROM users WHERE username = '{username}' AND password = '{password}';"
    )

    print("\n[ВРАЗЛИВИЙ ЗАПИТ]:")
    print(query)

    try:
        cur = conn.cursor()
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as e:
        print(f"\n[ПОМИЛКА БАЗИ ДАНИХ]: {e}")
        return

    if row:
        print("\nВхід ДОЗВОЛЕНО (вразлива версія).")
        print(f"ID: {row[0]}, username: {row[1]}, роль: {row[2]}, ПІБ: {row[3]}")
    else:
        print("\nНевірний логін або пароль (вразлива версія).")


def vulnerable_search(conn, term: str):
    # вразливий пошук: введення користувача підставляється прямо в LIKE
    query = (
        "SELECT id, username, full_name, email, role "
        f"FROM users WHERE username LIKE '%{term}%';"
    )

    print("\n[ВРАЗЛИВИЙ ЗАПИТ]:")
    print(query)

    try:
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
    except sqlite3.Error as e:
        print(f"\n[ПОМИЛКА БАЗИ ДАНИХ]: {e}")
        return

    if not rows:
        print("\nКористувачів не знайдено (вразлива версія).")
        return

    print("\nОтримано такі записи (вразлива версія):")
    for r in rows:
        print(f"- id={r[0]}, username={r[1]}, ПІБ={r[2]}, email={r[3]}, роль={r[4]}")


# ЗАХИЩЕНІ ФУНКЦІЇ


def safe_login(conn, username: str, password: str):
    # захищений логін: використовує параметризований запит
    # SQL-інʼєкція тут не працює
    query = (
        "SELECT id, username, role, full_name "
        "FROM users WHERE username = ? AND password = ?;"
    )

    print("\n[ЗАХИЩЕНИЙ ЗАПИТ]:")
    print("SELECT id, username, role, full_name FROM users WHERE username = ? AND password = ?;")
    print(f"[ПАРАМЕТРИ]: username={username!r}, password={password!r}")

    try:
        cur = conn.cursor()
        cur.execute(query, (username, password))
        row = cur.fetchone()
    except sqlite3.Error as e:
        print(f"\n[ПОМИЛКА БАЗИ ДАНИХ]: {e}")
        return

    if row:
        print("\nВхід ДОЗВОЛЕНО (захищена версія).")
        print(f"ID: {row[0]}, username: {row[1]}, роль: {row[2]}, ПІБ: {row[3]}")
    else:
        print("\nНевірний логін або пароль (захищена версія).")


def safe_search(conn, term: str):
    # захищений пошук: параметризований запит з LIKE
    # інʼєкція тут трактуєтсья як звичайний текст
    query = (
        "SELECT id, username, full_name, email, role "
        "FROM users WHERE username LIKE ?;"
    )

    print("\n[ЗАХИЩЕНИЙ ЗАПИТ]:")
    print("SELECT id, username, full_name, email, role FROM users WHERE username LIKE ?;")
    print(f"[ПАРАМЕТРИ]: term=%{term!r}%")

    try:
        cur = conn.cursor()
        cur.execute(query, (f"%{term}%",))
        rows = cur.fetchall()
    except sqlite3.Error as e:
        print(f"\n[ПОМИЛКА БАЗИ ДАНИХ]: {e}")
        return

    if not rows:
        print("\nКористувачів не знайдено (захищена версія).")
        return

    print("\n[РЕЗУЛЬТАТ]: Отримано такі записи (захищена версія):")
    for r in rows:
        print(f"- id={r[0]}, username={r[1]}, ПІБ={r[2]}, email={r[3]}, роль={r[4]}")


# ДОДАТКОВІ ДОПОМІЖНІ ФУНКЦІЇ


def show_all_users(conn):
    cur = conn.cursor()
    cur.execute("SELECT id, username, full_name, email, role FROM users ORDER BY id;")
    rows = cur.fetchall()
    print("\n[ВМІСТ ТАБЛИЦІ users]:")
    for r in rows:
        print(f"- id={r[0]}, username={r[1]}, ПІБ={r[2]}, email={r[3]}, роль={r[4]}")


def print_banner():
    print(
        dedent(
            """
            =========================================================
               ДЕМО-ЗАСТОСУНОК: SQL-ІНʼЄКЦІЇ ТА ЗАХИСТ ВІД НИХ
            =========================================================
            База даних: SQLite (sql_demo.db)
            Таблиця: users (id, username, full_name, email, role, password)

            Підказки для тестування інʼєкцій:
              - username: admin
              - пароль (реальний): admin123

              Спробуйте ці payload'и:
                * ' OR '1'='1--
                * admin'--
                * %' OR '1'='1--

            Обирайте пункт меню, щоб побачити різницю між
            вразливою та захищеною версіями.
            """
        )
    )


def print_menu():
    print(
        dedent(
            """
            ------------------------- МЕНЮ -------------------------
            1. Показати всіх користувачів (просто для огляду)
            2. Вразливий логін (SQL injection працює)
            3. Захищений логін (prepared statement)
            4. Вразливий пошук користувачів
            5. Захищений пошук користувачів
            0. Вихід
            --------------------------------------------------------
            """
        )
    )


def main():
    init_db()
    conn = connect_db()

    print_banner()

    while True:
        print_menu()
        choice = input("Оберіть пункт меню: ").strip()

        if choice == "0":
            print("\nЗавершення роботи.")
            break

        elif choice == "1":
            show_all_users(conn)

        elif choice == "2":
            print("\n[ВРАЗЛИВИЙ ЛОГІН]")
            username = input("Введіть username: ").strip()
            password = input("Введіть пароль: ").strip()
            vulnerable_login(conn, username, password)

        elif choice == "3":
            print("\n[ЗАХИЩЕНИЙ ЛОГІН]")
            username = input("Введіть username: ").strip()
            password = input("Введіть пароль: ").strip()
            safe_login(conn, username, password)

        elif choice == "4":
            print("\n[ВРАЗЛИВИЙ ПОШУК]")
            term = input("Введіть рядок для пошуку за username: ").strip()
            vulnerable_search(conn, term)

        elif choice == "5":
            print("\n[ЗАХИЩЕНИЙ ПОШУК]")
            term = input("Введіть рядок для пошуку за username: ").strip()
            safe_search(conn, term)

        else:
            print("\nНевідомий пункт меню, спробуйте ще раз.")

    conn.close()


if __name__ == "__main__":
    main()