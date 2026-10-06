import sqlite3
from datetime import datetime


DATABASE_NAME = "url_history.db"


def create_database():

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            url_length INTEGER,
            uses_https TEXT,
            number_of_dots INTEGER,
            number_of_hyphens INTEGER,
            number_of_digits INTEGER,
            checked_at TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_history(url, result, features):

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO url_history
        (
            url,
            result,
            url_length,
            uses_https,
            number_of_dots,
            number_of_hyphens,
            number_of_digits,
            checked_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        str(result),
        int(features["URL Length"]),
        str(features["Uses HTTPS"]),
        int(features["Number of Dots"]),
        int(features["Number of Hyphens"]),
        int(features["Number of Digits"]),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def get_history():

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM url_history
        ORDER BY id DESC
    """)

    history = cursor.fetchall()

    connection.close()

    return history