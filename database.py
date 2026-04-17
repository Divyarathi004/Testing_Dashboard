import sqlite3

conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

def create_tables():
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        filename TEXT,
        findings INTEGER,
        compliance REAL
    )
    """)

    conn.commit()