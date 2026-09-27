"""User lookup helpers."""

import sqlite3


def get_connection(path="users.db"):
    return sqlite3.connect(path)


def find_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM users WHERE name = ?", (username,))
    return cursor.fetchone()


def handle_request(username):
    conn = get_connection()
    try:
        return find_user(conn, username)
    finally:
        conn.close()
