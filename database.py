import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'scans.db')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            device_name TEXT,
            scan_date TEXT NOT NULL,
            total_score INTEGER NOT NULL,
            results_json TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def save_scan(device_ip, device_name, total_score, results_json):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO scans (device_ip, device_name, scan_date, total_score, results_json) VALUES (?, ?, datetime("now"), ?, ?)',
        (device_ip, device_name, total_score, results_json)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT id, device_ip, device_name, scan_date, total_score FROM scans ORDER BY scan_date DESC')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted > 0
