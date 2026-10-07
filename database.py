import sqlite3

def init_db():
    conn = sqlite3.connect('waf_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            payload TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("Database is ready!")

if __name__ == '__main__':
    init_db()
