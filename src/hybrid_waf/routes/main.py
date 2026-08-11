from flask import Blueprint, render_template, redirect, url_for
import sqlite3

main_bp = Blueprint('main', __name__)

# Helper function: Project me kahin se bhi call karke database me entry karne ke liye
def log_to_db(payload, attack_type):
    try:
        conn = sqlite3.connect('waf_logs.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO attack_logs (payload, attack_type, status) VALUES (?, ?, ?)",
            (payload, attack_type, "BLOCKED")
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database logging error: {e}")

# 1. Main Landing Page (Hero section wala page load karega)
@main_bp.route('/')
def index():
    return render_template('index.html')

# 2. Home route ko bhi main page par redirect kar dete hain
@main_bp.route('/home')
def home():
    return render_template('index.html')

# 3. Purane logs raste ko naye dashboard par redirect kar dete hain taaki maza aa jaye
@main_bp.route('/logs')
def view_logs():
    return redirect('/dashboard')
