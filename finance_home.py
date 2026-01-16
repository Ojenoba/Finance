import sqlite3
import random
import datetime

# Connect to SQLite database (creates finance.db if it doesn't exist)
conn = sqlite3.connect("finance.db")
cur = conn.cursor()

# Drop old tables if they exist (for clean setup)
cur.execute("DROP TABLE IF EXISTS users")
cur.execute("DROP TABLE IF EXISTS purchases")
cur.execute("DROP TABLE IF EXISTS history")
cur.execute("DROP TABLE IF EXISTS news")

# Create tables
cur.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    cash REAL NOT NULL DEFAULT 10000.00
)
""")

cur.execute("""
CREATE TABLE purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    symbol TEXT NOT NULL,
    shares INTEGER NOT NULL,
    price REAL NOT NULL,
    transacted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")

cur.execute("""
CREATE TABLE history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date DATE NOT NULL,
    portfolio_value REAL NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")

cur.execute("""
CREATE TABLE news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    published TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# Insert a test user
cur.execute("""
INSERT INTO users (username, hash, cash)
VALUES (?, ?, ?)
""", ("ojenoba", "hashed_password_here", 10000.00))

user_id = cur.lastrowid

# Mock stock symbols
symbols = ["AAPL", "MSFT", "TSLA", "GOOGL", "AMZN", "NFLX", "NVDA", "META", "IBM", "ORCL"]

# Generate ~500 purchases
for _ in range(500):
    symbol = random.choice(symbols)
    shares = random.randint(1, 20)
    price = round(random.uniform(50, 1000), 2)
    date = datetime.date(2025, random.randint(1, 12), random.randint(1, 28))

    cur.execute("""
    INSERT INTO purchases (user_id, symbol, shares, price, transacted)
    VALUES (?, ?, ?, ?, ?)
    """, (user_id, symbol, shares, price, date))

# Commit changes and close
conn.commit()
conn.close()

print("finance.db created with users and ~500 purchases.")