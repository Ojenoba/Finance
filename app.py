import os
import sqlite3
from cs50 import SQL
import random
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)
app.debug = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
conn = sqlite3.connect("finance.db", check_same_thread=False)
conn.row_factory = sqlite3.Row
cur = conn.cursor()



@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def home():
    """New homepage for app"""
    return render_template("home.html")

@app.route("/index", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks from database"""

    user_id = session["user_id"]

    # Get user's cash balance
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # Get user's stock holdings (aggregate purchases)
    stocks = db.execute("""
        SELECT symbol, SUM(shares) AS total_shares
        FROM purchases
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, user_id)

    portfolio = []
    total_stock_value = 0

    # For now, use placeholder prices (later you can plug in lookup() or mock values)
    mock_prices = {
        "AAPL": 150.25,
        "MSFT": 300.10,
        "TSLA": 700.00,
        "GOOGL": 120.50,
        "AMZN": 250.75
    }

    for stock in stocks:
        symbol = stock["symbol"]
        shares = stock["total_shares"]

        # Use mock price if available, else default
        price = mock_prices.get(symbol, 100.00)
        stock_value = price * shares
        total_stock_value += stock_value

        # Mock gain/loss and change for now
        gain_loss = round(stock_value * 0.05, 2)   # pretend 5% gain
        change = round(random.uniform(-3, 3), 2)   # random % change

        portfolio.append({
            "symbol": symbol,
            "name": symbol,  # later you can map to full company names
            "shares": shares,
            "price": price,
            "total_value": stock_value,
            "gain_loss": gain_loss,
            "change": change
        })

    # Grand total
    grand_total = user_cash + total_stock_value

    # Top gainer/loser
    if portfolio:
        top_gainer = max(portfolio, key=lambda s: s["change"])
        top_loser = min(portfolio, key=lambda s: s["change"])
    else:
        top_gainer = {"symbol": "N/A", "change": 0}
        top_loser = {"symbol": "N/A", "change": 0}

    # Diversification score (simple logic: number of unique holdings * 10)
    diversification_score = len(portfolio) * 10

    # Mock performance history (later you can query history table)
    performance_history = [
        {"date": "2026-01-01", "value": 7500},
        {"date": "2026-01-02", "value": 7700},
        {"date": "2026-01-03", "value": 7600},
        {"date": "2026-01-04", "value": 7800},
        {"date": "2026-01-05", "value": 7900}
    ]

    # Mock news feed (later you can query news table)
    news = [
        {"title": "Apple hits new high", "url": "https://example.com/apple"},
        {"title": "Microsoft earnings report", "url": "https://example.com/msft"},
        {"title": "Tesla expands production", "url": "https://example.com/tesla"}
    ]

    return render_template(
        "index.html",
        portfolio=portfolio,
        cash=user_cash,
        grand_total=grand_total,
        top_gainer=top_gainer,
        top_loser=top_loser,
        diversification_score=diversification_score,
        performance_history=performance_history,
        news=news
    )


@app.route("/buy", methods=["GET", "POST"])
@app.route("/buy/<symbol>", methods=["GET", "POST"])
@login_required
def buy(symbol=None):
    """Buy shares of stock and record in database."""

    if request.method == "POST":
        # Normalize input
        symbol = request.form.get("symbol", "").upper().strip()
        shares = request.form.get("shares")

        # Validate stock symbol
        if not symbol:
            return apology("must provide stock symbol")

        # Connect to DB
        conn = sqlite3.connect("finance.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Look up latest price for symbol
        cur.execute(
            "SELECT price FROM purchases WHERE symbol = ? ORDER BY transacted DESC LIMIT 1",
            (symbol,)
        )
        row = cur.fetchone()
        if row is None:
            conn.close()
            return apology("invalid stock symbol")

        price = row["price"]

        # Validate shares input
        try:
            shares = int(shares)
            if shares <= 0:
                conn.close()
                return apology("must buy at least one share")
        except ValueError:
            conn.close()
            return apology("shares must be a positive integer")

        # Get user's current cash balance
        user_id = session["user_id"]
        cur.execute("SELECT cash FROM users WHERE id = ?", (user_id,))
        user_cash = cur.fetchone()["cash"]

        # Calculate total purchase cost
        total_cost = price * shares

        # Ensure user has enough funds
        if user_cash < total_cost:
            conn.close()
            return apology("insufficient funds")

        # Deduct purchase cost and update user's cash balance
        cur.execute("UPDATE users SET cash = cash - ? WHERE id = ?", (total_cost, user_id))

        # Record transaction in purchases table
        cur.execute(
            "INSERT INTO purchases (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            (user_id, symbol, shares, price)
        )

        conn.commit()
        conn.close()

        # Redirect back to portfolio page
        return redirect("/index")

    # GET request → render form with optional prefilled symbol
    return render_template("buy.html", prefilled_symbol=symbol.upper() if symbol else "")


@app.route("/history")
@login_required
def history():
    """Show history of transactions."""

    user_id = session["user_id"]

    # Retrieve all transactions for the user
    transactions = db.execute(
        "SELECT symbol, shares, price, transacted FROM purchases WHERE user_id = ? ORDER BY transacted DESC",
        user_id
    )

    formatted_transactions = []
    total_buys = 0
    total_sells = 0
    net_shares = 0
    total_value = 0

    for transaction in transactions:
        shares = transaction["shares"]
        price = transaction["price"]

        # Update summary stats
        if shares > 0:
            total_buys += shares
        else:
            total_sells += abs(shares)

        net_shares += shares
        total_value += abs(shares * price)

        formatted_transactions.append({
            "symbol": transaction["symbol"],
            "shares": shares,
            "price": usd(price),
            "timestamp": transaction["transacted"],
            "type": "Bought" if shares > 0 else "Sold"
        })

    # Summary dictionary
    summary = {
        "total_buys": total_buys,
        "total_sells": total_sells,
        "net_shares": net_shares,
        "total_value": total_value
    }

    return render_template("history.html", transactions=formatted_transactions, summary=summary)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/index")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Ensure the user provided a stock symbol
        if not symbol:
            return apology("must provide stock symbol")

        # Lookup stock information
        stock = lookup(symbol)

        # Handle invalid symbols
        if stock is None:
            return apology("invalid stock symbol")

        # Render quoted.html with stock details
        return render_template("quoted.html", name=stock["name"], price=usd(stock["price"]), symbol=stock["symbol"])

    # Render the quote form
    return render_template("quote.html")


# Connect to CS50's database
db = SQL("sqlite:///finance.db")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure all fields are filled
        if not username or not password or not confirmation:
            return apology("All fields must be filled")

        # Ensure password and confirmation match
        if password != confirmation:
            return apology("Passwords must match")

        # Check if username already exists
        try:
            hashed_password = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)
        except ValueError:
            return apology("Username already exists")

        # Redirect user to login page
        return redirect("/login")

    return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@app.route("/sell/<symbol>", methods=["GET", "POST"])
@login_required
def sell(symbol=None):
    """Sell shares of stock and update database."""

    user_id = session["user_id"]

    # Connect to DB
    conn = sqlite3.connect("finance.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Retrieve user's owned stocks for dropdown
    cur.execute(
        "SELECT symbol, SUM(shares) AS total_shares FROM purchases WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        (user_id,)
    )
    stocks = cur.fetchall()

    if request.method == "POST":
        symbol = request.form.get("symbol", "").upper().strip()
        shares = request.form.get("shares")

        # Ensure symbol is provided
        if not symbol:
            conn.close()
            return apology("must select a stock to sell")

        # Ensure user owns the stock
        cur.execute(
            "SELECT SUM(shares) AS total_shares FROM purchases WHERE user_id = ? AND symbol = ?",
            (user_id, symbol)
        )
        stock_data = cur.fetchone()
        if not stock_data or stock_data["total_shares"] is None:
            conn.close()
            return apology("you do not own this stock")

        # Validate shares input
        try:
            shares = int(shares)
            if shares <= 0:
                conn.close()
                return apology("must sell at least one share")
        except ValueError:
            conn.close()
            return apology("shares must be a positive integer")

        # Check if user has enough shares to sell
        available_shares = stock_data["total_shares"]
        if shares > available_shares:
            conn.close()
            return apology("not enough shares to sell")

        # Look up latest price for symbol
        cur.execute(
            "SELECT price FROM purchases WHERE symbol = ? ORDER BY transacted DESC LIMIT 1",
            (symbol,)
        )
        row = cur.fetchone()
        if row is None:
            conn.close()
            return apology("invalid stock symbol")

        price = row["price"]

        # Calculate earnings from selling
        earnings = price * shares

        # ✅ Add earnings back to user's cash balance
        cur.execute("UPDATE users SET cash = cash + ? WHERE id = ?", (earnings, user_id))

        # Record transaction (negative shares indicate a sale)
        cur.execute(
            "INSERT INTO purchases (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            (user_id, symbol, -shares, price)
        )

        conn.commit()
        conn.close()

        # Redirect back to portfolio page
        return redirect("/index")

    conn.close()
    # GET request → render form with optional prefilled symbol
    return render_template("sell.html", stocks=stocks, prefilled_symbol=symbol.upper() if symbol else "")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow users to change their password."""

    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        user_id = session["user_id"]
        user_data = db.execute("SELECT hash FROM users WHERE id = ?", user_id)[0]

        # Validate old password
        if not check_password_hash(user_data["hash"], old_password):
            return apology("Incorrect current password")

        # Validate new password fields
        if not new_password or not confirmation:
            return apology("Must provide new password and confirmation")
        if new_password != confirmation:
            return apology("Passwords must match")

        # Update password in database
        hashed_password = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_password, user_id)

        flash("Password successfully changed!")
        return redirect("/")

    return render_template("change_password.html")


@app.route("/add-funds", methods=["GET", "POST"])
@login_required
def add_funds():
    """Allow users to add more cash to their account."""

    if request.method == "POST":
        amount = request.form.get("amount")

        # Validate input
        try:
            amount = float(amount)
            if amount <= 0:
                return apology("must add a positive amount")
        except ValueError:
            return apology("amount must be a number")

        user_id = session["user_id"]

        # Update user's cash balance
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", amount, user_id)

        flash(f"${amount:,.2f} successfully added!")
        return redirect("index.html")

    return render_template("add_funds.html")



@app.route("/autocomplete")
def autocomplete():
    query = request.args.get("query", "").upper().strip()
    if not query:
        return jsonify([])

    cur.execute("SELECT DISTINCT symbol FROM purchases WHERE symbol LIKE ? LIMIT 10", (query + "%",))
    rows = cur.fetchall()

    results = []
    for row in rows:
        symbol = row["symbol"]

        cur.execute("SELECT price FROM purchases WHERE symbol = ? ORDER BY transacted DESC LIMIT 1", (symbol,))
        price_row = cur.fetchone()
        price = price_row["price"] if price_row else None

        results.append({
            "symbol": symbol,
            "name": symbol,
            "price": price
        })

    return jsonify(results)


@app.route("/export", methods=["GET", "POST"])
@login_required
def export():
    """Allow users to export their portfolio data."""

    if request.method == "POST":
        format = request.form.get("format")

        user_id = session["user_id"]

        # Fetch user's portfolio data
        rows = db.execute("SELECT symbol, shares, price FROM purchases WHERE user_id = ?", user_id)

        # Convert to CSV or Excel format
        if format == "csv":
            return render_template("export.csv", rows=rows)
        elif format == "xlsx":
            return render_template("export.xlsx", rows=rows)
        elif format == "pdf":
            return render_template("export.pdf", rows=rows)

    return render_template("export.html")
