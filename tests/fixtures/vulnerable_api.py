"""Example vulnerable FastAPI application for testing."""
from fastapi import FastAPI, Request
import sqlite3
import jwt

app = FastAPI()

# VULNERABLE: Hardcoded secret
SECRET_KEY = "supersecret123"
DATABASE_URL = "database.db"


@app.get("/users/{user_id}")
def get_user(user_id: str):
    """Vulnerable SQL injection endpoint."""
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()

    # VULNERABLE: String interpolation in SQL
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()

    return {"user": user}


@app.post("/search")
async def search(request: Request):
    """Vulnerable SQL injection via f-string."""
    data = await request.json()
    query = data.get("query", "")

    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()

    # VULNERABLE: f-string in SQL
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    conn.close()

    return {"results": results}


@app.get("/admin/login")
def admin_login(password: str):
    """Vulnerable hardcoded password."""
    # VULNERABLE: Hardcoded password
    ADMIN_PASSWORD = "admin123"

    if password == ADMIN_PASSWORD:
        token = jwt.encode(
            {"role": "admin"},
            SECRET_KEY,
            algorithm="HS256"  # Weak algorithm
        )
        return {"token": token}
    return {"error": "Invalid"}


@app.get("/user/{user_id}")
def get_user_safe(user_id: int):
    """Safe parameterized query example."""
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()

    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    return {"user": user}
