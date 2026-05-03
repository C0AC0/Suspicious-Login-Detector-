from fastapi.middleware.cors import CORSMiddleware
import requests
from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
from datetime import datetime

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Database
conn = sqlite3.connect("logins.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS logins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    device TEXT,
    location TEXT,
    login_time TEXT
)
""")
conn.commit()

# Request model
class LoginRequest(BaseModel):
    username: str
    device: str
    location: str

# Home route
@app.get("/")
def home():
    return {"message": "Suspicious Login Detector is running"}

# Risk scoring
def risk_score(username, device, location):
    cursor.execute(
        "SELECT device, location FROM logins WHERE username = ?",
        (username,)
    )
    previous_logins = cursor.fetchall()

    known_devices = set()
    known_locations = set()

    for record in previous_logins:
        known_devices.add(record[0])
        known_locations.add(record[1])

    score = 0

    if device not in known_devices:
        score += 50

    if location not in known_locations:
        score += 50

    return score

# Login endpoint
def get_ip_location():
    try:
        ip = requests.get("https://api.ipify.org").text
        data = requests.get(f"https://ipapi.co/{ip}/json/").json()
        return data.get("city", "unknown")
    except:
        return "unknown"
    
@app.post("/login")
def login(data: LoginRequest):
    username = data.username
    device = data.device
    location = data.location

    time = datetime.now().strftime("%H:%M")

    score = risk_score(username, device, location)

    #IP tracking
    ip_location = get_ip_location()

    if ip_location != location and ip_location != "unknown":
        score += 30

    cursor.execute(
        "INSERT INTO logins VALUES (NULL, ?, ?, ?, ?)",
        (username, device, location, time)
    )
    conn.commit()

    return {
        "status": "login recorded",
        "risk_score": score,
        "risk_level": "HIGH" if score >= 50 else "LOW",
        "ip_location": ip_location
    }

@app.get("/logs")
def get_logs():
    cursor.execute("SELECT * FROM logins")
    rows = cursor.fetchall()

    return {
        "logs": [
            {
                "id": r[0],
                "username": r[1],
                "device": r[2],
                "location": r[3],
                "time": r[4]
            }
            for r in rows
        ]
    }
@app.get("/analytics")
def analytics():
    cursor.execute("SELECT * FROM logins")
    rows = cursor.fetchall()

    return {
        "total_logins": len(rows),
        "unique_users": len(set(r[1] for r in rows)),
        "unique_devices": len(set(r[2] for r in rows)),
        "unique_locations": len(set(r[3] for r in rows))
    }
