# Suspicious Login Detector

A lightweight cybersecurity-focused web application that detects suspicious login behavior using FastAPI, SQLite, and a real-time analytics dashboard.

The system tracks user logins, analyzes behavioral patterns (device and location changes), assigns risk scores, and visualizes activity through an interactive frontend dashboard.

---

## Features

- User login tracking system (username, device, location, timestamp)
- Risk scoring based on:
  - New device detection
  - New location detection
  - Suspicious username patterns
- IP-based geolocation enhancement
- REST API built with FastAPI
- SQLite database for lightweight storage
- Real-time analytics endpoint
- Interactive dashboard with:
  - Login logs viewer
  - Risk summary statistics
  - Pie chart visualization (Chart.js)

---

## How Risk Scoring Works

Each login is evaluated using simple anomaly detection rules:

- +50 points → New device detected  
- +50 points → New location detected  
- +30 points → IP location mismatch  

Risk Levels:
- 0–49 → LOW  
- 50+ → HIGH  

---

## Tech Stack

- Python
- FastAPI
- SQLite
- HTML / JavaScript
- Chart.js
- Requests library

---

## Project Structure
