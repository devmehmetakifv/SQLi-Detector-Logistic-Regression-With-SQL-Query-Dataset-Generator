# SQLi Demo Web App

A Dockerized vulnerable login page for testing SQL injection detection models.

## ⚠️ Warning

This application is **intentionally vulnerable** to SQL injection attacks for educational and testing purposes. 

**DO NOT deploy to production or expose to the internet.**

## Quick Start

```bash
# Start all services
docker-compose up --build

# Access the app
http://localhost:8080
```

## Architecture

| Service | Port | Description |
|---------|------|-------------|
| web | 8080 | PHP login page |
| api | 5000 | Python ML API |
| mysql | 3306 | User database |

## Test Credentials

| Username | Password |
|----------|----------|
| admin | admin123 |
| john_doe | password123 |

## SQLi Payloads to Try

```
' OR '1'='1' --
admin'--
' UNION SELECT * FROM users --
1' OR '1'='1
' OR 1=1#
```

## API Endpoints

- `GET /health` - Health check
- `POST /predict` - Analyze input for SQLi
- `GET /models` - List loaded models

## Stopping

```bash
docker-compose down
docker-compose down -v  # Also remove database volume
```
