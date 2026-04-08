# Exploiting Incorrectly Configured Access Control Security Levels

A web-based CTF challenge demonstrating **broken access control** vulnerabilities — one of the OWASP Top 10.

## Challenge Overview

**SecureCorp Portal** is a fictional employee management system. The application implements role-based access control (RBAC), but several critical misconfigurations allow low-privilege users to access restricted resources.

Your goal is to find the **flag** hidden behind the admin-only functionality.

| Field | Value |
|-------|-------|
| **Type** | Web |
| **Difficulty** | Beginner – Intermediate |
| **Flag format** | `FLAG{...}` |

## Hints

1. Try accessing restricted functions or pages directly instead of going through the normal UI.
2. Compare what a low-privilege user can access with what should actually be blocked.

## Getting Started

### Option A: Docker (Recommended)

```bash
docker compose up --build
```

The app will be available at **http://localhost:5000**.

### Option B: Run Locally

```bash
pip install -r requirements.txt
python app.py
```

### Login Credentials (Provided)

| Username | Password | Role |
|----------|----------|------|
| `guest` | `guest123` | Guest |
| `user` | `password123` | User |

> The admin and moderator credentials are **not provided** — that's part of the challenge.

## Vulnerabilities Included

This challenge contains **5 different access control vulnerabilities** of varying difficulty:

| # | Category | Difficulty |
|---|----------|------------|
| 1 | Client-side role enforcement | Easy |
| 2 | Missing authorisation on API endpoint | Easy |
| 3 | Insecure Direct Object Reference (IDOR) | Easy |
| 4 | Debug endpoint exposed in production | Easy |
| 5 | Horizontal/Vertical privilege escalation | Medium |

## Learning Objectives

- Understand how broken access control works in web applications
- Learn to identify client-side vs server-side authorisation checks
- Practice using browser DevTools and tools like `curl` / Burp Suite
- Recognise IDOR vulnerabilities and exposed debug endpoints

## Disclaimer

This application is **intentionally vulnerable** and is designed for educational purposes only. Do **not** deploy it on a public-facing server.

## License

MIT
