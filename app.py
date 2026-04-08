import os
import hashlib
import secrets
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    abort,
    make_response,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

FLAG = "FLAG{4cc3ss_c0ntr0l_byp4ss_1s_cr1t1c4l_2025}"

USERS = {
    "guest": {
        "password": hashlib.sha256("guest123".encode()).hexdigest(),
        "role": "guest",
        "name": "Guest User",
    },
    "user": {
        "password": hashlib.sha256("password123".encode()).hexdigest(),
        "role": "user",
        "name": "John Doe",
    },
    "moderator": {
        "password": hashlib.sha256("m0d$ecure!".encode()).hexdigest(),
        "role": "moderator",
        "name": "Jane Smith",
    },
    "admin": {
        "password": hashlib.sha256("Sup3r$ecr3tP@ssw0rd!".encode()).hexdigest(),
        "role": "admin",
        "name": "Administrator",
    },
}

ROLE_HIERARCHY = {"guest": 0, "user": 1, "moderator": 2, "admin": 3}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def role_required_ui(role):
    """Broken: only checks role via a client-visible cookie, not the server session."""

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role = request.cookies.get("role", "guest")
            if ROLE_HIERARCHY.get(user_role, 0) < ROLE_HIERARCHY.get(role, 0):
                abort(403)
            return f(*args, **kwargs)

        return decorated

    return decorator


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        if username in USERS and USERS[username]["password"] == pw_hash:
            session["username"] = username
            session["role"] = USERS[username]["role"]
            session["name"] = USERS[username]["name"]
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("role", USERS[username]["role"])
            return resp
        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("role")
    return resp


# ---------------------------------------------------------------------------
# Authenticated routes
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=session["username"],
        name=session["name"],
        role=session["role"],
    )


@app.route("/profile")
@login_required
def profile():
    return render_template(
        "profile.html",
        username=session["username"],
        name=session["name"],
        role=session["role"],
    )


# ---------------------------------------------------------------------------
# Vuln 1 – Admin panel: role checked via *cookie*, not server session
# ---------------------------------------------------------------------------

@app.route("/admin")
@login_required
@role_required_ui("admin")
def admin_panel():
    return render_template("admin.html", flag="Access the API to retrieve the flag.")


# ---------------------------------------------------------------------------
# Vuln 2 – Admin API: no authorisation check at all, only login_required
# ---------------------------------------------------------------------------

@app.route("/api/admin/flag")
@login_required
def api_admin_flag():
    return jsonify({"status": "success", "flag": FLAG})


# ---------------------------------------------------------------------------
# Vuln 3 – IDOR: any logged-in user can view other users' data
# ---------------------------------------------------------------------------

@app.route("/api/users/<username>")
@login_required
def api_user_detail(username):
    if username in USERS:
        user = USERS[username]
        data = {"username": username, "name": user["name"], "role": user["role"]}
        if user["role"] == "admin":
            data["secret_note"] = "The flag endpoint is /api/admin/flag"
        return jsonify(data)
    return jsonify({"error": "User not found"}), 404


# ---------------------------------------------------------------------------
# Vuln 4 – Hidden debug endpoint left in production
# ---------------------------------------------------------------------------

@app.route("/api/debug/users")
def debug_users():
    return jsonify(
        {u: {"name": d["name"], "role": d["role"]} for u, d in USERS.items()}
    )


# ---------------------------------------------------------------------------
# Vuln 5 – Horizontal privilege escalation via role parameter
# ---------------------------------------------------------------------------

@app.route("/api/admin/update-role", methods=["POST"])
@login_required
def update_role():
    target = request.json.get("username") if request.is_json else request.form.get("username")
    new_role = request.json.get("role") if request.is_json else request.form.get("role")

    if not target or not new_role:
        return jsonify({"error": "username and role are required"}), 400

    if target in USERS and new_role in ROLE_HIERARCHY:
        USERS[target]["role"] = new_role
        if target == session.get("username"):
            session["role"] = new_role
        return jsonify({"status": "success", "message": f"{target} is now {new_role}"})
    return jsonify({"error": "Invalid parameters"}), 400


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
