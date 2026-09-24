"""Authentication and password storage demonstration routes."""
from flask import Blueprint, render_template, request
from security.password_security import (
    register_user_vulnerable,
    login_user_vulnerable,
    get_vulnerable_store_view,
    register_user_secure,
    login_user_secure,
    get_secure_store_view
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/authentication", methods=["GET", "POST"])
def auth_view():
    action = request.form.get("action", "")
    mode = request.form.get("mode", "")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    message = None
    success = False
    details = None

    if request.method == "POST":
        if mode == "vulnerable":
            if action == "register":
                success, message = register_user_vulnerable(username, password)
            elif action == "login":
                success, message, details = login_user_vulnerable(username, password)
        elif mode == "secure":
            if action == "register":
                success, message = register_user_secure(username, password)
            elif action == "login":
                success, message = login_user_secure(username, password)

    vulnerable_users = get_vulnerable_store_view()
    secure_users = get_secure_store_view()

    return render_template(
        "authentication.html",
        message=message,
        success=success,
        mode=mode,
        action=action,
        vulnerable_users=vulnerable_users,
        secure_users=secure_users
    )
