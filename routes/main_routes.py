"""Main and educational dashboard routes."""
from flask import Blueprint, render_template, request
from security.validation import (
    validate_hostname_or_ip,
    validate_username,
    validate_password_strength,
    validate_filename_safe
)

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/validation", methods=["GET", "POST"])
def validation():
    val_type = request.form.get("val_type", "host")
    input_value = request.form.get("input_value", "")
    result = None

    if request.method == "POST" and input_value:
        if val_type == "host":
            is_valid, msg = validate_hostname_or_ip(input_value)
            reason = msg if not is_valid else "Matches valid IPv4/IPv6 address or RFC hostname allowlist. Zero shell tokens."
        elif val_type == "username":
            is_valid, msg = validate_username(input_value)
            reason = msg if not is_valid else "Matches alphanumeric allowlist (3-30 chars, letters/numbers/underscore/hyphen)."
        elif val_type == "password":
            is_valid, msg = validate_password_strength(input_value)
            reason = msg if not is_valid else "Satisfies length (>=8) and character variety (uppercase, lowercase, digit)."
        elif val_type == "filename":
            is_valid, msg = validate_filename_safe(input_value)
            reason = msg if not is_valid else "Contains only safe alphanumeric/dot/hyphen characters without path separators."
        else:
            is_valid, reason = False, "Unknown validator type."

        result = {
            "input": input_value,
            "type": val_type,
            "is_valid": is_valid,
            "status": "ACCEPTED" if is_valid else "REJECTED",
            "reason": reason
        }

    return render_template("validation.html", result=result, val_type=val_type, input_value=input_value)


@main_bp.route("/principles")
def principles():
    return render_template("principles.html")


@main_bp.route("/risk-assessment")
def risk_assessment():
    return render_template("risk_assessment.html")


@main_bp.route("/threat-model")
def threat_model():
    return render_template("threat_model.html")


@main_bp.route("/report")
def report():
    return render_template("report.html")
