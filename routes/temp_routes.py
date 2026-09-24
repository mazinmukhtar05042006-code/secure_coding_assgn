"""Temporary file creation demonstration routes."""
from flask import Blueprint, render_template, request
from security.temp_file_security import create_temp_file_vulnerable, create_temp_file_secure

temp_bp = Blueprint("temp", __name__)


@temp_bp.route("/temp-files", methods=["GET", "POST"])
def temp_view():
    vuln_result = None
    sec_result = None
    content_input = ""
    mode = ""

    if request.method == "POST":
        mode = request.form.get("mode", "secure")
        content_input = request.form.get("content", "").strip()

        if mode == "vulnerable":
            vuln_result = create_temp_file_vulnerable(content_input)
        else:
            sec_result = create_temp_file_secure(content_input)

    return render_template(
        "temp_files.html",
        vuln_result=vuln_result,
        sec_result=sec_result,
        content_input=content_input,
        mode=mode
    )
