"""File access and path traversal demonstration routes."""
from flask import Blueprint, render_template, request
import os
import config
from security.file_security import read_file_vulnerable, read_file_secure

file_bp = Blueprint("file", __name__)


@file_bp.route("/file-security", methods=["GET", "POST"])
def file_view():
    vuln_result = None
    sec_result = None
    requested_file = ""
    mode = ""

    # List files available in the safe directory for user convenience
    available_safe_files = []
    if config.SAFE_FILES_DIR.exists():
        available_safe_files = [f.name for f in config.SAFE_FILES_DIR.iterdir() if f.is_file()]

    if request.method == "POST":
        mode = request.form.get("mode", "secure")
        requested_file = request.form.get("filename", "").strip()

        if mode == "vulnerable":
            vuln_result = read_file_vulnerable(requested_file)
        else:
            sec_result = read_file_secure(requested_file)

    return render_template(
        "file_security.html",
        vuln_result=vuln_result,
        sec_result=sec_result,
        requested_file=requested_file,
        mode=mode,
        available_safe_files=available_safe_files
    )
