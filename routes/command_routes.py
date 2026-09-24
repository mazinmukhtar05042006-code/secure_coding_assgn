"""Command execution demonstration routes."""
from flask import Blueprint, render_template, request
from security.command_security import run_command_vulnerable, run_command_secure

command_bp = Blueprint("command", __name__)


@command_bp.route("/command", methods=["GET", "POST"])
def command_view():
    vuln_result = None
    sec_result = None
    target_input = ""
    mode = ""

    if request.method == "POST":
        mode = request.form.get("mode", "secure")
        target_input = request.form.get("target", "").strip()

        if mode == "vulnerable":
            vuln_result = run_command_vulnerable(target_input)
        else:
            sec_result = run_command_secure(target_input)

    return render_template(
        "command.html",
        vuln_result=vuln_result,
        sec_result=sec_result,
        target_input=target_input,
        mode=mode
    )
