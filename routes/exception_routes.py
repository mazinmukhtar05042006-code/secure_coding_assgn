"""Exception handling demonstration routes."""
from flask import Blueprint, render_template, request
from security.exception_security import process_operation_vulnerable, process_operation_secure

exception_bp = Blueprint("exception", __name__)


@exception_bp.route("/exception-handling", methods=["GET", "POST"])
def exception_view():
    vuln_result = None
    sec_result = None
    scenario = "file_not_found"
    custom_input = ""
    mode = ""

    if request.method == "POST":
        mode = request.form.get("mode", "secure")
        scenario = request.form.get("scenario", "file_not_found")
        custom_input = request.form.get("custom_input", "").strip()

        if mode == "vulnerable":
            vuln_result = process_operation_vulnerable(scenario, custom_input)
        else:
            sec_result = process_operation_secure(scenario, custom_input)

    return render_template(
        "exception_handling.html",
        vuln_result=vuln_result,
        sec_result=sec_result,
        scenario=scenario,
        custom_input=custom_input,
        mode=mode
    )
