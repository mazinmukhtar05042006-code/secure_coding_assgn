"""Dependency security, Software Composition Analysis (SCA), and audit demonstration routes."""
from flask import Blueprint, render_template
import sys
import importlib.metadata
import platform

dependency_bp = Blueprint("dependency", __name__)


@dependency_bp.route("/dependencies")
def dependencies_view():
    # Safely inspect installed package versions locally without downloading or executing unsafe scripts
    packages = []
    tracked_packages = ["flask", "werkzeug", "jinja2", "click", "itsdangerous", "pytest"]

    for pkg_name in tracked_packages:
        try:
            version = importlib.metadata.version(pkg_name)
            packages.append({
                "name": pkg_name,
                "version": version,
                "status": "Installed & Verified"
            })
        except importlib.metadata.PackageNotFoundError:
            packages.append({
                "name": pkg_name,
                "version": "Not installed / standard lib",
                "status": "Optional / Missing"
            })

    system_info = {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "architecture": platform.architecture()[0]
    }

    return render_template(
        "dependencies.html",
        packages=packages,
        system_info=system_info
    )
