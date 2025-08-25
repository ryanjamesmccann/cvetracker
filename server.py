from flask import Flask, render_template, request, send_from_directory, jsonify
import subprocess
import os
import sys

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))         # .../unpatched_cve_report/my-app
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))  # .../unpatched_cve_report
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
SCRIPT_PATH = os.path.join(PROJECT_ROOT, "cve_report.py")


os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route("/")
def index():
    files = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith(".html")])
    return render_template("index.html", files=files)

@app.route("/files")
def list_files():
    files = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith(".html")])
    return jsonify(files)

@app.route("/report/<path:filename>")
def report(filename):
    return send_from_directory(REPORTS_DIR, filename)

@app.route("/run", methods=["POST"])
def run():
    
    args = [sys.executable, SCRIPT_PATH]

    
    ifile = request.form.get("ifile")
    ofile = request.form.get("ofile")
    date = request.form.get("date")
    compared_report = request.form.get("compared_report")

    if "all" in request.form:
        args.append("-a")
    if ifile:
        args.extend(["-i", ifile])
    if ofile:
        args.extend(["-o", ofile])
    if date:
        args.extend(["-d", date])

    # Checkboxes
    if "summary" in request.form:
        args.append("-s")
    if "to_csv" in request.form:
        args.append("-c")
    if "unknown" in request.form:
        args.append("-u")
    if "x" in request.form:
        args.append("-x")
    
    if compared_report:
        args.extend(["-y", compared_report])

    
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT
    )

    
    output = ""
    if result.stdout:
        output += result.stdout
    if result.stderr:
        output += ("\n" + result.stderr if output else result.stderr)
    return output or "No output."

if __name__ == "__main__":
    app.run(port=5000, debug=True)
