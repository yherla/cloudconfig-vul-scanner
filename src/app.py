import os
import json
import csv
from io import StringIO
from flask import Flask, render_template, request, redirect, flash, Response, session, jsonify
from flask_wtf.csrf import CSRFProtect

from .scanner import VulnerabilityScanner

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# Enable CSRF Protection
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
csrf = CSRFProtect(app)

scanner = VulnerabilityScanner(
    opa_policy_url=os.environ.get('OPA_POLICY_URL')
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'config_file' not in request.files:
            flash('No file part')
            return jsonify({"error": "No file part"}), 400  

        file = request.files['config_file']
        if file.filename == '':
            flash('No selected file')
            return jsonify({"error": "No selected file"}), 400  

        try:
            config_data = json.load(file)
            vulnerabilities = scanner.scan(config_data, report_format="dict")
            session['vulnerabilities'] = vulnerabilities
            if len(vulnerabilities) == 0:
                summary = "No vulnerabilities found."
            else:
                summary = f"Found {len(vulnerabilities)} vulnerability(ies)."
            report = {
                "summary": summary,
                "details": vulnerabilities
            }
            return render_template('report.html', report=report)

        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format."}), 400  

        except Exception as e:
            return jsonify({"error": f"Error processing file: {e}"}), 500  

    return render_template('index.html')

@app.route('/download_csv')
def download_csv():
    vulnerabilities = session.get('vulnerabilities', [])
    if not vulnerabilities:
        flash("No vulnerabilities to export.")
        return redirect('/')

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["Type", "Location", "Severity", "Description", "Remediation"])
    for vuln in vulnerabilities:
        writer.writerow([
            vuln.get("type", ""),
            vuln.get("key", ""),
            vuln.get("severity", ""),
            vuln.get("message", ""),
            vuln.get("remediation", "")
        ])
    output = si.getvalue()
    si.close()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities_report.csv"}
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False) 
