from flask import Flask, render_template, request, redirect, flash
import json
import os 

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'templates')
app = Flask(__name__, template_folder=template_dir)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'config_file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['config_file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    try:
        config_data = json.load(file)
        vulnerabilities = scan_for_vulnerabilities(config_data)
        report = generate_report(vulnerabilities)
        return render_template('report.html', report=report)
    except Exception as e:
        flash(f'Error processing file: {e}')
        return redirect(request.url)

def scan_for_vulnerabilities(config):
    """Example vulnerability check."""
    vulns = []
    if isinstance(config, dict) and config.get("debug") is True:
        vulns.append({
            "type": "Debug Mode Enabled",
            "severity": "Medium",
            "message": "Debug mode should be disabled in production."
        })
    return vulns

def generate_report(vulns):
    if not vulns:
        return {"summary": "No vulnerabilities found.", "details": []}
    else:
        return {"summary": f"Found {len(vulns)} vulnerability(ies).", "details": vulns}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
