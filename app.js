import json
import requests
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
import re
import shodan

app = Flask(__name__)
# Set up the Shodan API key (you can get a free API key from https://account.shodan.io/register/api)
SHODAN_API_KEY = "nJtpJv1y8LWtkZY8TKdF6zoubMnjVqDM"
api = shodan.Shodan(SHODAN_API_KEY)

def analyze_page_content(content):
    vulnerabilities = []

    # Improved SQL injection detection using regular expressions
    sql_injection_pattern = re.compile(r"(?:\b(?:union\s+all\s+select\s+distinct\s+concat|select\s+.*\s+from\s+information_schema|insert\s+into\s+.*\s+values|delete\s+from\s+.*\s+where|drop\s+table\s+.*|alter\s+table\s+.*\s+add)\b|\bon\w+\s*=|\bwaitfor\s+delay\s+.*|\bload_file\s*\()", re.IGNORECASE)
    if sql_injection_pattern.search(content):
        vulnerabilities.append('SQL Injection vulnerability detected')

    # Improved XSS detection using regular expressions
    xss_pattern = re.compile(r"<script\b[^>]*>(?:[^<]|<[^/s>])*?</script\s*>|<\w+\s+on\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE)
    if xss_pattern.search(content):
        vulnerabilities.append('Cross-Site Scripting detected')

    # Shodan API integration for basic vulnerability detection
    try:
        hostname = urlparse(content).netloc
        results = api.host(hostname)

        for service in results["services"]:
            if "product" in service and "version" in service:
                if re.search(r"(\d{1,2}\.\d{1,2})", service["product"]):
                    product_version = service["product"] + " " + service["version"]
                    if product_version in known_vulnerable_services:
                        vulnerabilities.append(f"Service '{product_version}' is known to be vulnerable")
    except Exception as e:
        print(f"Error while querying Shodan API: {e}")

    if vulnerabilities:
        return {'severity': 'High', 'message': f'Vulnerabilities detected: {", ".join(vulnerabilities)}'}
    else:
        return {'severity': 'Low', 'message': 'No vulnerabilities found.'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    print(f"Received data: {data}")  # Print the received data
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid URL'}), 400

    print(f"Scanning URL: {url}")  # Print the URL being scanned

    # Fetch page content
    response = requests.get(url)
    page_content = response.text

    # Analyze page content
    report = analyze_page_content(page_content)

    print(f"Scan report: {report}")  # Print the scan report

    return jsonify(report)

if __name__ == '__main__':
    app.run(debug=True)
