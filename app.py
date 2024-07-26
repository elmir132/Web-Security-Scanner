import json
import requests
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
import re
import shodan
import zapv2
from openai import OpenAI

client = OpenAI(api_key="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") 


app = Flask(__name__)
# Set up the Shodan API key (you can get a free API key from https://account.shodan.io/register/api)
SHODAN_API_KEY = "gr3Rfv9PXJSJU5cZBT5XlAGP9Y06heLX"
api = shodan.Shodan(SHODAN_API_KEY)

  # Replace with your actual OpenAI API key


# Set up ZAP
zap_ip = "localhost"
zap_port = "8080"
zap = zapv2.ZAPv2(apikey="u91binh9n0n9932fms801rqrvu", proxies={"http": f"http://{zap_ip}:{zap_port}", "https": f"http://{zap_ip}:{zap_port}"})


def generate_suggestion_using_gpt(prompt):
    try:
        # Use the OpenAI API to generate a suggestion based on the provided prompt
        response = client.completions.create(engine="gpt-3.5-turbo",  # Use the newer engine
        prompt=prompt,
        max_tokens=4000,  # Adjust as needed
        temperature=0.7)

        suggestion = response.choices[0].text.strip()

        return suggestion
    except Exception as e:
        return str(e)




def analyze_page_content(content):
    vulnerabilities = []

    # Basic SQL injection detection using regular expressions
    sql_injection_pattern = re.compile(r"(?:\b(?:union\s+all\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|alter\s+table)\b|\bon\w+\s*=|\bwaitfor\s+delay|\bload_file\s*\()", re.IGNORECASE)
    if sql_injection_pattern.search(content):
        vulnerabilities.append('SQL Injection vulnerability detected')

    # Basic XSS detection using regular expressions
    xss_pattern = re.compile(r"<script\b[^>]*>(?:[^<]|<[^/s>])*?</script\s*>", re.IGNORECASE)
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

    # Fetch page content using ZAP
     # Fetch page content using ZAP
    zap.core.new_session("My Session")
    zap.urlopen(f"{url}")

    # Get alerts for the specific URL
    alert_list = zap.core.alerts(baseurl=f"{url}")

    # Analyze page content
    # Fetch page content using ZAP
    zap.core.new_session("My Session")
    zap.urlopen(f"{url}")

    # Get alerts for the specific URL
    alert_list = zap.core.alerts(baseurl=f"{url}")

    # Fetch page content using requests
    response = requests.get(url)
    page_content = response.text

    # Analyze page content
    report = analyze_page_content(page_content)

    print(f"Scan report: {report}")  # Print the scan report

    # Print the response content and status code
    print(f"Response content: {page_content}")
    print(f"Response status code: {response.status_code}")

    # Create a list to store structured alerts


    structured_alerts = []

    for alert in alert_list:
        if alert["risk"] != "Informational":
            structured_alert = {
                'name': alert['name'],
                'risk': alert['risk'],
                'description': alert['description'],
                # Add more fields as needed
            }
            structured_alerts.append(structured_alert)  # Append the alert to the list

    report['structured_alerts'] = structured_alerts

    return jsonify(report)


@app.route('/generate-suggestion', methods=['POST'])
def generate_suggestion():
    try:
        data = request.get_json()
        model = data.get('model', '')  # Retrieve the model parameter
        prompt = data.get('prompt', '')

        # Use the function to generate a suggestion based on the provided prompt
        suggestion = generate_suggestion_using_gpt(prompt)

        return jsonify({'text': suggestion})
    except Exception as e:
        return jsonify({'error': str(e)}), 500




if __name__ == '__main__':
    app.run(debug=True)