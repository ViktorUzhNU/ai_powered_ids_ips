import requests

def check_ip_abuse(ip, api_key):
    """
    Check an IP address on AbuseIPDB for malicious activity.
    Returns reputation info like abuse score, country, reports, etc.
    """
    # AbuseIPDB API endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    # Headers - required for authentication and response format
    headers = {
        'Key': api_key,           # My API key
        'Accept': 'application/json'  # We want JSON response
    }

    # Query parameters
    params = {
        'ipAddress': ip,          # The IP we want to check
        'maxAgeInDays': 90        # Only look at reports from the last 90 days
    }

    try:
        # Send GET request to AbuseIPDB
        response = requests.get(url, headers=headers, params=params, timeout=10)

        # If request was successful (HTTP 200)
        if response.status_code == 200:
            data = response.json()['data']  # Extract the useful part of the response

            # Return clean dictionary with the most important info
            return {
                'ip': ip,
                'abuseConfidenceScore': data['abuseConfidenceScore'],  # 0-100 score (higher = more bad)
                'countryCode': data.get('countryCode'),                # Country of the IP
                'usageType': data.get('usageType'),                    # e.g. Hosting, Business, Residential
                'domain': data.get('domain'),                          # ISP or domain name
                'totalReports': data.get('totalReports'),              # How many times reported
                'lastReportedAt': data.get('lastReportedAt')           # When it was last reported
            }
        else:
            # If API returned an error (like wrong key, rate limit, etc.)
            return {'ip': ip, 'error': f'HTTP {response.status_code}: {response.text}'}

    except Exception as e:
        # Catch network errors, timeouts, JSON errors, etc.
        return {'ip': ip, 'error': str(e)}