import requests
from zapv2 import ZAPv2 as ZAP
import time
import datetime
from os import getcwd
import sys
import json
from requests.exceptions import RequestException, Timeout, ConnectionError, HTTPError

# Test Automation Part of the Script
target_url = 'http://localhost:5050'
proxies = {
    'http': 'http://127.0.0.1:8090',
    'https': 'http://127.0.0.1:8090',
}

# Check if the application is accessible
max_retries = 5
retry_count = 0
app_accessible = False

while retry_count < max_retries and not app_accessible:
    try:
        print(f"Checking if application is accessible at {target_url} (Attempt {retry_count + 1}/{max_retries})")
        site_check = requests.get(target_url, proxies=proxies, verify=False, timeout=30)
        print(f"Application responded with status code: {site_check.status_code}")
        app_accessible = True
    except (ConnectionError, Timeout) as e:
        retry_count += 1
        print(f"Connection failed (Attempt {retry_count}/{max_retries}): {str(e)}")
        if retry_count < max_retries:
            print(f"Waiting 10 seconds before retrying...")
            time.sleep(10)
    except Exception as e:
        print(f"Unexpected error accessing application: {str(e)}")
        print("Continuing anyway, ZAP might still be able to scan...")
        break

# Even if we can't reach the app directly, we'll try through ZAP
auth_dict = {'username': 'admin', 'password': 'admin123'}

print(f"Attempting to login to {target_url}/login")
try:
    login = requests.post(target_url + '/login',
                          proxies=proxies, json=auth_dict, verify=False, timeout=30)

    if login.status_code == 200:  # if login is successful
        auth_token = login.headers['Authorization']
        auth_header = {"Authorization": auth_token}
        print("Login successful, proceeding with authentication.")
    else:
        print(f"Warning: Login failed (Status code: {login.status_code}), proceeding without authentication.")
        auth_header = {}  # Fallback to no auth if login fails
except Exception as e:
    print(f"Error during login: {str(e)}")
    auth_header = {}  # Fallback to no auth if login fails

# now lets run some operations - fixed indentation here
# Try some API endpoints to warm up the application
print("Attempting API operations to warm up the application")

try:
    # GET Customer by ID
    get_cust_id = requests.get(
        target_url + '/get/2', proxies=proxies, headers=auth_header, verify=False, timeout=30)
    if get_cust_id.status_code == 200:
        print("Get Customer by ID Response")
        print(get_cust_id.json())
        print()
except Exception as e:
    print(f"Error getting customer by ID: {str(e)}")

try:
    post = {'id': 2}
    fetch_customer_post = requests.post(
        target_url + '/fetch/customer', json=post, proxies=proxies, headers=auth_header, verify=False, timeout=30)
    if fetch_customer_post.status_code == 200:
        print("Fetch Customer POST Response")
        print(fetch_customer_post.json())
        print()
except Exception as e:
    print(f"Error fetching customer: {str(e)}")

try:
    search = {'search': 'dleon'}
    search_customer_username = requests.post(
        target_url + '/search', json=search, proxies=proxies, headers=auth_header, verify=False, timeout=30)
    if search_customer_username.status_code == 200:
        print("Search Customer POST Response")
        print(search_customer_username.json())
        print()
except Exception as e:
    print(f"Error searching customer: {str(e)}")

# ZAP Operations
print("Initializing ZAP connection...")
try:
    zap = ZAP(proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})
    print("ZAP connection initialized successfully")
except Exception as e:
    print(f"Error connecting to ZAP: {str(e)}")
    sys.exit(1)

# Make sure the target is available through ZAP
print(f"Accessing target {target_url} through ZAP")
try:
    resp = zap.urlopen(target_url)
    print(f"Successfully accessed target via ZAP (length: {len(resp)})")
except Exception as e:
    print(f"Error accessing target via ZAP: {str(e)}")
    print("This might indicate issues with the application, but we'll continue with scanning")

time.sleep(5)  # Give the app a moment to respond

# Add target to context
print("Adding target to context")
try:
    context_id = zap.context.new_context("VulnerableApp")
    context_name = "VulnerableApp"
    zap.context.include_in_context(context_name, ".*" + target_url.replace("http://", "").replace("https://", "") + ".*")
    print(f"Context created with ID: {context_id}")
except Exception as e:
    print(f"Error creating context: {str(e)}")

# Add URLs manually to ensure they're in scope
print("Adding key URLs to ZAP")
urls_to_visit = [
    target_url + '/',
    target_url + '/login',
    target_url + '/get/1',
    target_url + '/search',
    target_url + '/fetch/customer',
    target_url + '/register/user',
    target_url + '/register/customer',
    target_url + '/xxe',
    target_url + '/yaml'
]

# First try to browse URLs directly
print("Manually accessing key URLs through ZAP...")
for url in urls_to_visit:
    try:
        print(f"Accessing {url}")
        resp = zap.core.access_url(url)
        print(f"  - Response size: {len(resp) if resp else 'No response or empty'}")
        time.sleep(2)  # Increased pause between URLs for better app stability
    except Exception as e:
        print(f"Error accessing {url}: {str(e)}")

# Spider the target to discover endpoints
print("Spidering target...")
try:
    # Configure spider options
    zap.spider.set_option_max_depth(10)  # Increase depth for better coverage
    zap.spider.set_option_max_children(100)  # More children per node
    
    # Start the spider
    spider_id = zap.spider.scan(target_url)
    print(f"Spider started with ID: {spider_id}")
    time.sleep(2)

    # Wait for spider to complete
    time_waited = 0
    spider_timeout = 360  # 6 minutes timeout
    while int(zap.spider.status(spider_id)) < 100 and time_waited < spider_timeout:
        status = int(zap.spider.status(spider_id))
        print(f"Spider progress: {status}%")
        time.sleep(10)  # Check every 10 seconds
        time_waited += 10

    final_status = int(zap.spider.status(spider_id))
    if final_status < 100:
        print(f"Spider timed out at {final_status}% but proceeding anyway")
    else:
        print("Spider completed successfully")
    
    # Get the discovered URLs
    urls = zap.spider.results(spider_id)
    print(f"Spider discovered {len(urls)} URL(s)")
    for url in urls:
        print(f"  - {url}")
except Exception as e:
    print(f"Error during spidering: {str(e)}")
    print("Continuing with scan despite spider issues")

# Ajax Spider for better crawling of JavaScript-heavy sites
print("Running Ajax Spider...")
try:
    ajax_spider_id = zap.ajaxSpider.scan(target_url)
    
    # Wait for Ajax Spider to complete (timeout after 120 seconds)
    timeout = time.time() + 120
    while zap.ajaxSpider.status == 'running' and time.time() < timeout:
        ajax_results = zap.ajaxSpider.results()
        print(f"Ajax Spider still running... Found {len(ajax_results)} requests so far")
        time.sleep(10)
    
    final_ajax_results = zap.ajaxSpider.results()
    print(f"Ajax Spider completed or timed out. Found {len(final_ajax_results)} requests")
    
    # Debug: Print AJAX spider results if any
    if final_ajax_results:
        print("AJAX Spider Results:")
        for i, result in enumerate(final_ajax_results[:5]):  # Print only first 5 for brevity
            print(f"  {i+1}. {result.get('url')}")
except Exception as e:
    print(f"Error or timeout during Ajax Spider: {str(e)}")
    print("Continuing with scan despite AJAX spider issues")

# Wait for passive scan to complete
try:
    timeout = time.time() + 120  # 2 minutes timeout for passive scan
    records_remaining = int(zap.pscan.records_to_scan)
    print(f"Initial passive scan records to scan: {records_remaining}")
    
    while records_remaining > 0 and time.time() < timeout:
        print(f"Passive scan still scanning: {records_remaining} records left")
        time.sleep(10)
        records_remaining = int(zap.pscan.records_to_scan)
    
    if records_remaining > 0:
        print(f"Passive scan timed out but proceeding. {records_remaining} records left unscanned.")
    else:
        print("Passive scan completed successfully")
except Exception as e:
    print(f"Error during passive scan: {str(e)}")
    print("Continuing with active scan despite passive scan issues")

# Set up active scan
print("Preparing for active scan")
try:
    # Configure attack strength
    zap.ascan.set_option_attack_strength('HIGH')
    zap.ascan.set_option_alert_threshold('LOW')  # More verbose alerting
    
    # Enable all scanners for better coverage
    scanners = zap.ascan.scanners()
    enabled_count = 0
    for scanner in scanners:
        scanner_id = scanner['id']
        if scanner['enabled'] != 'true':
            print(f"Enabling scanner {scanner_id}: {scanner['name']}")
            zap.ascan.enable_scanners(scanner_id)
            enabled_count += 1
    
    print(f"Enabled {enabled_count} additional scanners")
    
    # Create scan policy
    if 'Medium' not in zap.ascan.scan_policy_names:
        print("Adding scan policies")
        zap.ascan.add_scan_policy("Medium", alertthreshold="Medium", attackstrength="HIGH")
        print("Scan policy 'Medium' created with HIGH attack strength")
except Exception as e:
    print(f"Error configuring scanners: {str(e)}")
    print("Continuing with default scan configuration")

# Start active scan
print("Starting active scan...")
try:
    # Use more aggressive scan settings
    active_scan_id = zap.ascan.scan(
        target_url, 
        recurse=True, 
        inscopeonly=False,  # Scan everything we can find
        scanpolicyname='Medium'
    )
    print(f"Active scan started with ID: {active_scan_id}")

    # Monitor the active scan status with a maximum timeout (10 minutes)
    max_wait = 600  # 10 minutes in seconds
    wait_time = 0
    last_status = 0
    
    while int(zap.ascan.status(active_scan_id)) < 100 and wait_time < max_wait:
        current_status = int(zap.ascan.status(active_scan_id))
        if current_status > last_status:  # Only print when there's progress
            print(f"Current Status of ZAP Active Scan: {current_status}%")
            last_status = current_status
        time.sleep(10)  # Check status every 10 seconds
        wait_time += 10

    final_scan_status = int(zap.ascan.status(active_scan_id))
    if wait_time >= max_wait:
        print(f"Warning: Scan did not complete within 10 minutes. Stopped at {final_scan_status}%.")
    else:
        print(f"Scan completed successfully at {final_scan_status}%")
    
    # Get scan stats
    scan_progress = zap.ascan.scan_progress(active_scan_id)
    print(f"Scan statistics: {scan_progress}")
except Exception as e:
    print(f"Error during active scan: {str(e)}")
    print("Will attempt to generate report regardless of scan status")

# Wait a moment for scan to finalize
print("Waiting 30 seconds for scan to finalize before generating report...")
time.sleep(30)

# Generate report using the core API
print("Generating report...")
try:
    now = datetime.datetime.now().strftime("%m/%d/%Y")
    path = getcwd() + "/zap-report.json"

    # Get alerts to verify we have findings
    alerts = zap.core.alerts()
    if alerts:
        print(f"Found {len(alerts)} alerts/vulnerabilities")
        print("Top 3 vulnerabilities found:")
        for i, alert in enumerate(alerts[:3]):
            print(f"  {i+1}. {alert.get('name')} - Risk: {alert.get('risk')}")
    else:
        print("WARNING: No vulnerabilities were found. This might indicate scanning issues.")
    
    # Generate the report
    report_content = zap.core.jsonreport()
    
    # Ensure report has content
    try:
        report_json = json.loads(report_content)
        site_count = len(report_json.get('site', []))
        print(f"Report contains data for {site_count} site(s)")
    except json.JSONDecodeError:
        print("WARNING: Generated report is not valid JSON")
    
    with open(path, 'w') as f:
        f.write(report_content)

    print(f"Report generated at: {path}")
except Exception as e:
    print(f"Error generating report: {str(e)}")

# Shutdown ZAP
try:
    print("Shutting down ZAP...")
    zap.core.shutdown()
    print("ZAP shutdown complete")
except Exception as e:
    print(f"Error during ZAP shutdown: {str(e)}")