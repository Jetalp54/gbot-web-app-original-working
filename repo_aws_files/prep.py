import os
import time
import json
import boto3
import subprocess
import threading
import re
import sys

# CRITICAL FIX FOR LAMBDA: Monkey patch multiprocessing to use threading.Lock
# This prevents PermissionError when undetected_chromedriver tries to create semaphore locks
# Lambda's /dev/shm is read-only, so we must use threading locks instead

# Import multiprocessing and patch it BEFORE any other imports that might use it
import multiprocessing
import multiprocessing.synchronize
import multiprocessing.context

# Create a threading-based Lock class that mimics multiprocessing.Lock interface
class ThreadingLockProxy:
    """Proxy that uses threading.Lock instead of multiprocessing.Lock for Lambda compatibility"""
    def __init__(self, *args, **kwargs):
        # Ignore all arguments - Lambda doesn't support semaphores
        self._lock = threading.Lock()
    
    def acquire(self, *args, **kwargs):
        return self._lock.acquire(*args, **kwargs)
    
    def release(self):
        return self._lock.release()
    
    def __enter__(self):
        self._lock.acquire()
        return self
    
    def __exit__(self, *args):
        self._lock.release()
    
    def __call__(self, *args, **kwargs):
        # Allow it to be called as a function
        return self

# COMPLETE REPLACEMENT: Replace the entire Lock class in synchronize module
# This ensures that when undetected_chromedriver does "lock = Lock()" at class definition,
# it gets our threading-based lock instead of trying to create a semaphore

class LambdaCompatibleLock:
    """Complete replacement for multiprocessing.Lock that uses threading.Lock"""
    def __init__(self, *args, **kwargs):
        # Ignore all arguments - we don't support semaphores in Lambda
        self._lock = threading.Lock()
    
    def acquire(self, *args, **kwargs):
        return self._lock.acquire(*args, **kwargs)
    
    def release(self):
        return self._lock.release()
    
    def __enter__(self):
        self._lock.acquire()
        return self
    
    def __exit__(self, *args):
        self._lock.release()
    
    def __call__(self, *args, **kwargs):
        return self

# Replace the Lock class entirely
multiprocessing.synchronize.Lock = LambdaCompatibleLock

# Patch multiprocessing.synchronize to use our proxy as fallback
def _patched_lock_factory(*args, **kwargs):
    return LambdaCompatibleLock()

# Patch context methods to return our LambdaCompatibleLock
if hasattr(multiprocessing.context, 'BaseContext'):
    def patched_context_lock(self, *args, **kwargs):
        return LambdaCompatibleLock()
    multiprocessing.context.BaseContext.Lock = patched_context_lock

# Patch the default context
try:
    ctx = multiprocessing.get_context()
    if hasattr(ctx, 'Lock'):
        ctx.Lock = _patched_lock_factory
except:
    pass

# Patch multiprocessing.Lock function
multiprocessing.Lock = _patched_lock_factory

# Set environment variables before importing undetected_chromedriver
os.environ['HOME'] = '/tmp'
os.environ['XDG_CACHE_HOME'] = '/tmp/.cache'
os.environ['TMPDIR'] = '/tmp'
os.environ['TMP'] = '/tmp'

# Now import undetected_chromedriver (it will use our patched Lock)
try:
    import undetected_chromedriver as uc
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.keys import Keys
    print("Successfully imported undetected_chromedriver")
except Exception as e:
    print(f"Warning: Could not import undetected_chromedriver: {e}")
    import traceback
    traceback.print_exc()
    # Fallback to regular selenium if available
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        uc = None
        print("Using regular Selenium as fallback")
    except ImportError:
        raise Exception("Neither undetected_chromedriver nor selenium could be imported")

# S3 Configuration
S3_BUCKET = os.environ.get('S3_BUCKET')
S3_KEY_PREFIX = "service-accounts"

# Lock for gcloud auth operations (gcloud doesn't handle parallel auth well)
gcloud_auth_lock = threading.Lock()

def upload_to_s3(file_path, email, project_id):
    """Upload service account JSON key to S3"""
    if not S3_BUCKET:
        print("S3_BUCKET env var not set, skipping upload.")
        return False
    
    s3 = boto3.client('s3')
    key = f"{S3_KEY_PREFIX}/{email}/{project_id}.json"
    try:
        s3.upload_file(file_path, S3_BUCKET, key)
        print(f"Uploaded {file_path} to s3://{S3_BUCKET}/{key}")
        return True
    except Exception as e:
        print(f"Failed to upload to S3: {e}")
        return False

def get_chrome_driver():
    """Initialize Chrome driver with Lambda-compatible settings"""
    # Ensure /tmp directories exist
    os.makedirs('/tmp/user-data', exist_ok=True)
    os.makedirs('/tmp/data-path', exist_ok=True)
    os.makedirs('/tmp/cache-dir', exist_ok=True)
    os.makedirs('/tmp/.cache', exist_ok=True)
    
    # Chrome options for Lambda
    chrome_options = [
        '--headless=new',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--single-process',
        '--disable-blink-features=AutomationControlled',
        '--user-data-dir=/tmp/user-data',
        '--data-path=/tmp/data-path',
        '--disk-cache-dir=/tmp/cache-dir',
        '--homedir=/tmp',
        '--window-size=1280,720',
        '--disable-extensions',
        '--disable-plugins',
        '--disable-images',
        '--disable-javascript-harmony-shipping',
    ]
    
    if uc:
        # Use undetected_chromedriver
        options = uc.ChromeOptions()
        for opt in chrome_options:
            options.add_argument(opt)
        
        print("Initializing undetected Chrome driver...")
        try:
            driver = uc.Chrome(options=options, version_main=None, use_subprocess=False)
            return driver
        except Exception as e:
            print(f"Failed to initialize undetected_chromedriver: {e}")
            print("Falling back to regular Selenium...")
            # Fall through to regular selenium
    
    # Fallback to regular Selenium
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    
    options = Options()
    for opt in chrome_options:
        options.add_argument(opt)
    
    # Find chromedriver
    chromedriver_path = '/usr/bin/chromedriver'
    if not os.path.exists(chromedriver_path):
        chromedriver_path = 'chromedriver'  # Try in PATH
    
    service = Service(chromedriver_path)
    driver = webdriver.Chrome(service=service, options=options)
    print("Initialized regular Chrome driver")
    return driver

def google_login(driver, email, password):
    """Login to Google Account"""
    print(f"Logging in as {email}...")
    
    try:
        # Navigate to Google login
        driver.get("https://accounts.google.com/signin")
        time.sleep(2)
        
        # Email
        email_input = WebDriverWait(driver, 20).until(
            EC.element_to_be_clickable((By.ID, "identifierId"))
        )
        email_input.clear()
        email_input.send_keys(email)
        driver.find_element(By.ID, "identifierNext").click()
        time.sleep(2)
        
        # Password
        password_input = WebDriverWait(driver, 20).until(
            EC.element_to_be_clickable((By.NAME, "Passwd"))
        )
        password_input.clear()
        password_input.send_keys(password)
        driver.find_element(By.ID, "passwordNext").click()
        
        # Wait for login to complete
        time.sleep(5)
        
        # Handle "Allow" consent screen if it appears (for gcloud app)
        try:
            allow_btn = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Allow')]"))
            )
            allow_btn.click()
            print("Clicked Allow.")
            time.sleep(2)
        except:
            print("No Allow button found (might be already authorized or different flow).")
        
        return True
    except Exception as e:
        print(f"Login failed: {e}")
        return False

def get_gcloud_verification_code(driver, auth_url, email, password):
    """Navigate to auth URL, login, and extract verification code"""
    print(f"Navigating to Auth URL: {auth_url[:50]}...")
    driver.get(auth_url)
    time.sleep(2)
    
    # Perform login
    if not google_login(driver, email, password):
        return None
    
    # Wait for code to appear
    time.sleep(3)
    
    # Capture code - look for textarea or code element
    try:
        # Look for the code element
        code_element = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.TAG_NAME, "textarea"))
        )
        code = code_element.get_attribute("value")
        if not code:
            code = code_element.text
        
        if code and len(code) > 10:
            print("Successfully captured verification code.")
            return code.strip()
    except Exception as e:
        print(f"Could not find code in textarea: {e}")
    
    # Fallback: search page source for code pattern
    try:
        body_text = driver.find_element(By.TAG_NAME, "body").text
        # Look for a pattern like 4/0...
        match = re.search(r'4/[0-9a-zA-Z_-]{20,}', body_text)
        if match:
            print(f"Found code via regex: {match.group(0)[:20]}...")
            return match.group(0).strip()
    except Exception as e:
        print(f"Regex search failed: {e}")
    
    # Last resort: check page source
    try:
        page_source = driver.page_source
        match = re.search(r'4/[0-9a-zA-Z_-]{20,}', page_source)
        if match:
            print(f"Found code in page source: {match.group(0)[:20]}...")
            return match.group(0).strip()
    except Exception as e:
        print(f"Page source search failed: {e}")
    
    print("Failed to extract verification code")
    return None

def extract_auth_url_from_gcloud(output):
    """Extract the OAuth URL from gcloud auth login output"""
    # gcloud outputs something like:
    # "Go to the following link in your browser:\nhttps://accounts.google.com/o/oauth2/auth?..."
    # The URL might be on the same line or the next line, and might be split across lines
    
    if not output:
        return None
    
    # Normalize output - replace newlines and carriage returns with spaces, but preserve structure
    normalized_output = re.sub(r'[\r\n]+', ' ', output)
    # Remove multiple spaces
    normalized_output = re.sub(r'\s+', ' ', normalized_output)
    
    # URL patterns - capture the full URL including all query parameters
    # Use non-greedy matching and look for common URL endings
    url_patterns = [
        # Pattern 1: Full URL with query string (most common)
        r'https://accounts\.google\.com/o/oauth2/auth\?[^\s<>"\']+(?:\s|$|"|\'|<)',
        # Pattern 2: v2 auth endpoint
        r'https://accounts\.google\.com/o/oauth2/v2/auth\?[^\s<>"\']+(?:\s|$|"|\'|<)',
        # Pattern 3: Without v2
        r'https://accounts\.google\.com/o/oauth2/auth[^\s<>"\']+(?:\s|$|"|\'|<)',
        # Pattern 4: More permissive - capture until whitespace or end
        r'https://accounts\.google\.com/o/oauth2/auth\?[^\s]+',
    ]
    
    for pattern in url_patterns:
        match = re.search(pattern, normalized_output)
        if match:
            url = match.group(0).strip()
            # Clean up any trailing characters that shouldn't be in URL
            url = url.rstrip('.,;:)\'"<> \t\n\r')
            # Make sure it's a complete URL with query parameters
            if '?' in url and len(url) > 50:
                print(f"Extracted URL (pattern {url_patterns.index(pattern)+1}): {url[:80]}... (length: {len(url)})")
                return url
    
    # Try original output without normalization (in case normalization broke something)
    for pattern in url_patterns:
        match = re.search(pattern, output, re.MULTILINE | re.DOTALL)
        if match:
            url = match.group(0).strip()
            url = url.rstrip('.,;:)\'"<> \t\n\r')
            if '?' in url and len(url) > 50:
                print(f"Extracted URL from original output: {url[:80]}... (length: {len(url)})")
                return url
    
    # Last resort: find any line that contains the URL and extract it manually
    lines = output.split('\n')
    for i, line in enumerate(lines):
        if 'accounts.google.com' in line and '/o/oauth2' in line:
            # Try to find URL start and end
            url_start = line.find('https://accounts.google.com')
            if url_start >= 0:
                # Find where URL ends (whitespace, quote, or end of line)
                url_end = len(line)
                for end_char in [' ', '\t', '"', "'", '<', '>', '\n', '\r']:
                    pos = line.find(end_char, url_start)
                    if pos >= 0 and pos < url_end:
                        url_end = pos
                
                url = line[url_start:url_end].strip()
                url = url.rstrip('.,;:)\'"<>')
                if '?' in url and len(url) > 50:
                    print(f"Extracted URL from line {i}: {url[:80]}... (length: {len(url)})")
                    return url
    
    print(f"Failed to extract URL from output (length: {len(output)}, preview: {output[:200]})")
    return None

def gcloud_auth_flow(email, password):
    """Authenticate gcloud CLI by hijacking OAuth flow"""
    print(f"Starting gcloud auth flow for {email}...")
    
    # Use lock to serialize gcloud auth operations (gcloud doesn't handle parallel auth well)
    with gcloud_auth_lock:
        print(f"Acquired gcloud auth lock for {email}")
        return _gcloud_auth_flow_internal(email, password)

def _gcloud_auth_flow_internal(email, password):
    """Internal gcloud auth flow (called with lock held)"""
    driver = None
    process = None
    
    try:
        # Start gcloud auth login process
        cmd = ["gcloud", "auth", "login", "--no-launch-browser"]
        print(f"Executing: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Combine stderr with stdout
            text=True,
            bufsize=0  # Unbuffered
        )
        
        # Read output to get auth URL using a thread to avoid blocking
        auth_url = None
        full_output = ""
        output_lock = threading.Lock()
        read_complete = threading.Event()
        
        def read_output():
            """Read subprocess output in a separate thread"""
            nonlocal auth_url, full_output
            try:
                # Read output character by character or in small chunks
                while True:
                    if process.poll() is not None:
                        # Process finished, read remaining
                        try:
                            remaining = process.stdout.read()
                            if remaining:
                                with output_lock:
                                    full_output += remaining
                                    print(f"gcloud final output: {remaining[:200]}")
                        except:
                            pass
                        break
                    
                    # Try to read available data (non-blocking)
                    try:
                        # Use select if available
                        import select
                        if hasattr(select, 'select'):
                            ready, _, _ = select.select([process.stdout], [], [], 0.1)
                            if ready:
                                chunk = process.stdout.read(4096)
                                if chunk:
                                    with output_lock:
                                        full_output += chunk
                                        print(f"gcloud output chunk: {chunk[:200]}")
                                        # Check for URL
                                        if not auth_url:
                                            auth_url = extract_auth_url_from_gcloud(full_output)
                                            if auth_url:
                                                print(f"Found auth URL: {auth_url[:50]}...")
                                                read_complete.set()
                                                return
                        else:
                            # Fallback: read with timeout using threading
                            chunk = None
                            def read_chunk():
                                nonlocal chunk
                                try:
                                    chunk = process.stdout.read(4096)
                                except:
                                    pass
                            
                            reader_thread = threading.Thread(target=read_chunk, daemon=True)
                            reader_thread.start()
                            reader_thread.join(timeout=0.1)
                            
                            if chunk:
                                with output_lock:
                                    full_output += chunk
                                    print(f"gcloud output: {chunk[:200]}")
                                    if not auth_url:
                                        auth_url = extract_auth_url_from_gcloud(full_output)
                                        if auth_url:
                                            print(f"Found auth URL: {auth_url[:50]}...")
                                            read_complete.set()
                                            return
                            time.sleep(0.1)
                    except Exception as e:
                        print(f"Error reading output: {e}")
                        time.sleep(0.1)
                
                read_complete.set()
            except Exception as e:
                print(f"Exception in read_output thread: {e}")
                read_complete.set()
        
        # Start reading output in background thread
        print("Waiting for gcloud to output auth URL...")
        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()
        
        # Wait for URL to be found or timeout
        timeout = 30
        start_time = time.time()
        check_interval = 0.5
        
        while time.time() - start_time < timeout:
            # Check if URL was found (with lock to ensure we see the latest value)
            with output_lock:
                current_auth_url = auth_url
                if current_auth_url:
                    auth_url = current_auth_url  # Update main thread's view
                    print(f"URL found! Breaking wait loop: {auth_url[:50]}...")
                    break
                
                # Also check accumulated output periodically
                if full_output and not current_auth_url:
                    current_auth_url = extract_auth_url_from_gcloud(full_output)
                    if current_auth_url:
                        auth_url = current_auth_url
                        print(f"Found auth URL in accumulated output: {auth_url[:50]}...")
                        break
                
                # Log progress
                if len(full_output) > 0 and time.time() - start_time > 5:
                    print(f"Still waiting... Output so far: {len(full_output)} chars, last 100: {full_output[-100:]}")
            
            if read_complete.is_set():
                break
            
            time.sleep(check_interval)
        
        # Wait for reader thread to finish
        reader_thread.join(timeout=2)
        
        # Final check of accumulated output (with lock)
        with output_lock:
            # First try to extract from accumulated output
            if not auth_url and full_output:
                auth_url = extract_auth_url_from_gcloud(full_output)
                if auth_url:
                    print(f"Found auth URL in final check: {auth_url[:80]}...")
                else:
                    print(f"URL extraction failed from accumulated output ({len(full_output)} chars)")
                    print(f"Output preview: {full_output[:500]}")
            
            # If still no URL, try alternative read method (even if we have some output)
            if not auth_url:
                print("Attempting alternative read method to get complete output...")
                try:
                    # Try to get any remaining output from the process
                    additional_output = ""
                    
                    # If process is still running, try to read more
                    if process.poll() is None:
                        # Try non-blocking read if available
                        try:
                            import fcntl
                            flags = fcntl.fcntl(process.stdout.fileno(), fcntl.F_GETFL)
                            fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
                            additional_output = process.stdout.read()
                        except:
                            # fcntl not available (Windows/Lambda), try other methods
                            try:
                                # Try reading with a small timeout
                                import select
                                if hasattr(select, 'select'):
                                    ready, _, _ = select.select([process.stdout], [], [], 0.1)
                                    if ready:
                                        additional_output = process.stdout.read(8192)
                            except:
                                pass
                    
                    # Use communicate to get any remaining buffered output
                    if process.poll() is None:
                        process.terminate()
                        time.sleep(0.5)
                    
                    try:
                        stdout, stderr = process.communicate(timeout=5)
                        if stdout:
                            additional_output += stdout
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate(timeout=2)
                        if stdout:
                            additional_output += stdout
                    
                    if additional_output:
                        combined_output = full_output + additional_output
                        print(f"Combined output length: {len(combined_output)} (original: {len(full_output)}, additional: {len(additional_output)})")
                        auth_url = extract_auth_url_from_gcloud(combined_output)
                        if auth_url:
                            print(f"Found auth URL using alternative method: {auth_url[:80]}...")
                            full_output = combined_output
                        else:
                            # Show what we got for debugging
                            print(f"Still no URL after alternative method.")
                            print(f"Combined output preview ({len(combined_output)} chars): {combined_output[:800]}")
                    else:
                        print("No additional output from alternative method")
                except Exception as e:
                    print(f"Alternative read method failed: {e}")
                    import traceback
                    traceback.print_exc()
        
        # Final check - make sure we have the latest value
        with output_lock:
            final_auth_url = auth_url
            if final_auth_url:
                print(f"Final auth_url confirmed: {final_auth_url[:80]}...")
        
        if not final_auth_url:
            print("ERROR: Could not extract auth URL from gcloud output")
            print(f"Accumulated output length: {len(full_output)}")
            if full_output:
                print(f"Output preview: {full_output[:500]}")
            if process:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except:
                    pass
            return False
        
        # Use the final auth_url value
        auth_url = final_auth_url
        print(f"Using auth URL: {auth_url[:80]}...")
        
        # Initialize Chrome driver
        print("Initializing Chrome driver...")
        driver = get_chrome_driver()
        
        # Get verification code
        code = get_gcloud_verification_code(driver, auth_url, email, password)
        if not code:
            print("Failed to get verification code.")
            if process:
                process.kill()
            return False
        
        # Send code to gcloud
        print("Sending verification code to gcloud...")
        process.stdin.write(code + "\n")
        process.stdin.flush()
        process.stdin.close()
        
        # Wait for process to finish
        stdout, stderr = process.communicate(timeout=60)
        print(f"gcloud auth finished. Return code: {process.returncode}")
        if stdout:
            print(f"stdout: {stdout[:500]}")
        if stderr:
            print(f"stderr: {stderr[:500]}")
        
        if process.returncode == 0:
            print("gcloud auth successful.")
            return True
        else:
            print("gcloud auth failed.")
            return False
            
    except subprocess.TimeoutExpired:
        print("gcloud auth process timed out")
        if process:
            process.kill()
        return False
    except Exception as e:
        print(f"Exception during auth flow: {e}")
        import traceback
        traceback.print_exc()
        if process:
            process.kill()
        return False
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass

def setup_gcp_resources(email):
    """Create GCP project, service account, and generate JSON key"""
    timestamp = int(time.time())
    project_id = f"edu-gw-{timestamp}"
    display_name = f"Edu GW {timestamp}"
    sa_name = f"sa-{timestamp}"
    
    print(f"Setting up GCP resources for {email}...")
    print(f"Project ID: {project_id}")
    
    try:
        # 1. Create Project
        print("Creating GCP project...")
        run_command(["gcloud", "projects", "create", project_id, "--name", display_name])
        
        # 2. Set as active project
        print("Setting active project...")
        run_command(["gcloud", "config", "set", "project", project_id])
        
        # 3. Create Service Account
        print("Creating service account...")
        run_command([
            "gcloud", "iam", "service-accounts", "create", sa_name,
            "--display-name", f"Service Account for {email}",
            "--project", project_id
        ])
        
        # 4. Disable Org Policy (Key Creation) - optional, may fail
        print("Attempting to disable org policy (if applicable)...")
        try:
            run_command([
                "gcloud", "resource-manager", "org-policies", "disable-enforce", 
                "iam.disableServiceAccountKeyCreation", 
                "--project", project_id
            ])
        except Exception as e:
            print(f"Warning: Failed to disable org policy (might not be needed or no permission): {e}")
        
        # 5. Create Key
        print("Creating service account key...")
        sa_email = f"{sa_name}@{project_id}.iam.gserviceaccount.com"
        key_path = f"/tmp/{project_id}.json"
        run_command([
            "gcloud", "iam", "service-accounts", "keys", "create", key_path,
            "--iam-account", sa_email,
            "--project", project_id
        ])
        
        # 6. Enable APIs
        print("Enabling required APIs...")
        apis = [
            "admin.googleapis.com",
            "siteverification.googleapis.com"
        ]
        for api in apis:
            try:
                run_command(["gcloud", "services", "enable", api, "--project", project_id])
                print(f"Enabled {api}")
            except Exception as e:
                print(f"Warning: Failed to enable {api}: {e}")
        
        # 7. Upload Key to S3
        if os.path.exists(key_path):
            print("Uploading key to S3...")
            if upload_to_s3(key_path, email, project_id):
                print("Key uploaded successfully")
                # Clean up local file
                try:
                    os.remove(key_path)
                except:
                    pass
                return {
                    "success": True,
                    "project_id": project_id,
                    "service_account": sa_email,
                    "key_path": f"s3://{S3_BUCKET}/{S3_KEY_PREFIX}/{email}/{project_id}.json"
                }
            else:
                print("Failed to upload key to S3")
                return {"success": False, "error": "S3 upload failed"}
        else:
            print("Key file not found!")
            return {"success": False, "error": "Key file not found"}
            
    except Exception as e:
        print(f"Failed to setup GCP resources: {e}")
        import traceback
        traceback.print_exc()
        return {"success": False, "error": str(e)}

def run_command(command):
    """Run shell command and return output"""
    print(f"Running: {' '.join(command)}")
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=300  # 5 minute timeout
    )
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        raise Exception(f"Command failed: {result.stderr}")
    print(f"Output: {result.stdout}")
    return result.stdout

def process_single_user(email, password):
    """Process a single user through the prep workflow"""
    print(f"\n{'='*60}")
    print(f"Processing account: {email}")
    print(f"{'='*60}")
    
    # Step 1: Authenticate gcloud
    print("\n[STEP 1] Authenticating gcloud...")
    if not gcloud_auth_flow(email, password):
        error_msg = "Failed to authenticate gcloud"
        print(f"Error: {error_msg}")
        return {
            "email": email,
            "status": "error",
            "message": error_msg
        }
    
    # Step 2: Setup GCP Resources
    print("\n[STEP 2] Setting up GCP resources...")
    result = setup_gcp_resources(email)
    
    if result.get("success"):
        print(f"\n{'='*60}")
        print(f"Prep Process Completed Successfully for {email}!")
        print(f"{'='*60}")
        return {
            "email": email,
            "status": "success",
            "message": "GCP resources created and key uploaded.",
            "project_id": result.get("project_id"),
            "service_account": result.get("service_account"),
            "key_path": result.get("key_path")
        }
    else:
        error_msg = result.get("error", "Failed to setup GCP resources")
        print(f"\nError for {email}: {error_msg}")
        return {
            "email": email,
            "status": "error",
            "message": error_msg
        }

def main(event, context):
    """Lambda handler for prep process - supports both single user and batch processing"""
    print("=" * 60)
    print("Starting Prep Process...")
    print("=" * 60)
    
    # Check if this is a batch request (list of users) or single user
    if 'users' in event and isinstance(event['users'], list):
        # Batch processing mode
        users = event['users']
        print(f"Batch mode: Processing {len(users)} users in parallel")
        
        results = []
        
        def process_user_wrapper(user_data):
            """Wrapper to process a single user"""
            email = user_data.get('email')
            password = user_data.get('password')
            
            if not email or not password:
                return {
                    "email": email or "unknown",
                    "status": "error",
                    "message": "Missing email or password"
                }
            
            try:
                return process_single_user(email, password)
            except Exception as e:
                import traceback
                error_msg = f"Exception: {str(e)}"
                print(f"Exception processing {email}: {error_msg}")
                traceback.print_exc()
                return {
                    "email": email,
                    "status": "error",
                    "message": error_msg
                }
        
        # Process users in parallel using ThreadPoolExecutor
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
        except ImportError:
            # Fallback for older Python versions
            print("Warning: concurrent.futures not available, processing sequentially")
            results = []
            for user in users:
                results.append(process_user_wrapper(user))
            return {
                "status": "batch_complete",
                "total": len(results),
                "success": sum(1 for r in results if r.get('status') == 'success'),
                "failed": sum(1 for r in results if r.get('status') != 'success'),
                "results": results
            }
        
        max_workers = min(10, len(users))  # Limit concurrent processing
        print(f"Using {max_workers} parallel workers")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_user_wrapper, user): user for user in users}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    status = result.get('status', 'unknown')
                    email = result.get('email', 'unknown')
                    print(f"Completed {email}: {status}")
                except Exception as e:
                    user = futures[future]
                    email = user.get('email', 'unknown')
                    print(f"Failed to process {email}: {e}")
                    results.append({
                        "email": email,
                        "status": "error",
                        "message": str(e)
                    })
        
        # Summary
        success_count = sum(1 for r in results if r.get('status') == 'success')
        error_count = len(results) - success_count
        
        print(f"\n{'='*60}")
        print(f"Batch Processing Complete: {success_count} success, {error_count} failed")
        print(f"{'='*60}")
        
        return {
            "status": "batch_complete",
            "total": len(results),
            "success": success_count,
            "failed": error_count,
            "results": results
        }
    
    else:
        # Single user mode (backward compatible)
        email = event.get('email')
        password = event.get('password')
        
        if not email or not password:
            error_msg = "Missing email or password"
            print(f"Error: {error_msg}")
            return {
                "status": "error",
                "message": error_msg
            }
        
        result = process_single_user(email, password)
        return result

if __name__ == "__main__":
    # Local testing
    test_event = {
        "email": "test@example.com",
        "password": "testpassword"
    }
    # main(test_event, None)
