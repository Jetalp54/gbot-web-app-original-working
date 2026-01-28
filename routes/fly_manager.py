import os
import time
import json
import base64
import logging
import subprocess
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, render_template, request, jsonify, stream_with_context, Response

# Define Blueprint
fly_bp = Blueprint('fly', __name__)

logger = logging.getLogger(__name__)

# Base directory for Fly files
FLY_REPO_DIR = os.path.join(os.getcwd(), 'repo_fly_files')

@fly_bp.route('/fly')
def index():
    """Render the Fly.io Management Page."""
    return render_template('fly_management.html')

@fly_bp.route('/fly/launch', methods=['POST'])
def launch_app():
    """Launch (create) the Fly app."""
    try:
        data = request.json
        app_name = data.get('app_name')
        token = data.get('token')
        
        if not app_name:
            return jsonify({"error": "App Name is required"}), 400

        cmd = ["fly", "apps", "create", app_name, "--org", "personal"] # Defaulting to personal org, can be parameterized
        
        # Execute synchronously for immediate feedback
        return _run_fly_command(cmd, token, cwd=FLY_REPO_DIR)
        
    except Exception as e:
        logger.error(f"Fly Launch Error: {e}")
        return jsonify({"error": str(e)}), 500

@fly_bp.route('/fly/deploy', methods=['POST'])
def deploy_app():
    """Deploy the Fly app (Build & Push)."""
    try:
        data = request.json
        app_name = data.get('app_name')
        token = data.get('token')
        
        if not app_name:
            return jsonify({"error": "App Name is required"}), 400

        # Deploy logic: simple command
        cmd = ["fly", "deploy", "--local-only", "--config", "fly.toml", "--dockerfile", "Dockerfile.fly", "--app", app_name]
        
        # Determine if we want to stream output or return job ID
        # For simplicity in this iteration, we'll return a generic "Started" and let frontend poll logs or use a long-running request
        # Better: SSE (Server Sent Events) or just run in background and return success
        
        # We'll run in background helper and return success
        threading.Thread(target=_run_fly_command_background, args=(cmd, token, FLY_REPO_DIR)).start()
        
        return jsonify({"status": "Deployment started", "message": f"Deploying {app_name}. Check logs for progress."})
        
    except Exception as e:
        logger.error(f"Fly Deploy Error: {e}")
        return jsonify({"error": str(e)}), 500

@fly_bp.route('/fly/process', methods=['POST'])
def process_batch_legacy():
    """Launch batch jobs on Fly Machines."""
    try:
        data = request.json
        app_name = data.get('app_name')
        token = data.get('token')
        accounts = data.get('accounts', []) # List of "email:pass:recovery" strings
        batch_size = int(data.get('batch_size', 10))
        
        if not app_name or not accounts:
            return jsonify({"error": "App Name and Accounts are required"}), 400
            
        # Parse accounts
        users = []
        for line in accounts:
            parts = line.split(':')
            if len(parts) >= 2:
                u = {"email": parts[0], "password": parts[1]}
                if len(parts) > 2: u["recovery_email"] = parts[2]
                users.append(u)
                
        if not users:
            return jsonify({"error": "No valid accounts parsed"}), 400
            
        # Create Batches
        batches = [users[i:i + batch_size] for i in range(0, len(users), batch_size)]
        
        logger.info(f"Launching {len(batches)} batches for {len(users)} users on Fly.io app {app_name}")
        
        # Launch in background
        threading.Thread(target=_launch_batches_background, args=(app_name, token, batches)).start()
        
        return jsonify({
            "status": "Processing started", 
            "message": f"Launching {len(batches)} machines for {len(users)} accounts."
        })
        
    except Exception as e:
        logger.error(f"Fly Process Error: {e}")
        return jsonify({"error": str(e)}), 500

@fly_bp.route('/fly/results', methods=['GET'])
def get_results():
    """Fetch results from app_passwords table."""
    try:
        from database import db
        from sqlalchemy import text
        
        # Determine table name - try 'app_passwords' (Fly worker) then 'aws_generated_password' (Legacy)
        # For this integration, we prioritized 'app_passwords' which the worker creates.
        
        # Raw SQL for flexibility with the ad-hoc table
        sql = text("SELECT * FROM app_passwords ORDER BY created_at DESC LIMIT 500")
        
        try:
            result = db.session.execute(sql)
            rows = []
            for r in result:
                # Handle row as dict-like
                row_dict = {
                    "email": r.email,
                    "app_password": r.app_password,
                    "created_at": r.created_at
                    # Add Secret Key if column exists and user is admin? Maybe hide for security
                }
                rows.append(row_dict)
                
            return jsonify({"status": "success", "results": rows})
            
        except Exception as db_err:
            # If table doesn't exist yet
            if "does not exist" in str(db_err):
                return jsonify({"status": "success", "results": [], "message": "No results table found yet."})
            raise db_err

    except Exception as e:
        logger.error(f"Fly Results Error: {e}")
        return jsonify({"error": str(e)}), 500

# ==============================================================================
# INFRASTRUCTURE TAB ENDPOINTS
# ==============================================================================

@fly_bp.route('/api/fly/initialize-app', methods=['POST'])
def initialize_app():
    """Initialize a new Fly.io app."""
    try:
        data = request.json
        token = data.get('token')
        app_name = data.get('app_name')
        
        if not app_name:
            return jsonify({"success": False, "error": "App name required"}), 400
        
        cmd = ["fly", "apps", "create", app_name, "--org", "personal"]
        result = _run_fly_command(cmd, token, cwd=FLY_REPO_DIR)
        
        if result.get('status') == 'success':
            return jsonify({"success": True, "message": f"App '{app_name}' created successfully"})
        else:
            return jsonify({"success": False, "error": result.get('error', 'Unknown error')})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@fly_bp.route('/api/fly/deploy-image', methods=['POST'])
def deploy_image():
    """Build and deploy Docker image to Fly.io."""
    try:
        data = request.json
        token = data.get('token')
        app_name = data.get('app_name')
        
        cmd = ["fly", "deploy", "--local-only", "--config", "fly.toml", 
               "--dockerfile", "Dockerfile.fly", "--app", app_name]
        
        # Run in background and log to buffer
        threading.Thread(target=_run_fly_command_background, args=(cmd, token, FLY_REPO_DIR)).start()
        
        return jsonify({"success": True, "message": "Deployment started. Check logs for progress."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@fly_bp.route('/api/fly/check-app-status', methods=['POST'])
def check_app_status():
    """Check status of a Fly.io app."""
    try:
        data = request.json
        token = data.get('token')
        app_name = data.get('app_name')
        
        cmd = ["fly", "status", "--app", app_name, "--json"]
        result = _run_fly_command(cmd, token, cwd=FLY_REPO_DIR)
        
        if result.get('status') == 'success':
            try:
                status_data = json.loads(result.get('output', '{}'))
                return jsonify({"success": True, "status": "running", "details": status_data})
            except:
                return jsonify({"success": True, "status": "unknown", "details": {}})
        else:
            return jsonify({"success": False, "error": result.get('error')})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@fly_bp.route('/api/fly/destroy-app', methods=['POST'])
def destroy_app():
    """Destroy a Fly.io app and all its resources."""
    try:
        data = request.json
        token = data.get('token')
        app_name = data.get('app_name')
        
        cmd = ["fly", "apps", "destroy", app_name, "--yes"]
        result = _run_fly_command(cmd, token, cwd=FLY_REPO_DIR)
        
        if result.get('status') == 'success':
            return jsonify({"success": True, "message": "App destroyed successfully"})
        else:
            return jsonify({"success": False, "error": result.get('error')})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ==============================================================================
# MACHINES TAB ENDPOINTS
# ==============================================================================

@fly_bp.route('/api/fly/list-machines', methods=['POST'])
def list_machines():
    """List all machines for an app."""
    try:
        data = request.json
        token = data.get('token')
        app_name = data.get('app_name')
        
        cmd = ["fly", "machine", "list", "--app", app_name, "--json"]
        result = _run_fly_command(cmd, token, cwd=FLY_REPO_DIR)
        
        if result.get('status') == 'success':
            try:
                machines = json.loads(result.get('output', '[]'))
                return jsonify({"success": True, "machines": machines})
            except:
                return jsonify({"success": True, "machines": []})
        else:
            return jsonify({"success": False, "error": result.get('error')})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@fly_bp.route('/api/fly/create-machine', methods=['POST'])
def create_machine():
    """Create a single test machine."""
    try:
        data = request.json
        token = data.get('token')
        app_name = data.get('app_name')
        region = data.get('region', 'lhr')
        
        cmd = ["fly", "machine", "run", "--app", app_name, "--region", region, 
               "--env", "TEST_MODE=true"]
        result = _run_fly_command(cmd, token, cwd=FLY_REPO_DIR)
        
        if result.get('status') == 'success':
            # Extract machine ID from output
            output = result.get('output', '')
            machine_id = 'unknown'
            # Try to parse machine ID from output
            return jsonify({"success": True, "machine_id": machine_id})
        else:
            return jsonify({"success": False, "error": result.get('error')})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@fly_bp.route('/api/fly/cleanup-machines', methods=['POST'])
def cleanup_machines():
    """Clean up stopped machines."""
    try:
        data = request.json
        token = data.get('token')
        app_name = data.get('app_name')
        
        # First list machines
        cmd_list = ["fly", "machine", "list", "--app", app_name, "--json"]
        result = _run_fly_command(cmd_list, token, cwd=FLY_REPO_DIR)
        
        if result.get('status') != 'success':
            return jsonify({"success": False, "error": "Failed to list machines"})
        
        try:
            machines = json.loads(result.get('output', '[]'))
            stopped = [m for m in machines if m.get('state') == 'stopped']
            
            # Run cleanup in background
            threading.Thread(target=_cleanup_machines_background, 
                           args=(app_name, token, stopped)).start()
            
            return jsonify({"success": True, "removed_count": len(stopped), 
                          "message": f"Removing {len(stopped)} stopped machine(s)"})
        except:
            return jsonify({"success": False, "error": "Failed to parse machine list"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ==============================================================================
# PROCESSING TAB ENDPOINTS
# ==============================================================================

@fly_bp.route('/api/fly/process-batch', methods=['POST'])
def process_batch():
    """Process batch of accounts using Fly machines with production orchestrator."""
    try:
        data = request.json
        token = data.get('token')
        app_name = data.get('app_name')
        accounts = data.get('accounts', [])
        batch_size = int(data.get('batch_size', 10))
        use_multi_region = data.get('use_multi_region', True)
        
        if not accounts:
            return jsonify({"success": False, "error": "No accounts provided"})
        
        # Parse accounts
        users = []
        for line in accounts:
            parts = line.split(':')
            if len(parts) >= 2:
                u = {"email": parts[0], "password": parts[1]}
                if len(parts) > 2:
                    u["recovery_email"] = parts[2]
                users.append(u)
        
        if not users:
            return jsonify({"success": False, "error": "No valid accounts parsed"})
        
        logger.info(f"Starting production processing for {len(users)} users")
        
        # Import orchestrator
        from routes.fly_orchestrator import process_large_batch
        
        # Run in background thread
        def _run_processing():
            try:
                summary = process_large_batch(
                    app_name=app_name,
                    token=token,
                    users=users,
                    batch_size=batch_size,
                    use_multi_region=use_multi_region,
                    log_buffer=log_buffer
                )
                logger.info(f"Processing complete: {summary}")
            except Exception as e:
                logger.error(f"Processing failed: {str(e)}")
                logger.error(traceback.format_exc())
        
        threading.Thread(target=_run_processing, daemon=True).start()
        
        estimated_machines = (len(users) + batch_size - 1) // batch_size
        
        return jsonify({
            "success": True, 
            "message": f"Processing {len(users)} accounts across ~{estimated_machines} machines",
            "estimated_machines": estimated_machines,
            "users_per_machine": batch_size,
            "max_duration_minutes": 20,
            "auto_cleanup": True
        })
    except Exception as e:
        logger.error(f"Process batch error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

# ==============================================================================
# STATUS TAB ENDPOINTS
# ==============================================================================

@fly_bp.route('/api/fly/global-status', methods=['POST'])
def global_status():
    """Get global status of all Fly.io apps."""
    try:
        data = request.json
        token = data.get('token')
        
        # List all apps
        cmd = ["fly", "apps", "list", "--json"]
        result = _run_fly_command(cmd, token, cwd=os.getcwd())
        
        if result.get('status') != 'success':
            return jsonify({"success": False, "error": "Failed to list apps"})
        
        try:
            apps_data = json.loads(result.get('output', '[]'))
            
            # For each app, get machine count
            apps = []
            total_running = 0
            total_stopped = 0
            regions_set = set()
            
            for app in apps_data:
                app_name = app.get('Name', app.get('name', ''))
                
                # Get machines for this app
                cmd_machines = ["fly", "machine", "list", "--app", app_name, "--json"]
                machines_result = _run_fly_command(cmd_machines, token, cwd=os.getcwd())
                
                machines = []
                app_regions = []
                if machines_result.get('status') == 'success':
                    try:
                        machines = json.loads(machines_result.get('output', '[]'))
                        app_regions = list(set([m.get('region', 'unknown') for m in machines]))
                        regions_set.update(app_regions)
                        
                        running = sum(1 for m in machines if m.get('state') == 'started')
                        stopped = sum(1 for m in machines if m.get('state') == 'stopped')
                        total_running += running
                        total_stopped += stopped
                    except:
                        pass
                
                apps.append({
                    "name": app_name,
                    "status": app.get('Status', 'unknown'),
                    "machine_count": len(machines),
                    "regions": app_regions
                })
            
            return jsonify({
                "success": True,
                "total_apps": len(apps),
                "running_machines": total_running,
                "stopped_machines": total_stopped,
                "total_regions": len(regions_set),
                "apps": apps
            })
        except Exception as parse_err:
            return jsonify({"success": False, "error": f"Parse error: {str(parse_err)}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



@fly_bp.route('/fly/cleanup', methods=['POST'])
def cleanup_machines_legacy():
    """Destroy stopped Fly Machines."""
    try:
        data = request.json
        app_name = data.get('app_name')
        token = data.get('token')
        
        if not app_name:
            return jsonify({"error": "App Name required"}), 400
            
        # Run in background
        threading.Thread(target=_cleanup_machines_background, args=(app_name, token)).start()
        
        return jsonify({"status": "Cleanup started", "message": "Destroying stopped machines..."})
        
    except Exception as e:
        logger.error(f"Fly Cleanup Error: {e}")
        return jsonify({"error": str(e)}), 500


@fly_bp.route('/fly/stream-app-logs')
def stream_app_logs():
    """Stream application logs from Fly.io (fly logs)."""
    app_name = request.args.get('app_name')
    token = request.args.get('token')
    
    if not app_name:
        return "App Name required", 400
        
    def generate():
        env = os.environ.copy()
        if token:
            env["FLY_ACCESS_TOKEN"] = token
            
        cmd = ["fly", "logs", "-a", app_name, "--no-print-ids", "--no-print-machine-id"]
        
        # Use Popen to stream
        try:
            startupinfo = None
            if os.name == 'nt':
                 startupinfo = subprocess.STARTUPINFO()
                 startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            proc = subprocess.Popen(
                cmd,
                cwd=FLY_REPO_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                startupinfo=startupinfo
            )
            
            # Yield lines
            for line in proc.stdout:
                if line:
                    data = {"message": line.strip(), "type": "app-log"}
                    yield f"data: {json.dumps(data)}\n\n"
                    
            # Handle exit
            stderr = proc.stderr.read()
            if stderr:
                 data = {"message": f"Log stream exited: {stderr}", "type": "error"}
                 yield f"data: {json.dumps(data)}\n\n"
                 
        except Exception as e:
            data = {"message": f"Log stream exception: {e}", "type": "error"}
            yield f"data: {json.dumps(data)}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


# ==============================================================================
# Real-time Log Streaming System
# ==============================================================================

class LogBuffer:
    """Thread-safe circular buffer for log messages."""
    def __init__(self, size=500):
        self.size = size
        self.buffer = []
        self.lock = threading.Lock()
        self.listeners = []  # List of Queue objects for active listeners

    def write(self, message, type='info'):
        """Write a message to the buffer and notify listeners."""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        entry = {"time": timestamp, "message": message, "type": type}
        
        with self.lock:
            self.buffer.append(entry)
            if len(self.buffer) > self.size:
                self.buffer.pop(0)
            
            # Notify listeners (push directly to queues)
            for q in self.listeners[:]: # Copy list to iterate safely
                try:
                    q.put(entry)
                except:
                    # If queue is full or closed, remove listener
                    if q in self.listeners:
                        self.listeners.remove(q)

    def get_recent(self, count=50):
        """Get recent logs for initial connection."""
        with self.lock:
            return list(self.buffer[-count:])

    def register_listener(self):
        """Register a new listener queue."""
        import queue
        q = queue.Queue(maxsize=100)
        with self.lock:
            self.listeners.append(q)
        return q
        
    def unregister_listener(self, q):
        """Remove a listener queue."""
        with self.lock:
            if q in self.listeners:
                self.listeners.remove(q)

# Global Log Buffer
log_buffer = LogBuffer()

@fly_bp.route('/fly/stream-logs')
def stream_logs():
    """SSE Endpoint for real-time logs."""
    def generate():
        q = log_buffer.register_listener()
        
        # Send recent history first
        recent = log_buffer.get_recent()
        for entry in recent:
            yield f"data: {json.dumps(entry)}\n\n"
            
        try:
            while True:
                # Wait for new messages (blocking get with timeout to allow heartbeat)
                try:
                    import queue
                    entry = q.get(timeout=15) # 15s heartbeat
                    yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
                    # Heartbeat comment to keep connection alive
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            # Client disconnected
            log_buffer.unregister_listener(q)
        except Exception as e:
            logger.error(f"SSE Error: {e}")
            log_buffer.unregister_listener(q)

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


# ==============================================================================
# Helper Functions
# ==============================================================================

def _run_fly_command(cmd, token, cwd=None):
    """Run command and return JSON output."""
    env = os.environ.copy()
    if token:
        env["FLY_ACCESS_TOKEN"] = token
        
    try:
        startupinfo = None
        if os.name == 'nt':
             startupinfo = subprocess.STARTUPINFO()
             startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            startupinfo=startupinfo
        )
        stdout, stderr = proc.communicate()
        
        if proc.returncode == 0:
            log_buffer.write(f"Command successful: {' '.join(cmd)}", 'success')
            return jsonify({"status": "success", "output": stdout, "stderr": stderr})
        else:
            log_buffer.write(f"Command failed: {' '.join(cmd)}", 'error')
            return jsonify({"status": "error", "output": stdout, "error_details": stderr}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _run_fly_command_background(cmd, token, cwd=None):
    """Run command in background and log to app logger."""
    env = os.environ.copy()
    if token:
        env["FLY_ACCESS_TOKEN"] = token
        
    try:
        log_buffer.write(f"Starting background command: {' '.join(cmd)}", 'info')
        logger.info(f"[FLY_BG] Starting: {' '.join(cmd)}")
        
        startupinfo = None
        if os.name == 'nt':
             startupinfo = subprocess.STARTUPINFO()
             startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Use Popen to stream output line by line if possible (simulated here with communicate for simplicity but blocking)
        # For true streaming, we'd read stdout in a loop.
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            startupinfo=startupinfo
        )
        
        # Read output line by line for better UX
        for line in proc.stdout:
            line = line.strip()
            if line:
                log_buffer.write(line, 'info')
                logger.info(f"[FLY_BG] {line}")
                
        # Wait for completion
        proc.wait()
        stderr = proc.stderr.read()
        
        if proc.returncode == 0:
            log_buffer.write("Background command finished successfully.", 'success')
            logger.info(f"[FLY_BG] Success.")
        else:
            log_buffer.write(f"Background command failed: {stderr}", 'error')
            logger.error(f"[FLY_BG] Failed: {stderr}")
            
    except Exception as e:
        log_buffer.write(f"Background command exception: {str(e)}", 'error')
        logger.error(f"[FLY_BG] Exception: {e}")

def _launch_batches_background(app_name, token, batches):
    """Launch Fly Machines for each batch."""
    image_ref = f"registry.fly.io/{app_name}:latest"
    env = os.environ.copy()
    if token:
        env["FLY_ACCESS_TOKEN"] = token
        
    log_buffer.write(f"Starting launch of {len(batches)} batches...", 'info')
        
    for i, batch in enumerate(batches):
        try:
            machine_name = f"{app_name}-batch-{int(time.time())}-{i+1}"
            batch_json = json.dumps(batch)
            batch_b64 = base64.b64encode(batch_json.encode('utf-8')).decode('utf-8')
            
            cmd = [
                "fly", "machine", "run", image_ref,
                "--name", machine_name,
                "--region", "yul",
                "--app", app_name,
                "--detach",
                "--autostart",
                "-e", f"BATCH_DATA_B64={batch_b64}"
            ]
            
            log_buffer.write(f"Launching batch {i+1}/{len(batches)}: {machine_name}", 'info')
            logger.info(f"[FLY_BATCH] Launching batch {i+1}: {machine_name}")
            
            # Execute
            startupinfo = None
            if os.name == 'nt':
                     startupinfo = subprocess.STARTUPINFO()
                     startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            proc = subprocess.Popen(
                cmd,
                cwd=FLY_REPO_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                startupinfo=startupinfo
            )
            stdout, stderr = proc.communicate()
            
            if proc.returncode != 0:
                log_buffer.write(f"Failed to launch batch {i+1}: {stderr}", 'error')
                logger.error(f"[FLY_BATCH] Failed batch {i+1}: {stderr}")
            else:
                log_buffer.write(f"Successfully launched batch {i+1}", 'success')
                logger.info(f"[FLY_BATCH] Launched batch {i+1}")
                
            time.sleep(2) # Throttle
            
        except Exception as e:
            log_buffer.write(f"Exception launching batch {i+1}: {str(e)}", 'error')
            logger.error(f"[FLY_BATCH] Exception batch {i+1}: {e}")
            
    log_buffer.write("All batches processed.", 'success')

def _cleanup_machines_background(app_name, token):
    """Cleanup stopped Fly Machines."""
    env = os.environ.copy()
    if token:
        env["FLY_ACCESS_TOKEN"] = token
        
    log_buffer.write("Starting cleanup of stopped machines...", 'info')
    
    try:
        # Step 1: List all machines
        cmd_list = ["fly", "machine", "list", "--app", app_name, "--json"]
        
        startupinfo = None
        if os.name == 'nt':
             startupinfo = subprocess.STARTUPINFO()
             startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        proc = subprocess.Popen(
            cmd_list,
            cwd=FLY_REPO_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            startupinfo=startupinfo
        )
        stdout, stderr = proc.communicate()
        
        if proc.returncode != 0:
            log_buffer.write(f"Failed to list machines: {stderr}", 'error')
            return
            
        machines = json.loads(stdout)
        stopped_machines = [m for m in machines if m.get('state') == 'stopped']
        
        if not stopped_machines:
            log_buffer.write("No stopped machines found to cleanup.", 'success')
            return
            
        log_buffer.write(f"Found {len(stopped_machines)} stopped machines. Deleting...", 'info')
        
        # Step 2: Delete one by one (safer than bulk in case of errors)
        for m in stopped_machines:
            mid = m['id']
            cmd_del = ["fly", "machine", "remove", mid, "--force", "--app", app_name]
            
            proc_del = subprocess.Popen(
                cmd_del,
                cwd=FLY_REPO_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                startupinfo=startupinfo
            )
            out, err = proc_del.communicate()
            
            if proc_del.returncode == 0:
                log_buffer.write(f"Deleted machine {mid}", 'info')
            else:
                log_buffer.write(f"Failed to delete {mid}: {err}", 'error')
                
        log_buffer.write("Cleanup complete.", 'success')
        
    except Exception as e:
        log_buffer.write(f"Cleanup Exception: {str(e)}", 'error')

