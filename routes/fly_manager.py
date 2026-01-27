import os
import time
import json
import base64
import logging
import subprocess
import threading
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
def process_batch():
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
            return jsonify({"status": "success", "output": stdout, "stderr": stderr})
        else:
            return jsonify({"status": "error", "output": stdout, "error_details": stderr}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _run_fly_command_background(cmd, token, cwd=None):
    """Run command in background and log to app logger."""
    env = os.environ.copy()
    if token:
        env["FLY_ACCESS_TOKEN"] = token
        
    try:
        logger.info(f"[FLY_BG] Starting: {' '.join(cmd)}")
        
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
            logger.info(f"[FLY_BG] Success: {stdout[:200]}...")
        else:
            logger.error(f"[FLY_BG] Failed: {stderr}")
            
    except Exception as e:
        logger.error(f"[FLY_BG] Exception: {e}")

def _launch_batches_background(app_name, token, batches):
    """Launch Fly Machines for each batch."""
    image_ref = f"registry.fly.io/{app_name}:latest"
    env = os.environ.copy()
    if token:
        env["FLY_ACCESS_TOKEN"] = token
        
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
                logger.error(f"[FLY_BATCH] Failed batch {i+1}: {stderr}")
            else:
                logger.info(f"[FLY_BATCH] Launched batch {i+1}")
                
            time.sleep(2) # Throttle
            
        except Exception as e:
            logger.error(f"[FLY_BATCH] Exception batch {i+1}: {e}")
