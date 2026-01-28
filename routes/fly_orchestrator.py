"""
Fly.io Production Orchestrator
Handles 1000+ concurrent users with parallel machine creation and auto-cleanup
"""
import os
import json
import time
import uuid
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Configuration
MAX_USERS_PER_MACHINE = 10  # Optimize for 10 users per machine
MAX_CONCURRENT_MACHINES = 100  # Fly.io limit
MACHINE_TIMEOUT_MINUTES = 20  # Max runtime per machine
MACHINE_CHECK_INTERVAL = 30  # Check machine status every 30 seconds

# Available regions for IP diversity
AVAILABLE_REGIONS = [
    'iad',  # US East
    'lax',  # US West
    'lhr',  # Europe (London)
    'fra',  # Europe (Frankfurt)
    'ams',  # Europe (Amsterdam)
    'syd',  # Asia Pacific (Sydney)
    'nrt',  # Asia Pacific (Tokyo)
]

class FlyOrchestrator:
    """
    Production orchestrator for parallel Fly.io machine management
    """
    
    def __init__(self, app_name: str, token: str, log_buffer=None):
        self.app_name = app_name
        self.token = token
        self.log_buffer = log_buffer
        self.active_machines = {}
        self.results = []
        self.lock = threading.Lock()
        
    def log(self, message: str, level: str = 'info'):
        """Thread-safe logging"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_msg = f"[{timestamp}] {message}"
        
        if level == 'info':
            logger.info(message)
        elif level == 'error':
            logger.error(message)
        elif level == 'warning':
            logger.warning(message)
            
        if self.log_buffer:
            self.log_buffer.write(json.dumps({
                "message": message,
                "type": level,
                "timestamp": timestamp
            }) + "\n")
    
    def run_fly_command(self, cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
        """
        Execute Fly CLI command with proper error handling
        """
        env = os.environ.copy()
        if self.token:
            env['FLY_ACCESS_TOKEN'] = self.token
        
        try:
            # Windows-compatible subprocess
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                startupinfo=startupinfo
            )
            
            if result.returncode == 0:
                return {"success": True, "output": result.stdout}
            else:
                return {"success": False, "error": result.stderr or result.stdout}
                
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Command timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_machine(self, region: str, batch_data: List[Dict], batch_index: int) -> Optional[str]:
        """
        Create a single Fly machine with batch data
        Returns machine ID or None on failure
        """
        try:
            # Encode batch data as environment variable
            batch_json = json.dumps(batch_data)
            batch_b64 = subprocess.run(
                ['python', '-c', f'import base64; print(base64.b64encode("{batch_json}".encode()).decode())'],
                capture_output=True,
                text=True
            ).stdout.strip()
            
            machine_name = f"batch-{batch_index}-{uuid.uuid4().hex[:8]}"
            
            cmd = [
                "fly", "machine", "run",
                "--app", self.app_name,
                "--region", region,
                "--name", machine_name,
                "--env", f"BATCH_DATA_B64={batch_b64}",
                "--env", "AUTO_DESTROY=true",
                "--auto-destroy",
                "--json"
            ]
            
            self.log(f"Creating machine {machine_name} in {region} for {len(batch_data)} users...")
            
            result = self.run_fly_command(cmd, timeout=120)
            
            if result['success']:
                try:
                    machine_info = json.loads(result['output'])
                    machine_id = machine_info.get('id') or machine_info.get('ID')
                    
                    with self.lock:
                        self.active_machines[machine_id] = {
                            "name": machine_name,
                            "region": region,
                            "batch_index": batch_index,
                            "user_count": len(batch_data),
                            "created_at": datetime.now(),
                            "status": "created"
                        }
                    
                    self.log(f"✅ Machine {machine_id} created successfully", 'info')
                    return machine_id
                except json.JSONDecodeError:
                    self.log(f"❌ Failed to parse machine creation response", 'error')
                    return None
            else:
                self.log(f"❌ Machine creation failed: {result['error']}", 'error')
                return None
                
        except Exception as e:
            self.log(f"❌ Exception creating machine: {str(e)}", 'error')
            return None
    
    def monitor_machine(self, machine_id: str) -> bool:
        """
        Monitor a machine until complete or timeout
        Returns True if successful, False if timeout/failed
        """
        start_time = datetime.now()
        timeout = timedelta(minutes=MACHINE_TIMEOUT_MINUTES)
        
        while True:
            elapsed = datetime.now() - start_time
            
            # Check timeout
            if elapsed > timeout:
                self.log(f"⏱️ Machine {machine_id} timed out after {MACHINE_TIMEOUT_MINUTES} minutes", 'warning')
                self.destroy_machine(machine_id)
                return False
            
            # Check status
            cmd = ["fly", "machine", "status", machine_id, "--app", self.app_name, "--json"]
            result = self.run_fly_command(cmd, timeout=10)
            
            if result['success']:
                try:
                    status_data = json.loads(result['output'])
                    state = status_data.get('state', 'unknown')
                    
                    with self.lock:
                        if machine_id in self.active_machines:
                            self.active_machines[machine_id]['status'] = state
                    
                    if state in ['stopped', 'destroyed']:
                        self.log(f"✅ Machine {machine_id} completed ({state})", 'info')
                        return True
                    elif state == 'failed':
                        self.log(f"❌ Machine {machine_id} failed", 'error')
                        return False
                        
                except json.JSONDecodeError:
                    pass
            
            # Wait before next check
            time.sleep(MACHINE_CHECK_INTERVAL)
    
    def destroy_machine(self, machine_id: str, force: bool = True):
        """
        Destroy a machine
        """
        try:
            cmd = ["fly", "machine", "destroy", machine_id, "--app", self.app_name]
            if force:
                cmd.append("--force")
            
            result = self.run_fly_command(cmd, timeout=30)
            
            if result['success']:
                self.log(f"🗑️ Machine {machine_id} destroyed", 'info')
                with self.lock:
                    if machine_id in self.active_machines:
                        del self.active_machines[machine_id]
            else:
                self.log(f"⚠️ Failed to destroy {machine_id}: {result['error']}", 'warning')
                
        except Exception as e:
            self.log(f"Error destroying machine {machine_id}: {str(e)}", 'error')
    
    def process_batch_parallel(self, users: List[Dict], batch_size: int = MAX_USERS_PER_MACHINE, 
                                use_multi_region: bool = True) -> Dict[str, Any]:
        """
        Main orchestration function: Process large batch with parallel machines
        
        Args:
            users: List of user dicts (email, password, recovery_email)
            batch_size: Users per machine
            use_multi_region: Distribute across regions
            
        Returns:
            Summary dict with statistics
        """
        total_users = len(users)
        self.log(f"🚀 Starting parallel processing for {total_users} users")
        self.log(f"📊 Batch size: {batch_size} users/machine")
        
        # Create batches
        batches = [users[i:i + batch_size] for i in range(0, total_users, batch_size)]
        total_machines = len(batches)
        
        self.log(f"📦 Created {total_machines} batches")
        
        # Distribute regions
        if use_multi_region:
            regions = [AVAILABLE_REGIONS[i % len(AVAILABLE_REGIONS)] for i in range(total_machines)]
            self.log(f"🌍 Distributing across {len(set(regions))} regions for IP diversity")
        else:
            regions = ['lhr'] * total_machines
        
        # Create machines in parallel
        machine_ids = []
        with ThreadPoolExecutor(max_workers=min(20, total_machines)) as executor:
            futures = {
                executor.submit(self.create_machine, regions[i], batch, i): i 
                for i, batch in enumerate(batches)
            }
            
            for future in as_completed(futures):
                machine_id = future.result()
                if machine_id:
                    machine_ids.append(machine_id)
        
        created_count = len(machine_ids)
        self.log(f"✅ Created {created_count}/{total_machines} machines successfully")
        
        if created_count == 0:
            return {
                "success": False,
                "error": "No machines could be created",
                "total_users": total_users,
                "machines_created": 0
            }
        
        # Monitor all machines in parallel
        self.log(f"👀 Monitoring {created_count} machines (max {MACHINE_TIMEOUT_MINUTES} minutes each)...")
        
        successful_machines = 0
        with ThreadPoolExecutor(max_workers=min(10, created_count)) as executor:
            monitor_futures = {
                executor.submit(self.monitor_machine, mid): mid 
                for mid in machine_ids
            }
            
            for future in as_completed(monitor_futures):
                if future.result():
                    successful_machines += 1
        
        # Cleanup any remaining machines
        self.log("🧹 Performing final cleanup...")
        cmd = ["fly", "machine", "list", "--app", self.app_name, "--json"]
        result = self.run_fly_command(cmd)
        
        if result['success']:
            try:
                machines = json.loads(result['output'])
                for machine in machines:
                    if machine.get('state') in ['stopped', 'failed']:
                        self.destroy_machine(machine.get('id'), force=True)
            except:
                pass
        
        # Summary
        summary = {
            "success": True,
            "total_users": total_users,
            "total_batches": total_machines,
            "machines_created": created_count,
            "machines_completed": successful_machines,
            "regions_used": list(set(regions)),
            "duration_minutes": (datetime.now() - datetime.now()).total_seconds() / 60
        }
        
        self.log(f"🎉 Processing complete! {successful_machines}/{created_count} machines succeeded")
        return summary


def process_large_batch(app_name: str, token: str, users: List[Dict], 
                       batch_size: int = 10, use_multi_region: bool = True,
                       log_buffer=None) -> Dict[str, Any]:
    """
    Convenience function to process large batch
    """
    orchestrator = FlyOrchestrator(app_name, token, log_buffer)
    return orchestrator.process_batch_parallel(users, batch_size, use_multi_region)
