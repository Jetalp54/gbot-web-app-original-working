"""
DigitalOcean Bulk Execution Orchestrator

Handles the complete workflow for distributing users across multiple droplets
and executing automation in parallel.
"""

import os
import json
import logging
import threading
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import re
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

from database import db, DigitalOceanDroplet, DigitalOceanExecution, AwsGeneratedPassword
from services.digitalocean_service import DigitalOceanService

logger = logging.getLogger(__name__)


class BulkExecutionOrchestrator:
    """Orchestrates bulk execution across multiple DigitalOcean droplets"""
    
    def __init__(self, config: Dict, service: DigitalOceanService, app=None):
        """
        Initialize orchestrator.
        
        Args:
            config: DigitalOcean configuration dict
            service: DigitalOceanService instance
        """
        self.config = config
        self.service = service
        self.app = app or current_app # If app not passed, try to grab current (risky in thread if not careful)
        # Actually, if we pass app in init, we are good.
        # But wait, in the manager route, we initialized `orchestrator = BulkExecutionOrchestrator(config_dict, service)` 
        # WITHOUT app.
        
        # We need to make sure `execute_bulk` can receive app or we set it later.
        # Let's check where it's initialized.

        self.execution_id = None
    def set_app(self, app):
        """Set Flask app instance for context"""
        self.app = app
        
    def execute_bulk(
        self,
        users: List[Dict],
        droplet_count: Optional[int] = None,
        snapshot_id: str = None,
        region: str = None,
        size: str = None,
        auto_destroy: bool = True,
        parallel_users: int = 5,
        users_per_droplet: int = 50,
        execution_id: str = None
    ) -> Dict:
        """
        Execute bulk automation across multiple droplets.
        
        Workflow:
        1. Distribute users across droplets
        2. Create droplets from snapshot
        3. Wait for droplets to be active
        4. Execute automation on each droplet via SSH
        5. Collect results
        6. Destroy droplets (if auto_destroy=True)
        
        Args:
            users: List of user dicts with email/password
            droplet_count: Number of droplets to create
            snapshot_id: Snapshot ID to use as base image
            region: Region to create droplets in
            size: Droplet size
            auto_destroy: Whether to destroy droplets after completion
            parallel_users: Total parallel users across all droplets
            users_per_droplet: Max users per droplet (to determine droplet count)
            execution_id: Optional existing execution ID to use
            
        Returns:
            Dict with execution results
        """
        exec_start = datetime.utcnow()
        self.execution_id = execution_id or f"exec_{int(time.time())}"
        
        # Determine efficient distribution
        # If droplet_count is 0 or None, we calculate it based on users_per_droplet
        if not droplet_count or droplet_count <= 0:
            if users_per_droplet and users_per_droplet > 0:
                droplet_count = (len(users) + users_per_droplet - 1) // users_per_droplet
            else:
                droplet_count = 1
        
        logger.info(f"[{self.execution_id}] Starting bulk execution: {len(users)} users, {droplet_count} droplets, {parallel_users} total parallel")
        
        try:
            # 1. Distribute users
            user_batches = DigitalOceanService.distribute_users(
                users, 
                droplet_count=droplet_count, 
                max_users_per_droplet=users_per_droplet
            )
            final_droplet_count = len(user_batches)
            logger.info(f"[{self.execution_id}] Distributed {len(users)} users into {final_droplet_count} batches")
            
            # 1.5 Fetch 2Captcha Config from DB
            self.twocaptcha_config = {'enabled': False, 'api_key': None}
            if self.app:
                try:
                    with self.app.app_context():
                        from database import TwoCaptchaConfig
                        config = TwoCaptchaConfig.query.first()
                        if config:
                            self.twocaptcha_config = {
                                'enabled': config.enabled,
                                'api_key': config.api_key
                            }
                            logger.info(f"[{self.execution_id}] 2Captcha Config: Enabled={config.enabled}")
                except Exception as cap_e:
                    logger.warning(f"[{self.execution_id}] Failed to fetch 2Captcha config: {cap_e}")
            
            # 2. Create droplets
            droplet_info, creation_errors = self._create_droplets_parallel(
                count=final_droplet_count,
                snapshot_id=snapshot_id,
                region=region,
                size=size
            )
            
            if not droplet_info:
                error_msg = f"Failed to create droplets: {'; '.join(creation_errors)}" if creation_errors else 'Failed to create droplets (Unknown error)'
                return {
                    'success': False,
                    'error': error_msg,
                    'execution_id': self.execution_id
                }
            
            logger.info(f"[{self.execution_id}] Created {len(droplet_info)} droplets")
            
            # Use parallel_users as threads per droplet (as indicated in the UI)
            workers_per_droplet = parallel_users
            logger.info(f"[{self.execution_id}] Using {workers_per_droplet} parallel workers per droplet")
            
            # 3. Execute automation on each droplet (and destroy if auto_destroy=True)
            results = self._execute_on_droplets_parallel(
                droplet_info, 
                user_batches, 
                workers_per_droplet,
                auto_destroy=auto_destroy
            )
            
            # 5. Compile results
            exec_end = datetime.utcnow()
            execution_time = (exec_end - exec_start).total_seconds()
            
            success_count = sum(1 for r in results if r.get('success'))
            fail_count = len(results) - success_count
            
            return {
                'success': True,
                'execution_id': self.execution_id,
                'total_users': len(users),
                'droplets_used': len(droplet_info),
                'success_count': success_count,
                'fail_count': fail_count,
                'execution_time_seconds': execution_time,
                'results': results
            }
            
        except Exception as e:
            import traceback
            logger.error(f"[{self.execution_id}] Bulk execution CRASHED: {e}")
            logger.error(traceback.format_exc())
            
            # Clean up any created droplets (safety net)
            if self.droplets_created and auto_destroy:
                logger.warning(f"[{self.execution_id}] Triggering safety cleanup of {len(self.droplets_created)} droplets due to crash.")
                self._destroy_droplets_parallel(self.droplets_created)
            
            return {
                'success': False,
                'error': f"Crash: {str(e)}",
                'execution_id': self.execution_id
            }
    
    def _create_droplets_parallel(
        self,
        count: int,
        snapshot_id: str,
        region: str,
        size: str
    ) -> Tuple[List[Dict], List[str]]:
        """Create multiple droplets in parallel"""
        droplets = []
        errors = []
        
        with ThreadPoolExecutor(max_workers=min(count, 10)) as executor:
            futures = []
            
            for i in range(count):
                # Sanitize name: replace underscores with hyphens for DO compliance
                safe_exec_id = self.execution_id.replace('_', '-')
                name = f"bulk-exec-{safe_exec_id}-{i+1}"
                future = executor.submit(
                    self._create_and_wait_for_droplet,
                    name, snapshot_id, region, size
                )
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    droplet = future.result()
                    if droplet:
                        droplets.append(droplet)
                        self.droplets_created.append(droplet)
                    else:
                        errors.append("Droplet creation returned None without exception")
                except Exception as e:
                    error_str = str(e)
                    logger.error(f"[{self.execution_id}] Future creation failed: {error_str}")
                    errors.append(error_str)
        
        return droplets, errors
    
    def _create_and_wait_for_droplet(
        self,
        name: str,
        snapshot_id: str,
        region: str,
        size: str
    ) -> Optional[Dict]:
        """Create a droplet and wait for it to be active"""
        # No broad try-except here - let exceptions bubble up to the parallel executor
        # PRIORITY: Look for SSH key named 'Default' in DigitalOcean account
        ssh_keys = []
        try:
            # Attempt 1: Look for "Default" key
            default_key = self.service.get_ssh_key_by_name('Default')
            if default_key:
                ssh_keys.append(default_key['id'])
                logger.info(f"[{self.execution_id}] Using 'Default' SSH key ID: {default_key['id']}")
            else:
                logger.warning(f"[{self.execution_id}] 'Default' SSH key NOT found on DigitalOcean.")
                
                # Attempt 2: Use configured key from Settings
                ssh_key_id = self.config.get('ssh_key_id')
                if ssh_key_id:
                    logger.info(f"[{self.execution_id}] Using configured SSH key ID from settings: {ssh_key_id}")
                    ssh_keys.append(int(ssh_key_id) if str(ssh_key_id).isdigit() else ssh_key_id)
                else:
                    # Attempt 3: Last resort - use the FIRST key found in account
                    all_keys = self.service.list_keys()
                    if all_keys:
                        last_resort_key = all_keys[0]
                        logger.warning(f"[{self.execution_id}] Using FIRST available key as last resort: {last_resort_key.get('name')} ({last_resort_key.get('id')})")
                        ssh_keys.append(last_resort_key['id'])
        
        except Exception as e:
            logger.error(f"[{self.execution_id}] Error resolving SSH keys: {e}")
            # Critical fallback
            ssh_key_id = self.config.get('ssh_key_id')
            if ssh_key_id:
                ssh_keys.append(int(ssh_key_id) if str(ssh_key_id).isdigit() else ssh_key_id)
        
        if not ssh_keys:
             logger.error(f"[{self.execution_id}] ❌ NO SSH KEYS FOUND. Droplet creation will fail.")
             raise Exception("No usable SSH key found. Please add a key named 'Default' to your DigitalOcean account or configure one in Settings.")

        # Create droplet
        logger.info(f"[{self.execution_id}] Creating droplet {name} in {region} (Size: {size}, Image: {snapshot_id})")
        result, error_msg = self.service.create_droplet(
            name=name,
            region=region,
            size=size,
            image=snapshot_id,
            ssh_keys=ssh_keys,
            tags=['bulk-execution', self.execution_id]
        )
        
        if not result:
            logger.error(f"[{self.execution_id}] ❌ API Error creating droplet {name}: {error_msg}")
            raise Exception(f"DigitalOcean API Error: {error_msg}")
        
        droplet_id = result['id']
        
        # Wait for active status and IP
        ip_address = self.service.wait_for_droplet_active(droplet_id, timeout=300)
        
        if not ip_address:
            logger.error(f"[{self.execution_id}] Droplet {droplet_id} did not become active")
            raise Exception(f"Droplet {droplet_id} timed out waiting for IP address after activation")
        
        # Wait additional time for SSH to be ready
        time.sleep(30)
        
        # Save droplet to database
        if self.app:
            with self.app.app_context():
                try:
                    droplet_record = DigitalOceanDroplet(
                        droplet_id=str(droplet_id),
                        droplet_name=name,
                        ip_address=ip_address,
                        region=region,
                        size=size,
                        status='active',
                        execution_task_id=self.execution_id,
                        created_by_username=self.config.get('username', 'system'),
                        auto_destroy=True
                    )
                    db.session.add(droplet_record)
                    db.session.commit()
                    logger.info(f"[{self.execution_id}] Saved droplet {droplet_id} to DB")
                except Exception as db_e:
                    logger.error(f"[{self.execution_id}] Failed to save droplet record: {db_e}")
        else:
             logger.warning(f"[{self.execution_id}] No app context - skipping DB save for droplet {droplet_id}")

        return {
            'id': droplet_id,
            'name': name,
            'ip_address': ip_address,
            'region': region,
            'size': size
        }
    
    def _execute_on_droplets_parallel(
        self,
        droplets: List[Dict],
        user_batches: List[List[Dict]],
        workers_per_droplet: int = 1,
        auto_destroy: bool = False
    ) -> List[Dict]:
        """Execute automation on multiple droplets in parallel"""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=len(droplets)) as executor:
            futures = {}
            
            for droplet, users in zip(droplets, user_batches):
                future = executor.submit(
                    self._execute_and_destroy_droplet,
                    droplet, users, workers_per_droplet, auto_destroy
                )
                futures[future] = droplet
            
            for future in as_completed(futures):
                droplet = futures[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    logger.info(f"[{self.execution_id}] Completed execution flow on {droplet['name']}")
                except Exception as e:
                    logger.error(f"[{self.execution_id}] Execution failed on {droplet['name']}: {e}")
        
        return all_results
    
    def _execute_and_destroy_droplet(
        self,
        droplet: Dict,
        users: List[Dict],
        workers_per_droplet: int,
        auto_destroy: bool
    ) -> List[Dict]:
        """Wrapper to execute on a droplet and immediately destroy it regardless of outcome"""
        try:
            results = self._execute_on_single_droplet(droplet, users, workers_per_droplet)
        except Exception as e:
            logger.error(f"[{self.execution_id}] Execution error in single droplet wrapper: {e}")
            results = [] 
        finally:
            logger.info(f"[{self.execution_id}] Finalizing droplet {droplet['name']}. Auto-destroy={auto_destroy}")
            if auto_destroy:
                try:
                    logger.info(f"[{self.execution_id}] IMMEDIATE DESTRUCTION: Destroying droplet {droplet['name']} ({droplet['id']})")
                    self.service.delete_droplet(droplet['id'])
                    
                    # Update DB status if possible
                    if self.app:
                        with self.app.app_context():
                            db_droplet = DigitalOceanDroplet.query.filter_by(droplet_id=str(droplet['id'])).first()
                            if db_droplet:
                                db_droplet.status = 'destroyed'
                                db_droplet.destroyed_at = datetime.utcnow()
                                db.session.commit()
                                
                except Exception as cleanup_error:
                    logger.error(f"[{self.execution_id}] Failed to auto-destroy droplet {droplet['name']}: {cleanup_error}")
        
        return results
    
    def _execute_on_single_droplet(
        self,
        droplet: Dict,
        users: List[Dict],
        parallel_users: int = 1
    ) -> List[Dict]:
        """
        Execute automation for a batch of users on a single droplet using Remote Parallelism.
        Uploads users.json and runs one script that handles threading internally.
        """
        results = []
        ip_address = droplet['ip_address']
        
        logger.info(f"[{self.execution_id}] Starting Bulk Execution on {droplet['name']} ({ip_address}) for {len(users)} users with {parallel_users} workers")
        
        # 1. Start Bulk Automation
        try:
           start_res = self.service.run_bulk_automation(
               ip_address=ip_address,
               users=users,
               max_workers=parallel_users, # Pass directly as max_workers
               ssh_key_path=self._get_ssh_key_path(),
               twocaptcha_config=self.twocaptcha_config
           )
           
           if not start_res.get('success'):
               logger.error(f"[{self.execution_id}] Failed to start bulk on {droplet['name']}: {start_res.get('error')}")
               return [{'email': u['email'], 'success': False, 'error': f"Start failed: {start_res.get('error')}"} for u in users]
               
           # Give the remote process 3 seconds to actually register in pgrep/system
           time.sleep(3)
           
           log_file = start_res['log_file']
           result_file = start_res['result_file']
           
        except Exception as e:
            logger.error(f"[{self.execution_id}] Exception starting bulk on {droplet['name']}: {e}")
            return [{'email': u['email'], 'success': False, 'error': str(e)} for u in users]

        # 2. Poll for completion and stream results
        cursor = 0
        timeout = 3600 * 24 # 24 hours (long timeout for bulk)
        start_time = time.time()
        
        # Track processed emails to ensure we don't miss any or duplicate
        processed_emails = set()
        
        # Local log file for UI streaming
        local_log_dir = os.path.join('logs', 'bulk_executions', self.execution_id)
        os.makedirs(local_log_dir, exist_ok=True)
        local_log_file = os.path.join(local_log_dir, f"{droplet['id']}.log")

        while (time.time() - start_time) < timeout:
            try:
                # Check status (pass email=None for bulk mode)
                status_res = self.service.check_automation_status(
                    ip_address=ip_address,
                    log_file=log_file,
                    result_file=result_file,
                    ssh_key_path=self._get_ssh_key_path(),
                    cursor=cursor,
                    email=None
                )
                
                # Update cursor
                if 'next_cursor' in status_res:
                    cursor = status_res['next_cursor']
                    
                # Parse logs for JSON results
                new_logs = status_res.get('logs', '')
                if new_logs:
                    # SYNC TO LOCAL LOG FILE (for UI)
                    with open(local_log_file, 'a', encoding='utf-8') as f:
                        f.write(new_logs)

                    # Find all <JSON_RESULT>...</JSON_RESULT> blocks
                    json_matches = re.findall(r'<JSON_RESULT>(.*?)</JSON_RESULT>', new_logs, re.DOTALL)
                    for json_str in json_matches:
                        try:
                           res = json.loads(json_str)
                           email = res.get('email')
                           
                           # Only add if not already processed (deduplication)
                           # Although logs should be sequential, network retries might cause duplicates?
                           # Actually, incremental logs shouldn't have duplicates.
                           # But simpler to just append.
                           results.append(res)
                           processed_emails.add(email)
                           
                           logger.info(f"[{self.execution_id}] ✓ Result received for {email}: {'Success' if res.get('success') else 'Failed'}")
                           
                           # Optional: Update DB real-time?
                           # For now, we collect all and return.
                           
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to decode JSON result tag: {json_str[:50]}...")

                status = status_res.get('status')
                
                if status == 'completed':
                    logger.info(f"[{self.execution_id}] Bulk execution completed on {droplet['name']}")
                    
                    # Merge with final result file if exists (for safety)
                    final_data = status_res.get('result')
                    if isinstance(final_data, list):
                        # Use final data as source of truth if available?
                        # Or just rely on stream.
                        # Streaming is better for real-time, but final file matches Phase 2 retries.
                        # Remote script saves ALL results to file at end.
                        # So we can just use final_data if available.
                        pass
                    
                    break
                    
                elif status == 'error':
                    # False Positive Protection:
                    # If process is dead but we haven't even seen a single log line yet,
                    # and it's within the first 30 seconds, maybe it's just slow to start?
                    # BUT we already added a sleep(3).
                    # Let's check if we have ANY results or logs.
                    if (time.time() - start_time) < 30 and cursor == 0:
                        logger.warning(f"[{self.execution_id}] Droplet {droplet['name']} report 'error' but no logs yet. Retrying...")
                        time.sleep(5)
                        continue

                    error = status_res.get('error', 'Unknown error')
                    logger.error(f"[{self.execution_id}] Bulk execution crashed on {droplet['name']}: {error}")
                    # Fill missing users with error
                    for u in users:
                        if u['email'] not in processed_emails:
                            results.append({'email': u['email'], 'success': False, 'error': f"Process crashed: {error}"})
                    break
                
                # Sleep with jitter
                time.sleep(random.uniform(5.0, 10.0))
                
            except Exception as e:
                logger.error(f"[{self.execution_id}] Error monitoring droplet {droplet['name']}: {e}")
                time.sleep(10)
        
        return results

    def _execute_single_user_automation(self, droplet: Dict, user: Dict) -> Dict:
        """Helper to execute automation for a single user (DEPRECATED - Kept for legacy if needed)"""

    def _execute_single_user_automation(self, droplet: Dict, user: Dict) -> Dict:
        """Helper to execute automation for a single user (called in parallel)"""
        email = user.get('email')
        password = user.get('password')
        ip_address = droplet['ip_address']
        
        if not email or not password:
            return {
                'success': False,
                'email': email or 'unknown',
                'error': 'Missing email or password',
                'droplet_id': droplet['id']
            }
        
        # Define log callback with history preservation and user-specific prefixing
        def log_callback(logs, append=False):
            try:
                log_dir = os.path.join('logs', 'bulk_executions', self.execution_id)
                os.makedirs(log_dir, exist_ok=True)
                log_file = os.path.join(log_dir, f"{droplet['id']}.log")
                
                # Prefix logs with email
                prefixed_logs = ""
                # Handle both string and list inputs
                log_lines = logs.splitlines() if isinstance(logs, str) else logs
                     
                for line in log_lines:
                    # Avoid double prefixing
                    prefix = f"[{email}] "
                    prefixed_logs += (line if prefix in line else f"{prefix}{line}") + "\n"
                
                # Since we are now fetching logs incrementally from the droplet, 
                # we simply append the new chunk to the local file.
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(prefixed_logs)
            except Exception as le:
                logger.error(f"Log callback error for {email}: {le}")

        # Fetch existing secret key if available
        secret_key = None
        # Need to import strictly inside method or at top? using inline to be safe
        from database import AwsGeneratedPassword
        
        try:
            # Ensure we have an app context
            if not self.app:
                # Fallback: Try to import app if not set
                try:
                    from app import app
                    self.app = app
                except ImportError:
                    logger.warning(f"[{self.execution_id}] Could not import 'app' for context.")
            
            if self.app:
                with self.app.app_context():
                    existing_creds = AwsGeneratedPassword.query.filter_by(email=email).first()
                    if existing_creds and existing_creds.secret_key:
                        secret_key = existing_creds.secret_key
                        # logger.info(f"[{self.execution_id}] Found existing secret key for {email}")
            else:
                 logger.warning(f"[{self.execution_id}] No app context - skipping secret key lookup for {email}")

        except Exception as db_e:
            logger.error(f"[{self.execution_id}] DB Lookup failed for {email}: {db_e}")

        # Execute automation via reusable service method (Async Polling version for robustness)
        # We renamed the async wrapper to run_automation_script_async_poll to distinguish it
        result_data = self.service.run_automation_script_async_poll(
            ip_address=ip_address,
            email=email,
            password=password,
            ssh_key_path=self.config.get('ssh_private_key_path'),
            log_callback=log_callback,
            secret_key=secret_key,
            twocaptcha_config=getattr(self, 'twocaptcha_config', None)
        )
        
        # Normalize result (ensure 'success' key exists for easier checking)
        if 'success' not in result_data:
            result_data['success'] = result_data.get('status') == 'success'
        
        # Add metadata
        result_data['email'] = email
        result_data['droplet_id'] = droplet['id']
        
        # Save app password and secret key if successful
        if result_data.get('success'):
             # Explicitly capture secret_key from result if present
             returned_secret = result_data.get('secret_key')
             returned_app_pass = result_data.get('app_password')
             
             if returned_app_pass:
                self._save_app_password_with_backup(email, returned_app_pass, returned_secret)
            
        return result_data

    def _save_app_password_with_backup(self, email: str, app_password: str, secret_key: str = None):
        """
        Dual-save system: Save app password to both database AND backup file.
        This ensures no data loss even if server crashes or database fails.
        
        Args:
            email: User email
            app_password: Generated app password
        """
        from database import db, AwsGeneratedPassword
        
        # 1. IMMEDIATE BACKUP TO FILE (fastest, most reliable)
        backup_success = False
        try:
            # Use ABSOLUTE path relative to CWD (app root)
            backup_dir = os.path.join(os.getcwd(), 'do_app_passwords_backup')
            os.makedirs(backup_dir, exist_ok=True)
            
            # Create backup file with timestamp
            backup_file = os.path.join(
                backup_dir, 
                f"{self.execution_id}_{email.replace('@', '_at_')}.json"
            )
            
            backup_data = {
                'email': email,
                'app_password': app_password,
                'secret_key': secret_key,
                'execution_id': self.execution_id,
                'timestamp': datetime.utcnow().isoformat(),
                'saved_to_db': False  # Will update after DB save
            }
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            backup_success = True
            logger.info(f"[{self.execution_id}] ✓ Backup file saved: {email}")
        except Exception as backup_error:
            logger.error(f"[{self.execution_id}] ✗ Backup file failed for {email}: {backup_error}")
        
        # 2. SAVE TO DATABASE (with retry logic)
        db_success = False
        max_retries = 3
        
        # Use app context if available (critical for threads)
        context_manager = self.app.app_context() if self.app else None
        
        try:
            if context_manager:
                context_manager.push()
                
            for attempt in range(max_retries):
                try:
                    # Check if already exists
                    existing = AwsGeneratedPassword.query.filter_by(email=email).first()
                    if existing:
                        existing.app_password = app_password
                        # Only update secret key if new one provided
                        if secret_key:
                            existing.secret_key = secret_key
                    else:
                        new_password = AwsGeneratedPassword()
                        new_password.email = email
                        new_password.app_password = app_password
                        new_password.secret_key = secret_key
                        db.session.add(new_password)
                    
                    # Immediate commit (don't batch)
                    db.session.commit()
                    db_success = True
                    logger.info(f"[{self.execution_id}] ✓ Database saved: {email}")
                    break
                    
                except Exception as db_error:
                    db.session.rollback()
                    logger.warning(f"[{self.execution_id}] Database save attempt {attempt+1}/{max_retries} failed for {email}: {db_error}")
                    
                    if attempt < max_retries - 1:
                        time.sleep(0.5)  # Brief pause before retry
                    else:
                        logger.error(f"[{self.execution_id}] ✗ Database save FAILED after {max_retries} attempts: {email}")
        finally:
            if context_manager:
                context_manager.pop()
        
        # 3. UPDATE BACKUP FILE STATUS
        if backup_success:
            try:
                with open(backup_file, 'r') as f:
                    backup_data = json.load(f)
                backup_data['saved_to_db'] = db_success
                backup_data['db_save_timestamp'] = datetime.utcnow().isoformat() if db_success else None
                
                with open(backup_file, 'w') as f:
                    json.dump(backup_data, f, indent=2)
            except:
                pass  # Non-critical
        
        # 4. LOG FINAL STATUS
        if db_success and backup_success:
            logger.info(f"[{self.execution_id}] ✓✓ DUAL-SAVE SUCCESS: {email}")
        elif db_success:
            logger.warning(f"[{self.execution_id}] ⚠ DB saved but backup failed: {email}")
        elif backup_success:
            logger.warning(f"[{self.execution_id}] ⚠ Backup saved but DB failed: {email} (can recover later)")
        else:
            logger.error(f"[{self.execution_id}] ✗✗ BOTH SAVES FAILED: {email}")
    
    def _destroy_droplets_parallel(self, droplets: List[Dict]):
        """Destroy multiple droplets in parallel"""
        logger.info(f"[{self.execution_id}] Destroying {len(droplets)} droplets")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            for droplet in droplets:
                future = executor.submit(self.service.delete_droplet, droplet['id'])
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"[{self.execution_id}] Error destroying droplet: {e}")
        
        logger.info(f"[{self.execution_id}] Droplet destruction complete")
