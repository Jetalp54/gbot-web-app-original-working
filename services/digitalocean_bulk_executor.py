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
        self.app = app
        self.execution_id = None
        self.droplets_created = []
        self.results = []
        
    def execute_bulk(
        self,
        users: List[Dict],
        droplet_count: int,
        snapshot_id: str,
        region: str,
        size: str,
        auto_destroy: bool = True,
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
            execution_id: Optional existing execution ID to use
            
        Returns:
            Dict with execution results
        """
        exec_start = datetime.utcnow()
        self.execution_id = execution_id or f"exec_{int(time.time())}"
        
        logger.info(f"[{self.execution_id}] Starting bulk execution: {len(users)} users, {droplet_count} droplets")
        
        try:
            # 1. Distribute users
            user_batches = DigitalOceanService.distribute_users(users, droplet_count)
            logger.info(f"[{self.execution_id}] Distributed users into {len(user_batches)} batches")
            
            # 2. Create droplets
            droplet_info, creation_errors = self._create_droplets_parallel(
                count=len(user_batches),
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
            
            # 3. Execute automation on each droplet
            results = self._execute_on_droplets_parallel(droplet_info, user_batches)
            
            # 4. Optionally destroy droplets
            if auto_destroy:
                self._destroy_droplets_parallel(droplet_info)
            
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
            logger.error(f"[{self.execution_id}] Bulk execution failed: {e}")
            # Clean up any created droplets
            if self.droplets_created and auto_destroy:
                self._destroy_droplets_parallel(self.droplets_created)
            
            return {
                'success': False,
                'error': str(e),
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
        user_batches: List[List[Dict]]
    ) -> List[Dict]:
        """Execute automation on multiple droplets in parallel"""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=len(droplets)) as executor:
            futures = {}
            
            for droplet, users in zip(droplets, user_batches):
                future = executor.submit(
                    self._execute_on_single_droplet,
                    droplet, users
                )
                futures[future] = droplet
            
            for future in as_completed(futures):
                droplet = futures[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    logger.info(f"[{self.execution_id}] Completed execution on {droplet['name']}")
                except Exception as e:
                    logger.error(f"[{self.execution_id}] Execution failed on {droplet['name']}: {e}")
        
        return all_results
    
    def _execute_on_single_droplet(
        self,
        droplet: Dict,
        users: List[Dict]
    ) -> List[Dict]:
        """Execute automation for a batch of users on a single droplet"""
        results = []
        ip_address = droplet['ip_address']
        
        logger.info(f"[{self.execution_id}] Processing {len(users)} users on {droplet['name']} ({ip_address})")
        
        # Pre-initialize log directory and file so UI doesn't show "File not found"
        try:
            log_dir = os.path.join('logs', 'bulk_executions', self.execution_id)
            os.makedirs(log_dir, exist_ok=True)
            log_file_path = os.path.join(log_dir, f"{droplet['id']}.log")
            if not os.path.exists(log_file_path):
                with open(log_file_path, 'w', encoding='utf-8') as f:
                    f.write(f"[{datetime.utcnow().isoformat()}] Initializing connection to droplet {droplet['name']}...\n")
        except Exception as init_le:
            logger.error(f"Failed to pre-initialize log file: {init_le}")

        try:
            # For each user, run the automation script
            for user in users:
                email = user.get('email')
                password = user.get('password')
                
                if not email or not password:
                    results.append({
                        'success': False,
                        'email': email or 'unknown',
                        'error': 'Missing email or password',
                        'droplet_id': droplet['id']
                    })
                    continue
                
                # Define log callback
                def log_callback(logs):
                    try:
                        log_dir = os.path.join('logs', 'bulk_executions', self.execution_id)
                        os.makedirs(log_dir, exist_ok=True)
                        log_file = os.path.join(log_dir, f"{droplet['id']}.log")
                        
                        # OVERWRITE logs because DigitalOceanService returns the full 'cat' history
                        with open(log_file, 'w', encoding='utf-8') as f:
                             f.write(logs)
                    except Exception as le:
                        logger.error(f"Log callback error: {le}")

                # Execute automation via reusable service method
                result_data = self.service.run_automation_script(
                    ip_address=ip_address,
                    email=email,
                    password=password,
                    ssh_key_path=self.config.get('ssh_private_key_path'),
                    log_callback=log_callback
                )
                
                if not result_data.get('success'):
                    results.append({
                        'success': False,
                        'email': email,
                        'error': result_data.get('error', 'Unknown error'),
                        'droplet_id': droplet['id']
                    })
                    continue
                
                # Success - process result
                app_password = result_data.get('app_password')
                
                # Save app password with dual-save backup system
                # Save app password with dual-save backup system
                if app_password:
                    self._save_app_password_with_backup(
                        email=email,
                        app_password=app_password
                    )

                results.append({
                    'success': True,
                    'email': email,
                    'app_password': app_password,
                    'droplet_id': droplet['id'],
                    'timestamp': datetime.utcnow().isoformat()
                })
                
        except Exception as e:
            logger.error(f"[{self.execution_id}] Error executing on droplet {droplet['name']}: {e}")
            # Add failure results for remaining users
            for user in users:
                results.append({
                    'success': False,
                    'email': user.get('email', 'unknown'),
                    'error': f'Droplet execution error: {str(e)}',
                    'droplet_id': droplet['id']
                })
        
        return results
    
    def _save_app_password_with_backup(self, email: str, app_password: str):
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
            backup_dir = 'do_app_passwords_backup'
            os.makedirs(backup_dir, exist_ok=True)
            
            # Create backup file with timestamp
            backup_file = os.path.join(
                backup_dir, 
                f"{self.execution_id}_{email.replace('@', '_at_')}.json"
            )
            
            backup_data = {
                'email': email,
                'app_password': app_password,
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
        
        for attempt in range(max_retries):
            try:
                # Check if already exists
                existing = AwsGeneratedPassword.query.filter_by(email=email).first()
                if existing:
                    existing.app_password = app_password
                else:
                    new_password = AwsGeneratedPassword()
                    new_password.email = email
                    new_password.app_password = app_password
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
