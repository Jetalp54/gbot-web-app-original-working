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
from typing import List, Dict, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from database import db, DigitalOceanDroplet, DigitalOceanExecution, AwsGeneratedPassword
from services.digitalocean_service import DigitalOceanService

logger = logging.getLogger(__name__)


class BulkExecutionOrchestrator:
    """Orchestrates bulk execution across multiple DigitalOcean droplets"""
    
    def __init__(self, config: Dict, service: DigitalOceanService):
        """
        Initialize orchestrator.
        
        Args:
            config: DigitalOcean configuration dict
            service: DigitalOceanService instance
        """
        self.config = config
        self.service = service
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
            droplet_info = self._create_droplets_parallel(
                count=len(user_batches),
                snapshot_id=snapshot_id,
                region=region,
                size=size
            )
            
            if not droplet_info:
                return {
                    'success': False,
                    'error': 'Failed to create droplets',
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
    ) -> List[Dict]:
        """Create multiple droplets in parallel"""
        droplets = []
        
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
                except Exception as e:
                    logger.error(f"[{self.execution_id}] Droplet creation failed: {e}")
        
        return droplets
    
    def _create_and_wait_for_droplet(
        self,
        name: str,
        snapshot_id: str,
        region: str,
        size: str
    ) -> Optional[Dict]:
        """Create a droplet and wait for it to be active"""
        try:
            # Create droplet
            result, error_msg = self.service.create_droplet(
                name=name,
                region=region,
                size=size,
                image=snapshot_id,
                tags=['bulk-execution', self.execution_id]
            )
            
            if not result:
                logger.error(f"[{self.execution_id}] Failed to create droplet {name}: {error_msg}")
                return None
            
            droplet_id = result['id']
            
            # Wait for active status and IP
            ip_address = self.service.wait_for_droplet_active(droplet_id, timeout=300)
            
            if not ip_address:
                logger.error(f"[{self.execution_id}] Droplet {droplet_id} did not become active")
                return None
            
            # Wait additional time for SSH to be ready
            time.sleep(30)
            
            return {
                'id': droplet_id,
                'name': name,
                'ip_address': ip_address,
                'region': region,
                'size': size
            }
            
        except Exception as e:
            logger.error(f"[{self.execution_id}] Error creating droplet {name}: {e}")
            return None
    
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
                
                # Execute automation via reusable service method
                result_data = self.service.run_automation_script(
                    ip_address=ip_address,
                    email=email,
                    password=password,
                    ssh_key_path=self.config.get('ssh_private_key_path')
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
