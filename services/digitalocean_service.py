"""
DigitalOcean Service for managing droplets, snapshots, and automation execution.
Uses direct API calls via requests to avoid dependency issues.
"""
import os
import time
import json
import logging
import requests
import paramiko
from typing import List, Dict, Optional, Tuple
from io import StringIO

logger = logging.getLogger(__name__)

class DigitalOceanService:
    """Service for managing DigitalOcean droplets and snapshots"""
    
    BASE_URL = "https://api.digitalocean.com/v2"
    
    def __init__(self, api_token: str):
        """
        Initialize DigitalOcean service with API token.
        
        Args:
            api_token: DigitalOcean API token with read/write permissions
        """
        self.api_token = api_token
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        logger.info("DigitalOcean service initialized")
    
    def test_connection(self) -> Tuple[bool, str]:
        """
        Test DigitalOcean API connection.
        
        Returns:
            Tuple of (success, message)
        """
        try:
            # Try to list account info
            response = requests.get(f"{self.BASE_URL}/account", headers=self.headers)
            
            if response.status_code == 200:
                account = response.json()['account']
                return True, f"Connected successfully. Email: {account['email']}"
            else:
                return False, f"Connection failed: {response.text}"
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False, f"Connection failed: {str(e)}"

    def get_account(self) -> Optional[Dict]:
        """
        Get DigitalOcean account information.
        
        Returns:
            Account dictionary or None
        """
        try:
            response = requests.get(f"{self.BASE_URL}/account", headers=self.headers)
            if response.status_code == 200:
                return response.json()['account']
            return None
        except Exception as e:
            logger.error(f"Error getting account info: {e}")
            return None
    
    def list_regions(self) -> List[Dict]:
        """
        List available DigitalOcean regions.
        
        Returns:
            List of region dictionaries with slug, name, availability
        """
        try:
            response = requests.get(f"{self.BASE_URL}/regions", headers=self.headers)
            if response.status_code == 200:
                regions = response.json()['regions']
                # Filter for available regions only
                return [r for r in regions if r['available']]
            return []
        except Exception as e:
            logger.error(f"Error listing regions: {e}")
            return []
    
    def list_sizes(self) -> List[Dict]:
        """
        List available droplet sizes.
        
        Returns:
            List of size dictionaries with slug, memory, vcpus, disk, price
        """
        try:
            response = requests.get(f"{self.BASE_URL}/sizes", params={'per_page': 200}, headers=self.headers)
            if response.status_code == 200:
                sizes = response.json()['sizes']
                # Filter to available sizes only
                available = [s for s in sizes if s.get('available')]
                
                return [{
                    'slug': s['slug'],
                    'memory': s['memory'],
                    'vcpus': s['vcpus'],
                    'disk': s['disk'],
                    'price_monthly': s['price_monthly'],
                    'price_hourly': s['price_hourly'],
                    'description': f"{s['memory']}MB RAM, {s['vcpus']} vCPU, {s['disk']}GB SSD"
                } for s in available]
            return []
        except Exception as e:
            logger.error(f"Error listing sizes: {e}")
            return []
    
    def list_droplets(self) -> List[Dict]:
        """
        List all droplets in the account.
        
        Returns:
            List of droplet dictionaries
        """
        try:
            response = requests.get(f"{self.BASE_URL}/droplets", params={'per_page': 200}, headers=self.headers)
            if response.status_code == 200:
                droplets = response.json()['droplets']
                
                return [{
                    'id': str(d['id']),
                    'name': d['name'],
                    'status': d['status'],
                    'region': d['region']['slug'],
                    'size': d['size']['slug'],
                    'ip_address': next((n['ip_address'] for n in d['networks']['v4'] if n['type'] == 'public'), None),
                    'created_at': d['created_at']
                } for d in droplets]
            return []
        except Exception as e:
            logger.error(f"Error listing droplets: {e}")
            return []
    
    def get_droplet(self, droplet_id: str) -> Optional[Dict]:
        """
        Get droplet details by ID.
        
        Args:
            droplet_id: Droplet ID
            
        Returns:
            Droplet dictionary or None
        """
        try:
            response = requests.get(f"{self.BASE_URL}/droplets/{droplet_id}", headers=self.headers)
            if response.status_code == 200:
                d = response.json()['droplet']
                
                return {
                    'id': str(d['id']),
                    'name': d['name'],
                    'status': d['status'],
                    'region': d['region']['slug'],
                    'size': d['size']['slug'],
                    'ip_address': next((n['ip_address'] for n in d['networks']['v4'] if n['type'] == 'public'), None),
                    'created_at': d['created_at']
                }
            return None
        except Exception as e:
            logger.error(f"Error getting droplet {droplet_id}: {e}")
            return None
    
    def create_droplet(
        self,
        name: str,
        region: str,
        size: str,
        image: str,
        ssh_keys: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        user_data: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Create a new droplet.
        
        Args:
            name: Droplet name
            region: Region slug (e.g., 'nyc3')
            size: Size slug (e.g., 's-1vcpu-1gb')
            image: Image slug or snapshot ID
            ssh_keys: List of SSH key IDs or fingerprints
            tags: List of tags to apply
            user_data: Cloud-init user data script
            
        Returns:
            Droplet dictionary or None
        """
        try:
            req = {
                'name': name,
                'region': region,
                'size': size,
                'image': int(image) if str(image).isdigit() else image,  # Handle snapshot IDs vs slugs
                'ssh_keys': ssh_keys or [],
                'backups': False,
                'ipv6': False,
                'monitoring': False
            }
            
            if tags:
                req['tags'] = tags
            
            if user_data:
                req['user_data'] = user_data
            
            if response.status_code in (200, 201, 202):
                d = response.json()['droplet']
                
                return {
                    'id': str(d['id']),
                    'name': d['name'],
                    'status': d['status'],
                    'region': d['region']['slug'],
                    'size': d['size']['slug'],
                    'ip_address': None,  # Not assigned yet
                    'created_at': d['created_at']
                }
            else:
                logger.error(f"Create droplet failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating droplet: {e}")
            return None
    
    def delete_droplet(self, droplet_id: str) -> bool:
        """
        Delete a droplet.
        
        Args:
            droplet_id: Droplet ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Deleting droplet: {droplet_id}")
            response = requests.delete(f"{self.BASE_URL}/droplets/{droplet_id}", headers=self.headers)
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Error deleting droplet {droplet_id}: {e}")
            return False
    
    def wait_for_droplet_active(self, droplet_id: str, timeout: int = 300) -> Optional[str]:
        """
        Wait for droplet to become active and return its IP address.
        
        Args:
            droplet_id: Droplet ID
            timeout: Maximum time to wait in seconds
            
        Returns:
            IP address or None if timeout
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            droplet = self.get_droplet(droplet_id)
            
            if droplet and droplet['status'] == 'active' and droplet['ip_address']:
                logger.info(f"Droplet {droplet_id} is active with IP {droplet['ip_address']}")
                return droplet['ip_address']
            
            logger.info(f"Waiting for droplet {droplet_id} (status: {droplet['status']})")
            time.sleep(5) # Changed from 10 to 5 as per instruction
        
        logger.error(f"Timeout waiting for droplet {droplet_id}")
        return None
    
    def list_snapshots(self) -> List[Dict]:
        """
        List all snapshots in the account.
        
        Returns:
            List of snapshot dictionaries
        """
        try:
            response = requests.get(f"{self.BASE_URL}/snapshots", params={'resource_type': 'droplet'}, headers=self.headers)
            if response.status_code == 200:
                snapshots = response.json()['snapshots']
                
                return [{
                    'id': s['id'],
                    'name': s['name'],
                    'regions': s['regions'],
                    'size_gigabytes': s['size_gigabytes'],
                    'created_at': s['created_at']
                } for s in snapshots]
            return []
        except Exception as e:
            logger.error(f"Error listing snapshots: {e}")
            return []
    
    def create_snapshot(self, droplet_id: str, snapshot_name: str) -> Optional[Dict]:
        """
        Create a snapshot from a droplet.
        
        Args:
            droplet_id: Droplet ID to snapshot
            snapshot_name: Name for the snapshot
            
        Returns:
            Action dictionary or None
        """
        try:
            logger.info(f"Creating snapshot '{snapshot_name}' from droplet {droplet_id}")
            
            req = {
                'type': 'snapshot',
                'name': snapshot_name
            }
            
            response = requests.post(f"{self.BASE_URL}/droplets/{droplet_id}/actions", json=req, headers=self.headers)
            
            if response.status_code in (200, 201, 202):
                action = response.json()['action']
                return {
                    'action_id': action['id'],
                    'status': action['status'],
                    'type': action['type']
                }
            return None
        except Exception as e:
            logger.error(f"Error creating snapshot: {e}")
            return None
    
    def delete_snapshot(self, snapshot_id: str) -> bool:
        """
        Delete a snapshot.
        
        Args:
            snapshot_id: Snapshot ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Deleting snapshot: {snapshot_id}")
            response = requests.delete(f"{self.BASE_URL}/snapshots/{snapshot_id}", headers=self.headers)
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Error deleting snapshot {snapshot_id}: {e}")
            return False
    
    def execute_ssh_command(
        self,
        ip_address: str,
        command: str,
        username: str = 'root',
        ssh_key_path: Optional[str] = None,
        password: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """
        Execute command on droplet via SSH.
        
        Args:
            ip_address: Droplet IP address
            command: Command to execute
            username: SSH username
            ssh_key_path: Path to SSH private key
            password: SSH password (if not using key)
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with key or password
            if ssh_key_path and os.path.exists(ssh_key_path):
                ssh.connect(ip_address, username=username, key_filename=ssh_key_path)
            elif password:
                ssh.connect(ip_address, username=username, password=password)
            else:
                return False, "", "No SSH key or password provided"
            
            # Execute command
            stdin, stdout, stderr = ssh.exec_command(command)
            
            stdout_text = stdout.read().decode('utf-8')
            stderr_text = stderr.read().decode('utf-8')
            exit_code = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            success = exit_code == 0
            return success, stdout_text, stderr_text
            
        except Exception as e:
            logger.error(f"SSH execution error: {e}")
            return False, "", str(e)
    
    def upload_file_sftp(
        self,
        ip_address: str,
        local_path: str,
        remote_path: str,
        username: str = 'root',
        ssh_key_path: Optional[str] = None,
        password: Optional[str] = None
    ) -> bool:
        """
        Upload file to droplet via SFTP.
        
        Args:
            ip_address: Droplet IP address
            local_path: Local file path
            remote_path: Remote file path
            username: SSH username
            ssh_key_path: Path to SSH private key
            password: SSH password
            
        Returns:
            True if successful, False otherwise
        """
        try:
            transport = paramiko.Transport((ip_address, 22))
            
            if ssh_key_path and os.path.exists(ssh_key_path):
                key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
                transport.connect(username=username, pkey=key)
            elif password:
                transport.connect(username=username, password=password)
            else:
                return False
            
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.put(local_path, remote_path)
            sftp.close()
            transport.close()
            
            logger.info(f"Uploaded {local_path} to {ip_address}:{remote_path}")
            return True
            
        except Exception as e:
            logger.error(f"SFTP upload error: {e}")
            return False
    
    def download_file_sftp(
        self,
        ip_address: str,
        remote_path: str,
        local_path: str,
        username: str = 'root',
        ssh_key_path: Optional[str] = None,
        password: Optional[str] = None
    ) -> bool:
        """
        Download file from droplet via SFTP.
        
        Args:
            ip_address: Droplet IP address
            remote_path: Remote file path
            local_path: Local file path
            username: SSH username
            ssh_key_path: Path to SSH private key
            password: SSH password
            
        Returns:
            True if successful, False otherwise
        """
        try:
            transport = paramiko.Transport((ip_address, 22))
            
            if ssh_key_path and os.path.exists(ssh_key_path):
                key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
                transport.connect(username=username, pkey=key)
            elif password:
                transport.connect(username=username, password=password)
            else:
                return False
            
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.get(remote_path, local_path)
            sftp.close()
            transport.close()
            
            logger.info(f"Downloaded {ip_address}:{remote_path} to {local_path}")
            return True
            
        except Exception as e:
            logger.error(f"SFTP download error: {e}")
            return False
    
    @staticmethod
    def distribute_users(users: List[Dict], droplet_count: int) -> List[List[Dict]]:
        """
        Distribute users evenly across droplets.
        
        Args:
            users: List of user dictionaries
            droplet_count: Number of droplets to distribute across
            
        Returns:
            List of user batches (one per droplet)
        """
        if droplet_count <= 0:
            return []
        
        # Calculate users per droplet (round up)
        total_users = len(users)
        users_per_droplet = (total_users + droplet_count - 1) // droplet_count
        
        # Split users into batches
        batches = []
        for i in range(0, total_users, users_per_droplet):
            batch = users[i:i + users_per_droplet]
            batches.append(batch)
        
        logger.info(f"Distributed {total_users} users across {len(batches)} droplets "
                   f"({users_per_droplet} users per droplet)")
        
        return batches
