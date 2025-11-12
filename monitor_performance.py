#!/usr/bin/env python3
"""
Performance monitoring script for GBot Web App
Monitors database connections, memory usage, and response times
"""

import psutil
import time
import requests
import json
import logging
from datetime import datetime
import subprocess
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_database_connections():
    """Check PostgreSQL connection count"""
    try:
        result = subprocess.run(['psql', '-U', 'gbot_user', '-d', 'gbot_db', '-c', 
                               "SELECT count(*) FROM pg_stat_activity WHERE datname='gbot_db';"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip().isdigit():
                    return int(line.strip())
    except Exception as e:
        logger.error(f"Error checking database connections: {e}")
    return 0

def check_memory_usage():
    """Check memory usage of the application"""
    try:
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            if 'gunicorn' in proc.info['name'] or 'python' in proc.info['name']:
                memory_mb = proc.info['memory_info'].rss / 1024 / 1024
                if memory_mb > 100:  # Only log processes using >100MB
                    logger.info(f"Process {proc.info['pid']} ({proc.info['name']}): {memory_mb:.1f}MB")
    except Exception as e:
        logger.error(f"Error checking memory usage: {e}")

def check_response_time():
    """Check response time of the application"""
    try:
        start_time = time.time()
        response = requests.get('http://127.0.0.1:5000/health', timeout=10)
        end_time = time.time()
        
        response_time = (end_time - start_time) * 1000  # Convert to milliseconds
        status = response.status_code
        
        logger.info(f"Health check: {status} - {response_time:.1f}ms")
        
        if response_time > 1000:  # Alert if response time > 1 second
            logger.warning(f"SLOW RESPONSE: {response_time:.1f}ms")
            
        return response_time, status
    except Exception as e:
        logger.error(f"Error checking response time: {e}")
        return None, None

def check_nginx_status():
    """Check Nginx status and active connections"""
    try:
        result = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("Nginx configuration is valid")
        else:
            logger.error(f"Nginx configuration error: {result.stderr}")
    except Exception as e:
        logger.error(f"Error checking Nginx: {e}")

def check_disk_space():
    """Check available disk space"""
    try:
        disk_usage = psutil.disk_usage('/')
        free_gb = disk_usage.free / (1024**3)
        total_gb = disk_usage.total / (1024**3)
        used_percent = (disk_usage.used / disk_usage.total) * 100
        
        logger.info(f"Disk usage: {used_percent:.1f}% ({free_gb:.1f}GB free of {total_gb:.1f}GB)")
        
        if used_percent > 90:
            logger.warning(f"HIGH DISK USAGE: {used_percent:.1f}%")
            
    except Exception as e:
        logger.error(f"Error checking disk space: {e}")

def check_cpu_usage():
    """Check CPU usage"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        logger.info(f"CPU usage: {cpu_percent:.1f}%")
        
        if cpu_percent > 80:
            logger.warning(f"HIGH CPU USAGE: {cpu_percent:.1f}%")
            
    except Exception as e:
        logger.error(f"Error checking CPU usage: {e}")

def main():
    """Main monitoring loop"""
    logger.info("Starting performance monitoring...")
    
    while True:
        try:
            logger.info("=" * 50)
            logger.info(f"Performance check at {datetime.now()}")
            
            # Check various metrics
            db_connections = check_database_connections()
            logger.info(f"Database connections: {db_connections}")
            
            check_memory_usage()
            check_cpu_usage()
            check_disk_space()
            check_nginx_status()
            
            response_time, status = check_response_time()
            
            # Summary
            if response_time and response_time < 500 and db_connections < 50:
                logger.info("✅ System performance: GOOD")
            elif response_time and response_time < 1000 and db_connections < 100:
                logger.info("⚠️ System performance: MODERATE")
            else:
                logger.warning("❌ System performance: POOR - Consider optimization")
            
            # Wait before next check
            time.sleep(30)  # Check every 30 seconds
            
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            time.sleep(30)

if __name__ == "__main__":
    main()
