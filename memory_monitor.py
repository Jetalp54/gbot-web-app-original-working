#!/usr/bin/env python3
"""
Memory monitoring script for GBot Web App
Automatically restarts the service if memory usage gets too high
"""

import psutil
import subprocess
import time
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/gbot-web-app/logs/memory_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_memory_usage():
    """Get current memory usage of the application"""
    try:
        total_memory = psutil.virtual_memory().total / (1024**3)  # GB
        available_memory = psutil.virtual_memory().available / (1024**3)  # GB
        used_memory = total_memory - available_memory
        memory_percent = psutil.virtual_memory().percent
        
        # Get Gunicorn process memory
        gunicorn_memory = 0
        gunicorn_processes = 0
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                if 'gunicorn' in proc.info['name'] or 'python' in proc.info['name']:
                    if 'app:app' in ' '.join(proc.cmdline()):
                        memory_mb = proc.info['memory_info'].rss / (1024**2)
                        gunicorn_memory += memory_mb
                        gunicorn_processes += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return {
            'total_gb': total_memory,
            'used_gb': used_memory,
            'available_gb': available_memory,
            'percent': memory_percent,
            'gunicorn_memory_mb': gunicorn_memory,
            'gunicorn_processes': gunicorn_processes
        }
    except Exception as e:
        logger.error(f"Error getting memory usage: {e}")
        return None

def restart_gbot_service():
    """Restart the GBot service"""
    try:
        logger.warning("🔄 Restarting GBot service due to high memory usage...")
        
        # Stop service
        result = subprocess.run(['systemctl', 'stop', 'gbot'], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logger.error(f"Failed to stop service: {result.stderr}")
            return False
        
        # Wait a moment
        time.sleep(5)
        
        # Start service
        result = subprocess.run(['systemctl', 'start', 'gbot'], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logger.error(f"Failed to start service: {result.stderr}")
            return False
        
        logger.info("✅ GBot service restarted successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error restarting service: {e}")
        return False

def check_service_status():
    """Check if the service is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'gbot'], 
                              capture_output=True, text=True, timeout=10)
        return result.stdout.strip() == 'active'
    except Exception as e:
        logger.error(f"Error checking service status: {e}")
        return False

def main():
    """Main monitoring loop"""
    logger.info("🚀 Starting memory monitoring for GBot Web App")
    logger.info("📊 Server specs: 4 vCPU, 16GB RAM")
    
    # Memory thresholds
    MEMORY_WARNING_PERCENT = 80  # Warning at 80%
    MEMORY_CRITICAL_PERCENT = 90  # Critical at 90%
    GUNICORN_MEMORY_LIMIT_MB = 8000  # 8GB limit for Gunicorn processes
    
    consecutive_high_memory = 0
    last_restart = 0
    
    while True:
        try:
            # Check if service is running
            if not check_service_status():
                logger.warning("⚠️ GBot service is not running, attempting to start...")
                restart_gbot_service()
                time.sleep(30)
                continue
            
            # Get memory usage
            memory_info = get_memory_usage()
            if not memory_info:
                time.sleep(30)
                continue
            
            # Log current status
            logger.info(f"💾 Memory: {memory_info['percent']:.1f}% used "
                       f"({memory_info['used_gb']:.1f}GB/{memory_info['total_gb']:.1f}GB) | "
                       f"Gunicorn: {memory_info['gunicorn_memory_mb']:.0f}MB "
                       f"({memory_info['gunicorn_processes']} processes)")
            
            # Check memory thresholds
            current_time = time.time()
            
            if memory_info['percent'] >= MEMORY_CRITICAL_PERCENT:
                consecutive_high_memory += 1
                logger.warning(f"🚨 CRITICAL: Memory usage {memory_info['percent']:.1f}% "
                             f"(consecutive: {consecutive_high_memory})")
                
                # Restart if critical for 3 consecutive checks or if Gunicorn using too much
                if (consecutive_high_memory >= 3 or 
                    memory_info['gunicorn_memory_mb'] > GUNICORN_MEMORY_LIMIT_MB):
                    
                    # Don't restart more than once every 5 minutes
                    if current_time - last_restart > 300:
                        if restart_gbot_service():
                            last_restart = current_time
                            consecutive_high_memory = 0
                        time.sleep(60)  # Wait longer after restart
                    else:
                        logger.warning("⏰ Skipping restart - too recent")
                        
            elif memory_info['percent'] >= MEMORY_WARNING_PERCENT:
                consecutive_high_memory += 1
                logger.warning(f"⚠️ WARNING: Memory usage {memory_info['percent']:.1f}% "
                             f"(consecutive: {consecutive_high_memory})")
            else:
                consecutive_high_memory = 0
            
            # Check Gunicorn memory specifically
            if memory_info['gunicorn_memory_mb'] > GUNICORN_MEMORY_LIMIT_MB:
                logger.warning(f"🚨 Gunicorn memory limit exceeded: "
                             f"{memory_info['gunicorn_memory_mb']:.0f}MB > {GUNICORN_MEMORY_LIMIT_MB}MB")
                
                if current_time - last_restart > 300:  # 5 minutes
                    if restart_gbot_service():
                        last_restart = current_time
                        consecutive_high_memory = 0
                    time.sleep(60)
            
            # Sleep before next check
            time.sleep(30)  # Check every 30 seconds
            
        except KeyboardInterrupt:
            logger.info("🛑 Memory monitoring stopped by user")
            break
        except Exception as e:
            logger.error(f"❌ Error in monitoring loop: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
