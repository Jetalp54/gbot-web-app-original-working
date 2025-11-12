#!/usr/bin/env python3
"""
Resource usage checker for GBot Web App
Checks if the app is using the full server capacity (4 vCPU, 16GB RAM)
"""

import psutil
import subprocess
import time
import json
from datetime import datetime

def check_gunicorn_processes():
    """Check Gunicorn worker processes and their resource usage"""
    gunicorn_processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'cmdline']):
        try:
            if 'gunicorn' in proc.info['name'] and 'app:app' in ' '.join(proc.info['cmdline']):
                gunicorn_processes.append({
                    'pid': proc.info['pid'],
                    'cpu_percent': proc.cpu_percent(),
                    'memory_mb': proc.info['memory_info'].rss / (1024 * 1024),
                    'cmdline': ' '.join(proc.info['cmdline'])
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return gunicorn_processes

def check_system_resources():
    """Check overall system resource usage"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        'cpu_percent': cpu_percent,
        'memory_total_gb': memory.total / (1024**3),
        'memory_used_gb': memory.used / (1024**3),
        'memory_percent': memory.percent,
        'disk_total_gb': disk.total / (1024**3),
        'disk_used_gb': disk.used / (1024**3),
        'disk_percent': (disk.used / disk.total) * 100
    }

def check_database_connections():
    """Check PostgreSQL connection count"""
    try:
        result = subprocess.run([
            'psql', '-U', 'gbot_user', '-d', 'gbot_db', '-c', 
            "SELECT count(*) FROM pg_stat_activity WHERE datname='gbot_db';"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip().isdigit():
                    return int(line.strip())
    except Exception as e:
        print(f"Error checking database connections: {e}")
    
    return 0

def check_nginx_connections():
    """Check Nginx active connections"""
    try:
        result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            nginx_connections = 0
            for line in lines:
                if ':80' in line and 'ESTAB' in line:
                    nginx_connections += 1
            return nginx_connections
    except Exception as e:
        print(f"Error checking nginx connections: {e}")
    
    return 0

def main():
    """Main resource check"""
    print("🔍 GBot Web App Resource Usage Check")
    print("=" * 50)
    print(f"Timestamp: {datetime.now()}")
    print()
    
    # Check Gunicorn processes
    print("📊 Gunicorn Workers:")
    gunicorn_procs = check_gunicorn_processes()
    if gunicorn_procs:
        total_cpu = 0
        total_memory = 0
        for i, proc in enumerate(gunicorn_procs, 1):
            print(f"  Worker {i}: PID {proc['pid']}, CPU: {proc['cpu_percent']:.1f}%, Memory: {proc['memory_mb']:.1f}MB")
            total_cpu += proc['cpu_percent']
            total_memory += proc['memory_mb']
        
        print(f"  Total Workers: {len(gunicorn_procs)}")
        print(f"  Total CPU Usage: {total_cpu:.1f}%")
        print(f"  Total Memory Usage: {total_memory:.1f}MB")
    else:
        print("  ❌ No Gunicorn workers found!")
    
    print()
    
    # Check system resources
    print("🖥️  System Resources:")
    system = check_system_resources()
    print(f"  CPU Usage: {system['cpu_percent']:.1f}%")
    print(f"  Memory: {system['memory_used_gb']:.1f}GB / {system['memory_total_gb']:.1f}GB ({system['memory_percent']:.1f}%)")
    print(f"  Disk: {system['disk_used_gb']:.1f}GB / {system['disk_total_gb']:.1f}GB ({system['disk_percent']:.1f}%)")
    
    print()
    
    # Check database connections
    print("🗄️  Database:")
    db_connections = check_database_connections()
    print(f"  Active Connections: {db_connections}")
    
    print()
    
    # Check nginx connections
    print("🌐 Nginx:")
    nginx_connections = check_nginx_connections()
    print(f"  Active Connections: {nginx_connections}")
    
    print()
    
    # Analysis
    print("📈 Analysis:")
    
    # CPU Analysis
    if system['cpu_percent'] > 80:
        print("  ✅ CPU: High usage - Good utilization")
    elif system['cpu_percent'] > 50:
        print("  ⚠️  CPU: Moderate usage - Could be higher")
    else:
        print("  ❌ CPU: Low usage - Not utilizing full capacity")
    
    # Memory Analysis
    if system['memory_percent'] > 70:
        print("  ✅ Memory: High usage - Good utilization")
    elif system['memory_percent'] > 40:
        print("  ⚠️  Memory: Moderate usage - Could be higher")
    else:
        print("  ❌ Memory: Low usage - Not utilizing full capacity")
    
    # Worker Analysis
    if len(gunicorn_procs) >= 8:
        print("  ✅ Workers: Good number of workers")
    elif len(gunicorn_procs) >= 4:
        print("  ⚠️  Workers: Moderate number - Could add more")
    else:
        print("  ❌ Workers: Too few workers - Not utilizing CPU cores")
    
    # Database Analysis
    if db_connections > 50:
        print("  ✅ Database: High connection usage - Good")
    elif db_connections > 20:
        print("  ⚠️  Database: Moderate connections - Could be higher")
    else:
        print("  ❌ Database: Low connections - Not utilizing pool")
    
    print()
    print("💡 Recommendations:")
    
    if system['cpu_percent'] < 50:
        print("  - Increase Gunicorn workers (currently 12, try 16)")
        print("  - Add more concurrent operations")
    
    if system['memory_percent'] < 40:
        print("  - Increase database connection pool")
        print("  - Add caching layers")
        print("  - Process more data in memory")
    
    if len(gunicorn_procs) < 8:
        print("  - Restart Gunicorn with more workers")
        print("  - Check if workers are crashing")
    
    if db_connections < 20:
        print("  - Increase database pool_size and max_overflow")
        print("  - Add more concurrent database operations")

if __name__ == "__main__":
    main()
