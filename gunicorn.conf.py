# Gunicorn configuration for high-load production
import multiprocessing
import os

# Server socket - High capacity for unlimited machines
bind = "127.0.0.1:5000"
backlog = 16384  # High backlog for unlimited concurrent machines

# Worker processes - Optimized for unlimited concurrent machines without crashing
workers = 16  # 4x CPU cores - safe for unlimited machines without resource exhaustion
worker_class = "sync"
worker_connections = 5000  # High connections per worker
max_requests = 50000  # Very high before restart
max_requests_jitter = 1000

# Timeouts - Extended for unlimited concurrent machines
timeout = 3600  # 1 hour for very long operations
keepalive = 30  # Keep connections alive much longer
graceful_timeout = 300  # More time for graceful shutdown

# Memory management
preload_app = True

# Logging
accesslog = "logs/gunicorn_access.log"
errorlog = "logs/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'gbot_web_app'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Performance tuning
worker_tmp_dir = "/dev/shm"  # Use shared memory for worker temp files

# Environment variables
raw_env = [
    'FLASK_ENV=production',
    'PYTHONPATH=/opt/gbot-web-app',
]

# Pre-fork optimization
def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")

def pre_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def worker_abort(worker):
    worker.log.info("worker received SIGABRT signal")
