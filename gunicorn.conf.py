import multiprocessing
import os

# Gunicorn config
port = int(os.environ.get("PORT", 10000))
bind = f"0.0.0.0:{port}"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 120  # Increase timeout to 120 seconds