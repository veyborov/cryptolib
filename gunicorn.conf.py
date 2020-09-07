from __future__ import print_function
import json
import multiprocessing
import os

workers_per_core_str = os.getenv("WORKERS_PER_CORE", "1")
web_concurrency_str = os.getenv("WEB_CONCURRENCY", None)
use_loglevel = os.getenv("LOG_LEVEL", "info")

cores = multiprocessing.cpu_count()
workers_per_core = float(workers_per_core_str)
default_web_concurrency = workers_per_core * cores
if web_concurrency_str:
    web_concurrency = int(web_concurrency_str)
    assert web_concurrency > 0
else:
    web_concurrency = int(default_web_concurrency)

# Gunicorn config variables
loglevel = use_loglevel
workers = web_concurrency
bind = '0.0.0.0:3010'
keepalive = 120
errorlog = "-"
accesslog = "-"

try:
    with open('versions.json', 'r') as f:
        loaded_json = json.load(f)
        print('VERSIONS: ', json.dumps(loaded_json))
except:
    print('VERSIONS: Error while parsing versions.json')

# For debugging and testing
log_data = {
    "loglevel": loglevel,
    "workers": workers,
    "bind": bind,
    # Additional, non-gunicorn variables
    "workers_per_core": workers_per_core,
}
print('CONFIG: ', json.dumps(log_data))

