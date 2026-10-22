"""gunicorn entry point: gunicorn netportal.wsgi:app (one worker, threads: the metrics counters
live in the process)."""

import logging

from . import config, registry, web

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
settings = config.load()
with registry.connect(settings.database_url) as _db:
    registry.init(_db, settings.policies)
app = web.create_app(settings)
