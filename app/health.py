import os
import tempfile

from flask import Blueprint, current_app, jsonify
from sqlalchemy import text

import config
from .models import db


health_blueprint = Blueprint('health', __name__)


def _probe_data_directory():
    descriptor = None
    probe_path = None
    try:
        descriptor, probe_path = tempfile.mkstemp(
            prefix='.webssh-ready-',
            dir=config.DATA_DIR,
        )
        os.write(descriptor, b'ready')
        os.fsync(descriptor)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            if probe_path is not None:
                os.unlink(probe_path)


def _probe_database():
    try:
        db.session.execute(text('SELECT 1'))
    except Exception:
        db.session.rollback()
        raise


@health_blueprint.get('/health')
def health():
    return jsonify({'status': 'ok'})


@health_blueprint.get('/ready')
def ready():
    failed = []
    from .maintenance_mode import is_active
    if is_active():
        failed.append('maintenance')
    lifecycle = current_app.extensions.get('runtime_lifecycle')
    if lifecycle is None or not lifecycle.accepting_work():
        failed.append('runtime')
    for category, probe in (
        ('database', _probe_database),
        ('data_directory', _probe_data_directory),
    ):
        try:
            probe()
        except Exception:
            failed.append(category)

    if failed:
        return jsonify({
            'status': 'not_ready',
            'failed': failed,
        }), 503

    return jsonify({'status': 'ready'})
