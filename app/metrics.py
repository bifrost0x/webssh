"""Prometheus text exposition of process-local runtime capacity.

Only aggregate counts are exported: no usernames, hosts, session IDs, share
tokens, or any other per-user detail ever appears in a label or value.
"""

import hmac
import os
import threading
import time

from flask import Blueprint, Response, abort, current_app, request

import config


metrics_blueprint = Blueprint('metrics', __name__)

_PROCESS_START = time.time()
_LOOPBACK = frozenset({'127.0.0.1', '::1'})


def _authorized():
    if config.METRICS_TOKEN:
        supplied = request.headers.get('Authorization', '')
        expected = f'Bearer {config.METRICS_TOKEN}'
        return hmac.compare_digest(
            supplied.encode('utf-8'),
            expected.encode('utf-8'),
        )
    return request.remote_addr in _LOOPBACK


class _Exposition:
    def __init__(self):
        self._lines = []

    def metric(self, name, kind, help_text, samples):
        self._lines.append(f'# HELP {name} {help_text}')
        self._lines.append(f'# TYPE {name} {kind}')
        for labels, value in samples:
            label_text = ''
            if labels:
                label_text = '{' + ','.join(
                    f'{key}="{val}"' for key, val in sorted(labels.items())
                ) + '}'
            self._lines.append(f'{name}{label_text} {float(value):g}')

    def gauge(self, name, help_text, value, **labels):
        self.metric(name, 'gauge', help_text, [(labels, value)])

    def render(self):
        return '\n'.join(self._lines) + '\n'


def _process_samples(out):
    out.gauge(
        'process_start_time_seconds',
        'Start time of the process since the Unix epoch.',
        _PROCESS_START,
    )
    out.gauge('webssh_threads', 'Live Python threads.', threading.active_count())
    try:
        with open('/proc/self/statm', encoding='ascii') as handle:
            resident_pages = int(handle.read().split()[1])
        out.gauge(
            'process_resident_memory_bytes',
            'Resident memory size in bytes.',
            resident_pages * os.sysconf('SC_PAGE_SIZE'),
        )
    except (OSError, ValueError, IndexError):
        pass
    try:
        out.gauge(
            'process_open_fds',
            'Open file descriptors.',
            len(os.listdir('/proc/self/fd')),
        )
    except OSError:
        pass


def collect():
    """Return the current exposition text."""
    from . import ssh_manager
    from .maintenance_mode import is_active
    from .ssh_output_flow import ssh_output_flow
    from .terminal_share import share_hub
    from .transfer_routes import transfer_manager

    out = _Exposition()

    summary, _items = ssh_manager.admin_session_snapshot(limit=0)
    out.gauge('webssh_ssh_sessions', 'Connected SSH terminal sessions.', summary['active'])
    out.gauge('webssh_ssh_session_owners', 'Users with at least one SSH session.', summary['users'])
    out.gauge('webssh_ssh_sessions_persistent', 'SSH sessions backed by tmux.', summary['tmux'])

    capacity = current_app.extensions.get('engineio_socket_capacity')
    if capacity is not None:
        sockets = capacity.snapshot()
        out.gauge('webssh_socket_connections', 'Admitted browser transports.', sockets['active'])
        out.metric(
            'webssh_socket_rejections_total', 'counter',
            'Browser transports refused for capacity since start.',
            [({}, sockets['rejected_total'])],
        )
    out.gauge(
        'webssh_socket_connections_limit',
        'Configured maximum browser transports.',
        config.MAX_SOCKET_CONNECTIONS,
    )

    flow = ssh_output_flow.usage()
    out.gauge(
        'webssh_ssh_output_unacked_bytes',
        'Terminal output awaiting browser acknowledgement.',
        flow['global_bytes'],
    )
    out.gauge(
        'webssh_ssh_output_unacked_events',
        'Terminal output events awaiting browser acknowledgement.',
        flow['global_events'],
    )

    shares = share_hub.stats()
    out.gauge('webssh_terminal_share_links', 'Active terminal share links.', shares['links'])
    out.metric(
        'webssh_terminal_share_viewers', 'gauge',
        'Terminal share viewers by state.',
        [
            ({'state': 'joined'}, shares['viewers']),
            ({'state': 'connected'}, shares['viewers_connected']),
            ({'state': 'pending'}, shares['viewers_pending']),
        ],
    )
    out.gauge('webssh_terminal_share_streams', 'Open viewer streams.', shares['streams'])
    out.gauge(
        'webssh_terminal_share_queued_bytes',
        'Undelivered output held for viewers.',
        shares['queued_bytes'],
    )
    out.metric(
        'webssh_terminal_share_resyncs_total', 'counter',
        'Viewers resynchronised after falling behind.',
        [({}, shares['resyncs'])],
    )
    out.metric(
        'webssh_terminal_share_chat_messages_total', 'counter',
        'Chat messages exchanged in shared sessions.',
        [({}, shares['chat_messages'])],
    )
    out.gauge(
        'webssh_terminal_share_viewers_limit',
        'Configured maximum concurrent share viewers.',
        config.TERMINAL_SHARE_MAX_VIEWERS,
    )

    lifecycle = current_app.extensions.get('runtime_lifecycle')
    if lifecycle is not None:
        jobs = lifecycle.snapshot()
        out.gauge('webssh_runtime_workers', 'Background worker capacity.', jobs['workers'])
        out.metric(
            'webssh_runtime_jobs', 'gauge', 'Background jobs by state.',
            [
                ({'state': 'running'}, jobs['running']),
                ({'state': 'queued'}, jobs['queued']),
                ({'state': 'cancelling'}, jobs['cancelling']),
            ],
        )
        out.gauge(
            'webssh_runtime_accepting_work',
            'Whether the runtime accepts new work.',
            int(bool(jobs['accepting_work'])),
        )

    transfers = transfer_manager.snapshot()
    out.metric(
        'webssh_transfers', 'gauge', 'File transfers by state.',
        [({'state': state}, count) for state, count in sorted(transfers.items())],
    )
    out.gauge('webssh_maintenance_mode', 'Restore maintenance mode.', int(bool(is_active())))
    out.gauge(
        'webssh_gunicorn_threads',
        'Configured Gunicorn worker threads.',
        config.GUNICORN_THREADS,
    )
    _process_samples(out)
    return out.render()


@metrics_blueprint.get('/metrics')
def metrics():
    if not config.METRICS_ENABLED:
        abort(404)
    if not _authorized():
        if config.METRICS_TOKEN:
            response = Response('Unauthorized\n', status=401, mimetype='text/plain')
            response.headers['WWW-Authenticate'] = 'Bearer realm="metrics"'
            return response
        abort(404)
    response = Response(
        collect(),
        mimetype='text/plain',
        content_type='text/plain; version=0.0.4; charset=utf-8',
    )
    response.headers['Cache-Control'] = 'no-store'
    return response
