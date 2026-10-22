"""Disposable output producers for real transport/browser regression tests."""
import threading
import time

from flask import request
from flask_login import current_user


def _produce_frames(emit_frame, stop, *, started, clock=time.monotonic):
    """Keep all 240 frames on absolute 20 Hz slots, including after backpressure."""
    completed = 0
    for sequence in range(1, 241):
        if stop.is_set():
            break
        deadline = started + (sequence - 1) * 0.05
        if stop.wait(max(0.0, deadline - clock())):
            break
        if emit_frame(sequence) is False:
            break
        completed = sequence
    return completed


def register_output_load(socketio, app):
    @socketio.on('e2e_output_load')
    def output_load():
        if not current_user.is_authenticated:
            return {'ok': False}
        sid, user_id = request.sid, current_user.id

        def run():
            from app.ssh_output_flow import emit_ssh_output, ssh_output_flow

            stop = threading.Event()
            counts = [0] * 20
            started = time.monotonic()
            peak = 0

            def produce(index):
                def emit_frame(sequence):
                    frame = ('\x1b[?1049h\x1b[?2004h\x1b[?1h' if sequence == 1 else '')
                    frame += '\x1b[H' + ('\x1b[32m' + 'x' * 100 + '\x1b[0m\r\n') * 24
                    frame += f'\x1b[Hstream-{index} frame-{sequence} END'
                    with app.app_context():
                        emit_ssh_output(socketio, sid, user_id, f'load-{index}', {
                            'session_id': f'load-{index}', 'data': frame,
                            'sequence': sequence,
                        }, cancel_event=stop)
                    return not stop.is_set()

                counts[index] = _produce_frames(emit_frame, stop, started=started)

            readers = [threading.Thread(target=produce, args=(i,), daemon=True) for i in range(20)]
            for reader in readers:
                reader.start()
            while any(reader.is_alive() for reader in readers):
                peak = max(peak, ssh_output_flow.usage()['socket_events'].get(sid, 0))
                if time.monotonic() - started > 35:
                    stop.set()
                time.sleep(0.01)
            socketio.emit('e2e_output_load_done', {
                'counts': counts,
                'peak': peak,
                'elapsed_ms': round((time.monotonic() - started) * 1000),
                'aborted': stop.is_set(),
            }, to=sid)

        socketio.start_background_task(run)
        return {'ok': True}
