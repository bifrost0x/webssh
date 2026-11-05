"""Disposable loopback SSH peer for end-to-end automation browser tests."""
import atexit
import io
import socket
import threading
import time
import paramiko


def seed(app, users):
    from app.key_manager import save_key
    from app.profile_manager import add_profile, update_profile_organization
    from app.host_key_store import HostKeyStore
    import config
    key = paramiko.RSAKey.generate(2048)
    client_key = paramiko.RSAKey.generate(2048)
    private_key = io.StringIO()
    client_key.write_private_key(private_key)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(16)
    port = listener.getsockname()[1]
    transports = []
    channels = []
    class Server(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return 'publickey'
        def check_auth_publickey(self, username, supplied_key):
            return paramiko.AUTH_SUCCESSFUL if username == 'fixture' and supplied_key == client_key else paramiko.AUTH_FAILED
        def check_channel_request(self, kind, channel_id):
            return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_exec_request(self, channel, command):
            def respond():
                try:
                    if command == b'wait':
                        for _ in range(200):
                            if channel.closed:
                                return
                            time.sleep(.1)
                    channel.sendall(b'fixture command completed\n')
                    channel.send_exit_status(2 if command == b'fail' else 0)
                    channel.shutdown_write()
                except (OSError, EOFError):
                    pass
            # Let the exec acknowledgement be delivered before the command ends.
            threading.Timer(.05, respond).start()
            return True
    def serve():
        while True:
            try:
                connected, _ = listener.accept()
            except OSError:
                return
            transport = paramiko.Transport(connected)
            transport.add_server_key(key)
            transports.append(transport)
            def start(transport=transport):
                try:
                    transport.start_server(server=Server())
                    while transport.is_active():
                        channel = transport.accept(.2)
                        if channel is not None:
                            channels.append(channel)
                except (OSError, EOFError, paramiko.SSHException):
                    transport.close()
            threading.Thread(target=start, daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    def close():
        listener.close()
        for transport in transports:
            transport.close()
    atexit.register(close)
    for user in users:
        key_meta, error = save_key(user.id, 'Automation fixture key', private_key.getvalue())
        if error:
            raise RuntimeError('Could not seed automation key')
        profile, error = add_profile(user.id, 'Automation fixture', '127.0.0.1', port, 'fixture', 'key', key_id=key_meta['id'])
        if error:
            raise RuntimeError('Could not seed automation profile')
        update_profile_organization(user.id, profile['id'], {'group': 'Automation lab'})
        HostKeyStore(user.id, config.KNOWN_HOSTS_FILE, config.USERS_DIR).record(f'[127.0.0.1]:{port}', key)
