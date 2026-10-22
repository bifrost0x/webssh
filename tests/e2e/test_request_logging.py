"""Successful fixture requests must not flood CI's shared output pipe."""
import importlib.util
from pathlib import Path
from unittest.mock import patch


def test_fixture_request_logging_preserves_http_failures_without_success_noise():
    source = Path(__file__).with_name('run_app.py')
    spec = importlib.util.spec_from_file_location('fixture_request_logging', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handler = object.__new__(module.FixtureRequestHandler)
    with patch('werkzeug.serving.WSGIRequestHandler.log_request') as log:
        for status in [200, 204, 302, '304']:
            handler.log_request(status, 123)
        log.assert_not_called()
        for status in [400, '404', 500]:
            handler.log_request(status, 456)
        assert [call.args for call in log.call_args_list] == [(400, 456), ('404', 456), (500, 456)]
