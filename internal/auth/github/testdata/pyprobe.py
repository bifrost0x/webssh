"""Answers the differential tests of internal/auth/github with the Python
release's own functions (app/github_auth_service.py).

Reads one JSON request per line on stdin and writes one JSON answer per
line. Test support only.
"""

import json
import sys

sys.path.insert(0, sys.argv[1])

import config  # noqa: E402
from app import github_auth_service as gh  # noqa: E402
from app import github_auth_routes as routes  # noqa: E402


class _Response:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return json.loads(self._body)


class _HTTP:
    def __init__(self, status, body):
        self.answer = _Response(status, body)

    def get(self, *args, **kwargs):
        return self.answer


def answer(req):
    op = req['op']
    if op == 'redirect':
        config.APPLICATION_ROOT = req.get('root', '')
        try:
            gh._validate_redirect_uri(req['value'])
            return ''
        except gh.GitHubConfigurationError as exc:
            return str(exc)
    if op == 'orgs':
        try:
            return list(gh._normalize_orgs(req['value']))
        except gh.GitHubConfigurationError as exc:
            return {'error': str(exc)}
    if op == 'profile':
        try:
            p = gh.fetch_profile('t', http=_HTTP(req['status'], req['body']))
            return [p.user_id, p.login, p.display_name or '']
        except gh.GitHubProviderError:
            return None
    if op == 'base':
        login = req.get('login', '')
        return (routes._USERNAME_PATTERN.sub('_', login.lower()).strip('_') or 'github')[:32]
    raise ValueError(op)


def main():
    for line in sys.stdin:
        print(json.dumps(answer(json.loads(line))), flush=True)


if __name__ == '__main__':
    main()
