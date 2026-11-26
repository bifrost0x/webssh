"""Record how the Python release maps ID Token claims to assurance.

Writes a corpus with the results of evaluate_oidc_assurance so the Go test
replays it without Python. Run from the repository root with the project
virtual environment:

    WS=$PWD .venv/bin/python -I internal/auth/oidc/testdata/assurance_oracle.py \
        internal/auth/oidc/testdata/assurance_oracle.json.gz
"""
import gzip
import itertools
import json
import os
import random
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='oidc-oracle-')

from app.oidc_service import evaluate_oidc_assurance  # noqa: E402

ACR = ['absent', 'null', '"mfa"', '"phr"', '"both"', '"other"', '""', '7', 'true',
       '"' + 'a' * 256 + '"', '"' + 'a' * 257 + '"', '"ü"', '["mfa"]']
AMR = ['absent', 'null', '[]', '["otp"]', '["hwk"]', '["pwd"]', '["otp","hwk"]',
       '["pwd","otp","otp"]', '["both"]', '"otp"', '[1]', '[""]', '["otp",null]',
       json.dumps(['otp'] * 16), json.dumps(['otp'] * 17), json.dumps(['x' * 129]),
       json.dumps(['x' * 128, 'hwk'])]
AUTH_TIME = ['absent', 'null', '1700000000', '0', '-1', '1.5', '1e3', 'true', '"1700000000"',
             '253402300799', '253402300800', '1700000000.0']
POLICIES = [
    {},
    {'OIDC_MFA_ACR_VALUES': ['mfa', 'both'], 'OIDC_MFA_AMR_VALUES': ['otp', 'both'],
     'OIDC_PHISHING_RESISTANT_ACR_VALUES': ['phr', 'both'],
     'OIDC_PHISHING_RESISTANT_AMR_VALUES': ['hwk', 'both']},
    {'OIDC_MFA_ACR_VALUES': ['mfa'], 'OIDC_PHISHING_RESISTANT_AMR_VALUES': ['hwk']},
    {'OIDC_MFA_AMR_VALUES': ['otp', ''], 'OIDC_PHISHING_RESISTANT_ACR_VALUES': ['phr']},
    {'OIDC_MFA_ACR_VALUES': ['x' * 257, 'mfa'], 'OIDC_MFA_AMR_VALUES': ['otp']},
]


def claims_text(acr, amr, auth_time):
    parts = []
    for name, value in (('acr', acr), ('amr', amr), ('auth_time', auth_time)):
        if value != 'absent':
            parts.append(f'"{name}":{value}')
    return '{' + ','.join(parts) + '}'


def record(text, index):
    result = evaluate_oidc_assurance(json.loads(text), POLICIES[index])
    return {
        'claims': text,
        'policy': index,
        'level': result.level.value,
        'reason': result.reason,
        'acr': result.acr if isinstance(result.acr, str) else None,
        'amr': list(result.amr),
        'auth_time': result.auth_time,
    }


def main():
    cases = []
    for index in range(len(POLICIES)):
        for acr, amr, auth_time in itertools.product(ACR, AMR, AUTH_TIME):
            cases.append(record(claims_text(acr, amr, auth_time), index))
    rng = random.Random(7)
    values = ['mfa', 'phr', 'both', 'otp', 'hwk', 'pwd', 'other']
    for _ in range(2000):
        amr = json.dumps(rng.sample(values, rng.randint(0, 4)))
        acr = json.dumps(rng.choice(values)) if rng.random() < 0.7 else 'absent'
        auth_time = str(rng.randint(-5, 2 ** 40)) if rng.random() < 0.8 else 'absent'
        cases.append(record(claims_text(acr, amr, auth_time), rng.randrange(len(POLICIES))))
    data = json.dumps({'policies': POLICIES, 'cases': cases}, ensure_ascii=False, separators=(',', ':'))
    with open(sys.argv[1], 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as out:
        out.write(data.encode('utf-8') + b'\n')


if __name__ == '__main__':
    main()
