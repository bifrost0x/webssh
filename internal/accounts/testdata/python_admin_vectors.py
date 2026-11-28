"""Record the answers of the Python account administration as test vectors.

Usage (from the repository root, with the venv in $WEBSSH_PYTHON_ROOT):

    $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/accounts/testdata/python_admin_vectors.py "$WEBSSH_PYTHON_ROOT" \
        > internal/accounts/testdata/python_admin_vectors.json

The Flask application of the given checkout runs unchanged with a
throw-away data directory. Each scenario starts from an empty database,
creates its accounts (LDAP- and GitHub-managed ones through their identity
rows), signs the actor in with the password form, obtains the step-up
grant through /api/step-up/password and sends the request. The vector
records the answer and the target account afterwards.
"""

import json
import os
import pathlib
import sys
import tempfile

root = pathlib.Path(sys.argv[1]).resolve()
# The application logs to stdout; the vectors go to the real stdout only.
vectors_out = sys.stdout
sys.stdout = sys.stderr
sys.path.insert(0, str(root))

work = tempfile.TemporaryDirectory(prefix="webssh-admin-vectors-")
os.environ.update({
    "SECRET_KEY": "admin-vectors-secret-key-0123456789",
    "DEBUG": "True",
    "DEPLOYMENT_PROFILE": "homelab",
    "DATA_DIR": str(pathlib.Path(work.name) / "data"),
    "TRANSFER_TEMP_DIR": str(pathlib.Path(work.name) / "transfers"),
    "BACKUP_TEMP_DIR": str(pathlib.Path(work.name) / "backups"),
    "RATELIMIT_STORAGE_URL": "memory://",
    "RATELIMIT_ENABLED": "false",
    "LDAP_ENABLED": "false",
    "OIDC_ENABLED": "false",
    "TAILSCALE_SSH_ENABLED": "false",
    "ADMIN_PANEL_ENABLED": "true",
})

import bcrypt  # noqa: E402

_gensalt = bcrypt.gensalt
bcrypt.gensalt = lambda rounds=12, prefix=b"2b": _gensalt(rounds=4, prefix=prefix)

import config  # noqa: E402
from app import create_app  # noqa: E402
from app.models import GitHubIdentity, LDAPIdentity, User, db  # noqa: E402

PASSWORD = "password123"

app = create_app(start_runtime=False)
app.config["TESTING"] = True
app.config["WTF_CSRF_ENABLED"] = False

# Accounts: (name, admin, locked, managed). The actor is always "actor".
BASE = [("actor", True, False, ""), ("bob", False, False, "")]

SCENARIOS = []


def scenario(name, accounts, method, target, path, body=None, admins=(), action=None, step=None):
    SCENARIOS.append({
        "name": name, "accounts": [list(a) for a in accounts], "admin_users": list(admins),
        "method": method, "target": target, "path": path, "body": body,
        "step_up": step,
    })


for action in ("lock", "unlock", "promote", "demote", "delete"):
    for who, accounts in (
        ("self", BASE),
        ("user", BASE),
        ("admin", BASE + [("carol", True, False, "")]),
        ("locked", BASE + [("carol", False, True, "")]),
        ("ldap", BASE + [("carol", False, False, "ldap")]),
        ("github", BASE + [("carol", False, False, "github")]),
        ("listed", BASE + [("carol", True, False, "")]),
        ("listed_locked", BASE + [("carol", True, True, "")]),
        ("listed_ldap", BASE + [("carol", False, False, "ldap")]),
    ):
        target = {"self": "actor", "user": "bob"}.get(who, "carol")
        admins = ("carol",) if who.startswith("listed") else ()
        scenario(f"{action}-{who}", accounts, "post", target, f"/admin/api/users/{{id}}/{action}",
                 admins=admins, step=["user.manage", f"{{id}}:{action}"])
scenario("unknown-action", BASE, "post", "bob", "/admin/api/users/{id}/explode", step=["user.manage", "{id}:explode"])
scenario("missing-user", BASE, "post", "nobody", "/admin/api/users/{id}/lock", step=["user.manage", "{id}:lock"])
scenario("no-grant", BASE, "post", "bob", "/admin/api/users/{id}/lock")
for name, body in (
    ("ok", {"confirm_username": "bob"}),
    ("case", {"confirm_username": "Bob"}),
    ("missing", {}),
    ("list", ["bob"]),
    ("number", {"confirm_username": 5}),
):
    scenario(f"mfa-{name}", BASE, "delete", "bob", "/admin/api/users/{id}/mfa", body=body, step=["user.mfa_reset", "{id}"])
    scenario(f"recovery-{name}", BASE, "post", "bob", "/admin/api/users/{id}/recovery", body=body, step=["recovery.reset", "{id}"])
scenario("mfa-self", BASE, "delete", "actor", "/admin/api/users/{id}/mfa", body={"confirm_username": "actor"}, step=["user.mfa_reset", "{id}"])
scenario("mfa-missing-user", BASE, "delete", "nobody", "/admin/api/users/{id}/mfa", body={"confirm_username": "x"}, step=["user.mfa_reset", "{id}"])
scenario("mfa-no-grant", BASE, "delete", "bob", "/admin/api/users/{id}/mfa", body={"confirm_username": "bob"})
scenario("recovery-missing-user", BASE, "post", "nobody", "/admin/api/users/{id}/recovery", body={"confirm_username": "x"}, step=["recovery.reset", "{id}"])


def build(accounts):
    ids = {}
    for name, admin, locked, managed in accounts:
        user = User(username=name, is_admin=admin, is_locked=False)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.flush()
        if managed == "ldap":
            db.session.add(LDAPIdentity(user_id=user.id, provider="corp", subject=f"s-{name}",
                                        directory_username=name, distinguished_name=f"uid={name},dc=example"))
        elif managed == "github":
            db.session.add(GitHubIdentity(user_id=user.id, github_user_id=1000 + user.id, login=name,
                                          display_name=name, provisioned_by_github=True))
        ids[name] = user.id
    db.session.commit()
    return ids


def run(sc):
    with app.app_context():
        db.drop_all()
        db.create_all()
        ids = build(sc["accounts"])
    config.ADMIN_USERS = sc["admin_users"]
    client = app.test_client()
    resp = client.post("/login", data={"username": "actor", "password": PASSWORD})
    assert resp.status_code == 302, resp.status_code
    with app.app_context():
        for name, _admin, locked, _managed in sc["accounts"]:
            if locked:
                db.session.get(User, ids[name]).is_locked = True
        db.session.commit()
    target_id = ids.get(sc["target"], 99)
    headers = {}
    if sc["step_up"]:
        action, target = sc["step_up"]
        grant = client.post("/api/step-up/password", json={
            "action": action, "target": target.format(id=target_id), "password": PASSWORD})
        assert grant.status_code == 200, (sc["name"], grant.get_json())
        headers["X-WebSSH-Step-Up"] = grant.get_json()["grant"]
    path = sc["path"].format(id=target_id)
    request = getattr(client, sc["method"])
    resp = request(path, json=sc["body"], headers=headers) if sc["body"] is not None else request(path, headers=headers)
    body = resp.get_json(silent=True) or {}
    out = {"status": resp.status_code, "error": body.get("error"), "codes": len(body.get("codes") or [])}
    with app.app_context():
        user = db.session.get(User, target_id)
        out["after"] = None if user is None else {
            "is_admin": bool(user.is_admin), "is_locked": bool(user.is_locked), "mfa_enabled": bool(user.mfa_enabled)}
        if user is not None and "user" in body:
            out["user"] = {k: body["user"][k] for k in ("is_admin", "is_locked", "admin_managed_by_config", "ldap_managed", "github_managed")}
    sc = dict(sc)
    sc["want"] = out
    return sc


vectors_out.write(json.dumps([run(sc) for sc in SCENARIOS], indent=1, sort_keys=True) + "\n")
