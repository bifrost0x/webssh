"""Server-side OIDC state and stable identity-link behavior."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest


def _create_user(app, username):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        db.session.commit()
        return user.id


def test_oidc_state_is_session_bound_expiring_and_single_use(app):
    from app.oidc_service import OIDCStateError, consume_login_state, create_login_state

    now = datetime.now(timezone.utc)
    with app.app_context():
        create_login_state(
            state="state-token",
            nonce="nonce-token",
            session_binding="browser-a-binding",
            code_verifier="pkce-verifier",
            now=now,
            ttl=timedelta(seconds=30),
        )

        intent = consume_login_state(
            state="state-token",
            session_binding="browser-a-binding",
            now=now,
        )
        assert intent.nonce == "nonce-token"
        assert intent.code_verifier == "pkce-verifier"
        assert intent.purpose == "login"
        assert intent.continuation == "/"
        with pytest.raises(OIDCStateError):
            consume_login_state(
                state="state-token",
                session_binding="browser-a-binding",
                now=now,
            )


def test_oidc_identity_resolution_never_uses_email(app):
    from app.models import OIDCIdentity, db
    from app.oidc_service import resolve_identity

    alice_id = _create_user(app, "oidc_alice")
    _create_user(app, "same_email_name")
    with app.app_context():
        db.session.add(OIDCIdentity(
            user_id=alice_id,
            issuer="https://issuer.example",
            subject="subject-1",
        ))
        db.session.commit()

        assert resolve_identity(
            "https://issuer.example",
            "subject-1",
        ).id == alice_id
        assert resolve_identity(
            "https://issuer.example",
            "same_email_name",
        ) is None


def test_new_oidc_state_replaces_prior_state_for_same_browser(app):
    from app.models import OIDCLoginState
    from app.oidc_service import create_login_state

    with app.app_context():
        for suffix in ("first", "second"):
            create_login_state(
                state=f"state-{suffix}-token",
                nonce=f"nonce-{suffix}-token",
                session_binding="same-browser-binding",
                code_verifier=f"verifier-{suffix}-token",
            )

        rows = OIDCLoginState.query.all()
        assert len(rows) == 1
        assert rows[0].nonce == "nonce-second-token"


def test_as_naive_utc_normalizes_aware_and_preserves_naive_values():
    from app.models import as_naive_utc

    naive = datetime(2026, 7, 30, 12, 0)
    aware = datetime(
        2026, 7, 30, 14, 0,
        tzinfo=timezone(timedelta(hours=2)),
    )

    assert as_naive_utc(naive) is naive
    assert as_naive_utc(aware) == naive


def _assurance_config(**overrides):
    values = {
        "OIDC_MFA_AMR_VALUES": frozenset(),
        "OIDC_MFA_ACR_VALUES": frozenset(),
        "OIDC_PHISHING_RESISTANT_AMR_VALUES": frozenset(),
        "OIDC_PHISHING_RESISTANT_ACR_VALUES": frozenset(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_oidc_success_without_configured_claim_match_is_basic():
    from app.auth_assurance import AssuranceLevel
    from app.oidc_service import evaluate_oidc_assurance

    result = evaluate_oidc_assurance(
        {"amr": ["pwd"], "auth_time": 1234},
        _assurance_config(),
    )

    assert result.level is AssuranceLevel.BASIC
    assert result.amr == ("pwd",)
    assert result.auth_time == 1234


def test_oidc_phishing_resistant_requires_explicit_amr_match():
    from app.auth_assurance import AssuranceLevel
    from app.oidc_service import evaluate_oidc_assurance

    result = evaluate_oidc_assurance(
        {"amr": ["webauthn", "mfa"], "auth_time": 1234},
        _assurance_config(
            OIDC_PHISHING_RESISTANT_AMR_VALUES={"webauthn"},
        ),
    )

    assert result.level is AssuranceLevel.PHISHING_RESISTANT
    assert result.reason == "explicit_match"


def test_oidc_mfa_accepts_an_explicit_acr_match():
    from app.auth_assurance import AssuranceLevel
    from app.oidc_service import evaluate_oidc_assurance

    result = evaluate_oidc_assurance(
        {"acr": "urn:example:aal2", "auth_time": 1234},
        _assurance_config(
            OIDC_MFA_ACR_VALUES={"urn:example:aal2"},
        ),
    )

    assert result.level is AssuranceLevel.MFA
    assert result.acr == "urn:example:aal2"


def test_oidc_conflicting_acr_and_amr_assurance_is_basic():
    from app.auth_assurance import AssuranceLevel
    from app.oidc_service import evaluate_oidc_assurance

    result = evaluate_oidc_assurance(
        {
            "acr": "urn:example:aal2",
            "amr": ["webauthn"],
            "auth_time": 1234,
        },
        _assurance_config(
            OIDC_MFA_ACR_VALUES={"urn:example:aal2"},
            OIDC_PHISHING_RESISTANT_AMR_VALUES={"webauthn"},
        ),
    )

    assert result.level is AssuranceLevel.BASIC
    assert result.reason == "conflicting_evidence"


@pytest.mark.parametrize(
    "claims",
    (
        {"amr": "mfa", "auth_time": 1234},
        {"amr": ["mfa", 7], "auth_time": 1234},
        {"acr": ["urn:example:aal2"], "auth_time": 1234},
        {"amr": ["mfa"], "auth_time": True},
        {"amr": ["mfa"], "auth_time": "1234"},
        {"amr": ["mfa"] * 17, "auth_time": 1234},
    ),
)
def test_malformed_oidc_assurance_evidence_is_basic(claims):
    from app.auth_assurance import AssuranceLevel
    from app.oidc_service import evaluate_oidc_assurance

    result = evaluate_oidc_assurance(
        claims,
        _assurance_config(OIDC_MFA_AMR_VALUES={"mfa"}),
    )

    assert result.level is AssuranceLevel.BASIC
    assert result.reason == "malformed_evidence"


def test_strong_oidc_match_without_auth_time_is_basic():
    from app.auth_assurance import AssuranceLevel
    from app.oidc_service import evaluate_oidc_assurance

    result = evaluate_oidc_assurance(
        {"amr": ["mfa"]},
        _assurance_config(OIDC_MFA_AMR_VALUES={"mfa"}),
    )

    assert result.level is AssuranceLevel.BASIC
    assert result.reason == "missing_auth_time"


def test_oidc_step_up_state_binds_requested_assurance_action_and_target(app):
    from app.oidc_service import consume_login_state, create_login_state

    target_hash = "a" * 64
    with app.app_context():
        create_login_state(
            state="step-up-state-token",
            nonce="step-up-nonce-token",
            session_binding="step-up-browser-binding",
            code_verifier="step-up-pkce-verifier",
            purpose="step_up",
            continuation="/admin",
            requested_acr="urn:example:aal2 urn:example:aal3",
            step_up_action="user.lock",
            step_up_target_hash=target_hash,
        )

        intent = consume_login_state(
            state="step-up-state-token",
            session_binding="step-up-browser-binding",
        )

    assert intent.purpose == "step_up"
    assert intent.continuation == "/admin"
    assert intent.requested_acr == "urn:example:aal2 urn:example:aal3"
    assert intent.step_up_action == "user.lock"
    assert intent.step_up_target_hash == target_hash
