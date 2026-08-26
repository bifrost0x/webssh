"""Credential-free diagnostic metadata for SMB failures."""

from __future__ import annotations

import re


SMB_DIAGNOSTIC_PHASES = frozenset({
    'file_operation',
    'lifecycle',
    'security_requirements',
    'session_authentication',
    'share_access',
    'target_resolution',
    'transport_negotiate',
    'unknown',
})
_EXCEPTION_TYPE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z', re.ASCII)
_NT_STATUS = re.compile(r'0[xX][0-9A-Fa-f]{8}\Z', re.ASCII)


def _safe_phase(value):
    return (
        value
        if isinstance(value, str) and value in SMB_DIAGNOSTIC_PHASES
        else 'unknown'
    )


def _safe_exception_type(value):
    if isinstance(value, str) and _EXCEPTION_TYPE.fullmatch(value):
        return value
    return None


def _safe_nt_status(value):
    if isinstance(value, str):
        if not _NT_STATUS.fullmatch(value):
            return None
        return f'0x{value[2:].upper()}'
    try:
        numeric = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not 0 <= numeric <= 0xFFFFFFFF:
        return None
    return f'0x{numeric:08X}'


def build_smb_diagnostic(
    *,
    phase,
    exception=None,
    exception_type=None,
    nt_status=None,
):
    """Return only fixed-format metadata safe for structured server logs."""
    if exception is not None:
        exception_type = type(exception).__name__
        nt_status = getattr(exception, 'ntstatus', nt_status)
    return {
        'diagnostic_phase': _safe_phase(phase),
        'diagnostic_exception_type': _safe_exception_type(exception_type),
        'diagnostic_nt_status': _safe_nt_status(nt_status),
    }


def copy_smb_diagnostic(error, *, phase=None):
    """Validate diagnostic attributes while copying an exception boundary."""
    return build_smb_diagnostic(
        phase=(
            phase
            if phase is not None
            else getattr(error, 'diagnostic_phase', 'unknown')
        ),
        exception_type=getattr(error, 'diagnostic_exception_type', None),
        nt_status=getattr(error, 'diagnostic_nt_status', None),
    )


def smb_diagnostic_log_fields(error):
    """Map validated internal attributes to stable structured-log fields."""
    diagnostic = copy_smb_diagnostic(error)
    return {
        'diagnostic_phase': diagnostic['diagnostic_phase'],
        'cause_type': diagnostic['diagnostic_exception_type'],
        'nt_status': diagnostic['diagnostic_nt_status'],
    }
