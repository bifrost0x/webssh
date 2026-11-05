import pytest
from tests.test_paramiko5_readiness import store_key, write_metadata


@pytest.mark.parametrize('metadata_type', [[], {}])
def test_malformed_key_type_does_not_abort_remaining_keys(tmp_path, rsa_private_key_pem, metadata_type):
    from scripts.check_paramiko5_readiness import audit_data_dir

    entries = [
        store_key(tmp_path, 1, 'malformed-type', rsa_private_key_pem, metadata_type),
        store_key(tmp_path, 1, 'ordinary', rsa_private_key_pem, 'RSA'),
    ]
    write_metadata(tmp_path, 1, entries)
    results = audit_data_dir(tmp_path)
    assert len(results) == 2
    assert results[0]['metadata_type'] == 'UNKNOWN'
    assert results[1]['metadata_type'] == 'RSA'
    assert all(result['actual_type'] == 'RSA' for result in results)
