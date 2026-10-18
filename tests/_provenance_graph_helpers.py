import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aural import provenance


# RFC 8032 test-vector seed #1, matching the repository's deterministic
# provenance fixture generator. This is test-only material.
_TEST_SEED = bytes.fromhex(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
)


def signed_record(assertion):
    """Return a genuinely signed canonical test record for an assertion."""
    assertion_bytes = provenance._jcs_text(
        assertion, provenance.VerificationStage.SIGNATURE,
    ).encode('utf-8')
    signature = Ed25519PrivateKey.from_private_bytes(_TEST_SEED).sign(
        provenance.SIGNATURE_DOMAIN + assertion_bytes,
    )
    document = {
        'assertion': assertion,
        'signature': base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii'),
    }
    return provenance._jcs_text(
        document, provenance.VerificationStage.RECORD,
    ).encode('utf-8')
