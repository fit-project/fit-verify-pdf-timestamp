from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from fit_verify_pdf_timestamp.rfc3161ng_compat import _verify_signature


@pytest.mark.unit
def test_verify_signature_accepts_ec_public_keys() -> None:
    signed_data = b"timestamp signed attributes"
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    _verify_signature(
        private_key.public_key(),
        signature,
        signed_data,
        hashes.SHA256(),
    )


@pytest.mark.unit
def test_verify_signature_keeps_rsa_public_key_path() -> None:
    signed_data = b"timestamp signed attributes"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = private_key.sign(
        signed_data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    _verify_signature(
        private_key.public_key(),
        signature,
        signed_data,
        hashes.SHA256(),
    )


@pytest.mark.unit
def test_verify_signature_rejects_invalid_ec_signature() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(b"original", ec.ECDSA(hashes.SHA256()))

    with pytest.raises(InvalidSignature):
        _verify_signature(
            private_key.public_key(),
            signature,
            b"changed",
            hashes.SHA256(),
        )
