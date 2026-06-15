import hashlib


def _verify_signature(public_key, signature, signed_data, hash_algorithm):
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            signature,
            signed_data,
            padding.PKCS1v15(),
            hash_algorithm,
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            signature,
            signed_data,
            ec.ECDSA(hash_algorithm),
        )
    else:
        raise TypeError(f"unsupported public key type: {type(public_key).__name__}")


def apply_rfc3161ng_ec_compat():
    try:
        import rfc3161ng
        import rfc3161ng.api as rfc3161ng_api  # type: ignore[import-untyped]
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return

    def check_timestamp(
        tst, certificate=None, data=None, digest=None, hashname=None, nonce=None
    ):
        hashname = hashname or "sha1"
        hashobj = hashlib.new(hashname)
        if digest is None:
            if not data:
                raise ValueError("check_timestamp requires data or digest argument")
            hashobj.update(data)
            digest = hashobj.digest()

        if not isinstance(tst, rfc3161ng.TimeStampToken):
            tst, substrate = rfc3161ng_api.decoder.decode(
                tst, asn1Spec=rfc3161ng.TimeStampToken()
            )
            if substrate:
                raise ValueError("extra data after tst")
        signed_data = tst.content
        certificate = rfc3161ng_api.load_certificate(signed_data, certificate)
        if nonce is not None and int(tst.tst_info["nonce"]) != int(nonce):
            raise ValueError("nonce is different or missing")

        message_imprint = tst.tst_info.message_imprint
        if (
            message_imprint.hash_algorithm[0] != rfc3161ng_api.get_hash_oid(hashname)
            or bytes(message_imprint.hashed_message) != digest
        ):
            raise ValueError("Message imprint mismatch")
        if not len(signed_data["signerInfos"]):
            raise ValueError("No signature")

        signer_info = signed_data["signerInfos"][0]
        if tst.content["contentInfo"]["contentType"] != rfc3161ng.id_ct_TSTInfo:
            raise ValueError(
                "Signed content type is wrong: %s != %s"
                % (
                    tst.content["contentInfo"]["contentType"],
                    rfc3161ng.id_ct_TSTInfo,
                )
            )

        content = bytes(
            rfc3161ng_api.decoder.decode(
                bytes(tst.content["contentInfo"]["content"]),
                asn1Spec=rfc3161ng_api.univ.OctetString(),
            )[0]
        )
        signer_hash_name = hashname
        if len(signer_info["authenticatedAttributes"]):
            authenticated_attributes = signer_info["authenticatedAttributes"]
            signer_digest_algorithm = signer_info["digestAlgorithm"]["algorithm"]
            signer_hash_class = rfc3161ng_api.get_hash_class_from_oid(
                signer_digest_algorithm
            )
            signer_hash_name = rfc3161ng_api.get_hash_from_oid(signer_digest_algorithm)
            content_digest = signer_hash_class(content).digest()
            for authenticated_attribute in authenticated_attributes:
                if authenticated_attribute[0] == rfc3161ng_api.id_attribute_messageDigest:
                    try:
                        signed_digest = bytes(
                            rfc3161ng_api.decoder.decode(
                                bytes(authenticated_attribute[1][0]),
                                asn1Spec=rfc3161ng_api.univ.OctetString(),
                            )[0]
                        )
                        if signed_digest != content_digest:
                            raise ValueError("Content digest != signed digest")
                        signed_attributes = rfc3161ng_api.univ.SetOf()
                        for i, value in enumerate(authenticated_attributes):
                            signed_attributes.setComponentByPosition(i, value)
                        signed_data = rfc3161ng_api.encoder.encode(signed_attributes)
                        break
                    except rfc3161ng_api.PyAsn1Error:
                        raise
            else:
                raise ValueError("No signed digest")
        else:
            signed_data = content

        signature = signer_info["encryptedDigest"]
        public_key = certificate.public_key()
        hash_family = getattr(hashes, signer_hash_name.upper())
        _verify_signature(public_key, bytes(signature), signed_data, hash_family())
        return True

    rfc3161ng_api.check_timestamp = check_timestamp
    rfc3161ng.check_timestamp = check_timestamp
