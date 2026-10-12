"""
Tests for ML-DSA-87 signing of short-form reports, in JWS and CoRIM.

Each format gets a round trip plus negative controls: a tampered payload, the
wrong key, the wrong key type, and a mislabelled algorithm must all be refused,
each for the reason the test names.
"""

import base64
import json
import os
import sys

# Add parent directory to path to import OcpReportLib
LIB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, LIB_DIR)
import cbor2
import jwt
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from OcpReportLib import ShortFormReport


def pems(key):
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def report():
    rep = ShortFormReport(framework_ver="1.1")
    rep.add_device(vendor="Test Vendor", product="Test Device", category="storage",
                   repo_tag="test_v1.0.0", fw_ver="1.0.0",
                   fw_hash_sha384="a" * 96, fw_hash_sha512="b" * 128)
    rep.add_audit(srp="Test SRP", methodology="whitebox", date="2023-01-01",
                  report_ver="1.0", scope_number=1)
    return rep


def raises(fn, expected, text=""):
    """True only if fn raises `expected` with `text` in its message. The CoRIM
    verifier re-raises a generic Exception, so its original cause counts too."""
    try:
        fn()
    except Exception as e:
        for err in (e, e.__context__):
            if isinstance(err, expected) and text in str(err):
                return True
        print(f"  unexpected {type(e).__name__}: {e}")
        return False
    return False


def test_mldsa87_signing():
    """Run every ML-DSA-87 case and return True only if all of them pass."""
    print("=== Testing ML-DSA-87 Signing ===")
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        priv, pub = pems(mldsa.MLDSA87PrivateKey.generate())
    except (ImportError, UnsupportedAlgorithm):
        print("SKIP: ML-DSA-87 needs cryptography 48.0.0 or later")
        return True
    _, wrong_pub = pems(mldsa.MLDSA87PrivateKey.generate())
    priv65, pub65 = pems(mldsa.MLDSA65PrivateKey.generate())
    ecpriv, ecpub = pems(ec.generate_private_key(ec.SECP384R1()))
    rep = report()
    results = []

    # JWS
    results.append(("JWS sign", rep.sign_json_report_pem(priv, "ML-DSA-87", "k")))
    jws = rep.get_signed_json_report()
    results.append(("JWS verify", rep.verify_signed_json_report(jws, pub) == rep.get_report_as_dict()))
    results.append(("JWS wrong key rejected", raises(lambda: rep.verify_signed_json_report(jws, wrong_pub), jwt.InvalidSignatureError)))
    h, p, s = jws.decode().split(".")
    bad = f"{h}.{p[:-2]}{'A' if p[-2] != 'A' else 'B'}{p[-1]}.{s}".encode()
    results.append(("JWS tampered payload rejected", raises(lambda: rep.verify_signed_json_report(bad, pub), jwt.InvalidSignatureError)))
    results.append(("JWS ML-DSA-87 key as ES384 refused", rep.sign_json_report_pem(priv, "ES384", "k") is False))
    results.append(("JWS EC key as ML-DSA-87 refused", rep.sign_json_report_pem(ecpriv, "ML-DSA-87", "k") is False))
    results.append(("JWS ML-DSA-65 key refused", rep.sign_json_report_pem(priv65, "ML-DSA-87", "k") is False))
    results.append(("JWS verify with ML-DSA-65 key rejected", raises(lambda: rep.verify_signed_json_report(jws, pub65), jwt.InvalidKeyError)))
    results.append(("JWS verify with EC key rejected", raises(lambda: rep.verify_signed_json_report(jws, ecpub), jwt.InvalidKeyError)))
    # existing algorithm unchanged
    results.append(("ES384 still signs", rep.sign_json_report_pem(ecpriv, "ES384", "e")))
    results.append(("ES384 still verifies", rep.verify_signed_json_report(rep.get_signed_json_report(), ecpub) == rep.get_report_as_dict()))
    eh, ep, es = rep.get_signed_json_report().decode().split(".")
    relabelled = base64.urlsafe_b64encode(json.dumps({"alg": "ML-DSA-87", "kid": "e", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    results.append(("JWS ES384 report relabelled ML-DSA-87 rejected",
                    raises(lambda: rep.verify_signed_json_report(f"{relabelled}.{ep}.{es}".encode(), pub), jwt.InvalidSignatureError)))

    # CoRIM
    results.append(("CoRIM sign", rep.sign_corim_report_pem(priv, "ML-DSA-87", "k")))
    cor = rep.get_signed_corim_report()
    d = cbor2.loads(cor)
    results.append(("CoRIM is COSE_Sign1 with alg -50", d.tag == 18 and cbor2.loads(d.value[0]) == {1: -50}))
    results.append(("CoRIM verify", rep.verify_signed_corim_report(cor, pub, "k", algo=-50)))
    results.append(("CoRIM wrong key rejected", raises(lambda: rep.verify_signed_corim_report(cor, wrong_pub, "k", algo=-50), InvalidSignature)))
    results.append(("CoRIM wrong kid rejected", raises(lambda: rep.verify_signed_corim_report(cor, pub, "x", algo=-50), ValueError, "kid does not match")))
    pay = bytearray(d.value[2]); pay[-1] ^= 1
    bad = cbor2.dumps(cbor2.CBORTag(18, [d.value[0], d.value[1], bytes(pay), d.value[3]]))
    results.append(("CoRIM tampered payload rejected", raises(lambda: rep.verify_signed_corim_report(bad, pub, "k", algo=-50), InvalidSignature)))
    results.append(("CoRIM ML-DSA-65 key rejected", raises(lambda: rep.verify_signed_corim_report(cor, pub65, "k", algo=-50), ValueError, "not an ML-DSA-87 key")))
    results.append(("CoRIM EC key as ML-DSA-87 refused", rep.sign_corim_report_pem(ecpriv, "ML-DSA-87", "k") is False))
    results.append(("CoRIM -50 report not accepted as ES384", raises(lambda: rep.verify_signed_corim_report(cor, pub, "k", algo=-35), ValueError)))
    results.append(("CoRIM ES384 still round-trips", rep.sign_corim_report_pem(ecpriv, "ES384", "e")
                    and rep.verify_signed_corim_report(rep.get_signed_corim_report(), ecpub, "e", algo=-35)))
    es384 = cbor2.loads(rep.get_signed_corim_report())
    relabelled = cbor2.dumps(cbor2.CBORTag(18, [cbor2.dumps({1: -50}), {4: b"e"}, es384.value[2], es384.value[3]]))
    results.append(("CoRIM ES384 report relabelled -50 rejected",
                    raises(lambda: rep.verify_signed_corim_report(relabelled, pub, "e", algo=-50), InvalidSignature)))

    # The shipped sample must keep verifying against its published key
    with open(os.path.join(LIB_DIR, "samples", "example_mldsa87.jws"), "rb") as f:
        sample = f.read()
    with open(os.path.join(LIB_DIR, "samples", "testkey_mldsa87.pub"), "rb") as f:
        sample_pub = f.read()
    results.append(("Sample example_mldsa87.jws verifies",
                    ShortFormReport().verify_signed_json_report(sample, sample_pub)["device"]["vendor"] == "ACME Inc"))

    failed = [n for n, ok in results if not ok]
    for n, ok in results:
        print(("PASS " if ok else "FAIL ") + n)
    print(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    return not failed


if __name__ == "__main__":
    sys.exit(0 if test_mldsa87_signing() else 1)
