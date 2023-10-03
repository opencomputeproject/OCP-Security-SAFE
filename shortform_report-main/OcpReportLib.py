"""
A simple library for generating the short-form vendor security review report.

This script is intended to be used by Security Review Providers who are
participating in the Open Compute Project's Firmware Security Review Framework.
The script complies with version 0.3 (draft) of the Security Review Framework
document.

More details about the OCP review framework can be found here:
*  https://www.opencompute.org/wiki/Security

For example usage of this script, refer to the following:
  * example_generate.py: 
      Demonstrates how to generate, sign and verify the JSON report.
  * sample_report.json
      An example JSON report that was created by this script.

Author: Jeremy Boone, NCC Group
Date  : June 5th, 2023
"""

import json
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

# Only the following JSON Web Algorithms (JWA) will be accepted by this script
# for signing the short-form report. Refer to RFC7518 for more details. 
ALLOWED_JWA_RSA_ALGOS = (
    "PS384",  # RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    "PS512",  # RSASSA-PSS using SHA-512 and MGF1 with SHA-512
)
ALLOWED_JWA_ECDSA_ALGOS = (
    "ES384",  # ECDSA using P-384 and SHA-384
    "ES512"  # ECDSA using P-521 and SHA-512
)
ALLOWED_JWA_ALGOS = ALLOWED_JWA_RSA_ALGOS + ALLOWED_JWA_ECDSA_ALGOS

# Only the following RSA key sizes (in bits) will be accepted by this script for
# signing a short-form report.
ALLOWED_RSA_KEY_SIZES = (
    3072,  # RSA 384
    4096  # RSA 512
)


class ShortFormReport(object):
    def __init__(self, framework_ver: str = "0.3"):
        self.report = {}
        self.report["review_framework_version"] = f"{framework_ver}".strip()
        self.signed_report = None

    def add_device(self, vendor: str, product: str, category: str, repo_tag: str, fw_ver: str, fw_hash_sha384: str,
                   fw_hash_sha512: str) -> None:
        """Add metadata that describes the vendor's device that was tested.

        vendor:    The name of the vendor that manufactured the device.
        product:   The name of the device. Usually a model name or number.
        category:  The type of device that was audited. Usually a short string 
                     such as: 'storage', 'network', 'gpu', 'cpu', 'apu', or 'bmc'.
        repo_tag:  The Git repository tag associated with the audit. Useful when
                     evaluating ROMs for which we cannot easily calculate or 
                     verify the hash.
        fw_ver:    The version of the firmware image that is attested by this
                     report. In most cases this will be the firmware version
                     produced by the vendor after the security audit completes,
                     which contains fixes for all vulnerabilities found during
                     the audit.
        fw_hash_sha384: A hex-encoded string containing the SHA2-384 hash of 
                        the firmware image. Prefixed with "0x".
        fw_hash_sha512: ... ditto but using SHA2-512 ...
        """
        self.report["device"] = {}
        self.report["device"]["vendor"] = f"{vendor}".strip()
        self.report["device"]["product"] = f"{product}".strip()
        self.report["device"]["category"] = f"{category}".strip()
        self.report["device"]["repo_tag"] = f"{repo_tag}".strip()
        self.report["device"]["fw_version"] = f"{fw_ver}".strip()
        self.report["device"]["fw_hash_sha2_384"] = f"{fw_hash_sha384}".strip()
        self.report["device"]["fw_hash_sha2_512"] = f"{fw_hash_sha512}".strip()

    def add_audit(self, srp: str, methodology: str, date: str, report_ver: str, scope_number: int, cvss_ver: str = "3.1") -> None:
        """Add metadata that describes the scope of the security review.

        srp:         The name of the Security Review Provider.
        methodology: The test methodology. Currently a free-form text field.
                       Usually a value like 'whitebox' or 'blackbox'.
        date:        The date when the security audit completed. In the 
                       YYYY-MM-DD format.
        report_ver:  Version of the report created by the SRP.
        scope:       The OCP scope number of the audit, 1, 2, or 3.
        cvss_ver:    Version of CVSS used to calculate scores for each issue.
                       Defaults to "3.1".
        """
        self.report["audit"] = {}
        self.report["audit"]["srp"] = f"{srp}".strip()
        self.report["audit"]["methodology"] = f"{methodology}".strip()
        self.report["audit"]["completion_date"] = f"{date}".strip()
        self.report["audit"]["report_version"] = f"{report_ver}".strip()
        self.report["audit"]["scope_number"] = scope_number
        self.report["audit"]["cvss_version"] = f"{cvss_ver}".strip()
        self.report["audit"]["issues"] = []

    def add_issue(self, title: str, cvss_score: str, cvss_vec: str, cwe: str, description: str, cve=None) -> None:
        """Add one issue to the list of issues. This list should only contain
        unfixed issues. That is, any vulnerabilities discovered during the
        audit that were fixed before the 'fw_version' (listed above) should not
        be included.

        title:       A brief summary of the issue. Usually taken directly from 
                       the SRP's audit report.
        cvss_score:  The CVSS base score, represented as a string, such as "7.1".
        cvss_vec:    The CVSS base vector. Temporal and environmental metrics are
                       not used or tracked.
        cwe:         The CWE identifier for the vulnerability, for example "CWE-123".
        description: A one or two sentence description of the issue. All vendor
                       sensitive information should be redacted.
        cve:         This field is optional, as not all reported issues will be
                       assigned a CVE number.
        """
        new_issue = {
            "title": f"{title}".strip(),
            "cvss_score": f"{cvss_score}".strip(),
            "cvss_vector": f"{cvss_vec}".strip(),
            "cwe": f"{cwe}".strip(),
            "description": f"{description}".strip(),
        }

        if cve is None:
            new_issue["cve"] = None
        else:
            new_issue["cve"] = f"{cve}".strip()

        self.report["audit"]["issues"].append(new_issue)

    ###########################################################################
    # APIs for getting and printing the JSON report
    ###########################################################################

    def get_report_as_dict(self) -> dict:
        """Returns the short-form report as a Python dict.
        """
        return self.report

    def get_report_as_str(self) -> str:
        """Return the short-form report as a formatted and indented string.
        """
        return json.dumps(self.get_report_as_dict(), indent=4)

    def print_report(self) -> None:
        """Pretty-prints the short-form report
        """
        print(self.get_report_as_str())

    ###########################################################################
    # APIs for signing the report
    ###########################################################################

    def sign_report(self, priv_key: bytes, algo: str, kid: str) -> bool:
        """Sign the JSON object to make a JSON Web Signature. Refer to RFC7515
        for additional details of the JWS specification.

        The report can be signed using RSAPSS-384 or RSAPSS-512, or using ECDSA
        with the NIST approved P-384 (secp384r1) or P-521 (secp521r1) curves.

        priv_key: A bytes object containing the private key.
        algo:     The string that specifies the RFC7518 JSON Web Algorithm (JWA).
        kid:      The Key ID to be included in the JWS header. This field will
                    be used to uniquely identify the unique SRP key that was used
                    to sign the report.

        Returns True on success, and False on failure.
        """
        # Ensure the signing algorithm is in the allow list
        if algo not in ALLOWED_JWA_ALGOS:
            print(f"Algorithm '{algo}' not in: {ALLOWED_JWA_ALGOS}")
            return False

        # Parse the private key to do some simple validation
        pem = serialization.load_pem_private_key(priv_key, None, backend=default_backend())

        # Ensure the correct private key types are passed
        if not isinstance(pem, (RSAPrivateKey, EllipticCurvePrivateKey)):
            print(f"Expected 'priv_key' to be a 'RSAPrivateKey' or 'EllipticCurvePrivateKey'")
            return False

        # Sanity check which curve is in use:
        if algo in ALLOWED_JWA_ECDSA_ALGOS:
            if pem.curve.name not in ("secp521r1", "secp384r1"):
                print(f"Using disallowed curve: {pem.curve.name}")
                return False

        # Because the JWA algorithm (e.g., 'PS384') specifies the hash-size, and
        # not the key-size, we must double check the key-size here. We don't want
        # RSA keys smaller than 3072 bytes.
        if algo in ALLOWED_JWA_RSA_ALGOS:
            if pem.key_size not in ALLOWED_RSA_KEY_SIZES:
                print(f"RSA key is too small: {pem.key_size}, must be one of: {ALLOWED_RSA_KEY_SIZES}")
                return False

        # Ensure the provided private key corresponds with the specified algo parameter.
        if ((algo == "PS384") and (pem.key_size != 3072)) or \
                ((algo == "PS512") and (pem.key_size != 4096)) or \
                ((algo == "ES384") and (pem.key_size != 384)) or \
                ((algo == "ES512") and (pem.key_size != 521)):
            print(f"Mismatch between algo={algo} and private key size: {pem.key_size}")
            return False

        # Set the JWS headers
        jws_headers = {"kid": f"{kid}"}

        # Finally, we can sign the short-form report.
        self.signed_report = jwt.encode(self.get_report_as_dict(),
                                        key=priv_key,
                                        algorithm=algo,
                                        headers=jws_headers)
        return True

    def get_signed_report(self) -> bytes:
        """Returns the signed short form report (a JWS) as a bytes object. May
        return a 'None' object if the report hasn't been signed yet.
        """
        return self.signed_report

    ###########################################################################
    # APIs for verifying a signed report
    ###########################################################################

    def get_signed_report_kid(self, signed_report: bytes) -> str:
        """Read the unverified JWS header to extract the Key ID. This will be
        used to find the appropriate public key for verifying the report 
        signature.

        signed_report: A bytes object containing the signed report as a JWS 
                         object.

        Returns None if the 'kid' isn't present, otherwise return the 'kid' string.
        """
        header = jwt.get_unverified_header(signed_report)
        kid = header.get("kid", None)
        return kid

    def verify_signed_report(self, signed_report: bytes, pub_key: bytes) -> dict:
        """Verify the signed report using the provided public key.

        signed_report: A bytes object containing the signed report as a JWS 
                         object.
        pub_key:       A bytes object containing the public key used to verify
                         the signed report, which corresponds to the SRP's 'kid'.

        Returns a dictionary containing the decoded JSON short-form report 
        payload.
        """
        decoded = jwt.decode(signed_report,
                             pub_key,
                             algorithms=ALLOWED_JWA_ALGOS)
        return decoded
