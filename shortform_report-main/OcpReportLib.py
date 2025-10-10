"""
A library for generating Security Review Short-Form Reports (SFR) in both JSON and CoRIM formats.

This script is intended to be used by Security Review Providers who are
participating in the Open Compute Project's Firmware Security Review Framework.
The script complies with version 0.3 (draft) of the Security Review Framework
document and supports the new CoRIM (CBOR) format.

More details about the OCP review framework can be found here:
*  https://www.opencompute.org/wiki/Security

For example usage of this script, refer to the following:
  * example_gen_sign_verify.py:
      Demonstrates how to generate, sign and verify reports in legacy JSON format.
  * example_dual_format_generation.py
      Demonstrates how to generate, sign and verify reports in both formats.
  * samples/*
      Example reports that were created by this library

Author: Jeremy Boone, NCC Group (original),
        Alex Tzonkov, AMD and Rob Wood, Tetrel Security (Extended for CoRIM support)
Date  : June 5th, 2023 (original)
        October 2025 (CoRIM extension)
"""

import time
import json
import jwt
import base64
import hashlib
import cbor2
import cwt
import logging
import prettyprinter
from datetime import datetime
from typing import Dict, List, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicNumbers,
    SECP521R1,
)

from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

# Only the following JSON Web Algorithms (JWA) will be accepted by this script
# for signing the short-form report. Refer to RFC7518 for more details.
ALLOWED_JWA_RSA_ALGOS = (
    "PS384",  # RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    "PS512",  # RSASSA-PSS using SHA-512 and MGF1 with SHA-512
)
ALLOWED_JWA_ECDSA_ALGOS = (
    "ES384",  # ECDSA using P-384 and SHA-384
    "ES512",  # ECDSA using P-521 and SHA-512
)
ALLOWED_JWA_ALGOS = ALLOWED_JWA_RSA_ALGOS + ALLOWED_JWA_ECDSA_ALGOS

# Only the following RSA key sizes (in bits) will be accepted by this script for
# signing a short-form report.
ALLOWED_RSA_KEY_SIZES = (
    3072,  # RSA 384
    4096,  # RSA 512
)

# CoRIM specific constants
DEVICE_CATEGORIES = {"storage": 0, "network": 1, "gpu": 2, "cpu": 3, "apu": 4, "bmc": 5}

# CBOR tags for CoRIM
CORIM_TAG = 501
COMID_TAG = 506

# OCP SAFE SFR Profile OID: 1.3.6.1.4.1.42623.1.1
# DER encoded OID bytes
OCP_SAFE_SFR_PROFILE_OID = bytes.fromhex("060A2B0601040182F4170101")


# Define the custom pretty-print function for CBORTag
@prettyprinter.register_pretty(cbor2.CBORTag)
def pretty_cbor_tag(value, ctx):
    """
    Pretty-prints a cbor2.CBORTag object using the modern prettyprinter API.
    """
    if isinstance(value.value, bytes):
        try:
            # attempt to handle a bytes object as a nested CBORTag
            c = cbor2.loads(value.value)
        except Exception:
            c = value.value
    else:
        c = value.value
    return prettyprinter.pretty_call(ctx, cbor2.CBORTag, (value.tag, c))


class AzureKeyVaultSigner(cwt.Signer):
    """
    A custom Signer class that uses Azure Key Vault for the actual signing
    operation, adhering to the required interface of the python-cwt library.
    """

    def __init__(self, vault: str, kid: str, debug: bool = False):
        self._signature_value = ""
        super().__init__(
            cose_key=None, protected=None, unprotected={4: kid.encode("utf-8")}
        )
        if not debug:
            logger = logging.getLogger("azure")
            logger.setLevel(logging.ERROR)

        credential = DefaultAzureCredential(logging_enable=debug)
        key_client = KeyClient(vault_url=vault, credential=credential)
        key = key_client.get_key(kid)
        self.crypto_client = CryptographyClient(key, credential=credential)

        if key.key.crv != "P-521":
            print(f"Key must be a P-521 key, but is actually a {key.key.crv}.")
            raise Exception("unsupported algorithm.")

    def sign(self, message: bytes) -> bytes:
        """
        Calculates the message hash and delegates the signing operation to Azure Key Vault.
        """
        digest = hashlib.sha512(message).digest()

        # Call Azure Key Vault to sign the digest
        try:
            self._signature_value = self.crypto_client.sign(
                SignatureAlgorithm.es512, digest
            ).signature
            return self._signature_value
        except Exception as e:
            raise Exception(f"Failed to sign using Azure Key Vault: {e}")

    @property
    def signature(self):
        return self._signature_value


class ShortFormReport(object):
    def __init__(self, framework_ver: str = "1.1"):
        self.report = {}
        self.report["review_framework_version"] = f"{framework_ver}".strip()
        self.signed_json_report = None
        self.signed_corim_report = None

    def add_device(
        self,
        vendor: str,
        product: str,
        category: str,
        repo_tag: str,
        fw_ver: str,
        fw_hash_sha384: str,
        fw_hash_sha512: str,
        manifest: str = None,
    ) -> None:
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
                        the firmware image. If the `manifest` field is present,
                        this is a hash of that field instead.
        fw_hash_sha512: ... ditto but using SHA2-512 ...
        manifest:  A JSON list of filename and file hash pairs. This field is optional.
        """
        self.report["device"] = {}
        self.report["device"]["vendor"] = f"{vendor}".strip()
        self.report["device"]["product"] = f"{product}".strip()
        self.report["device"]["category"] = f"{category}".strip()
        self.report["device"]["repo_tag"] = f"{repo_tag}".strip()
        self.report["device"]["fw_version"] = f"{fw_ver}".strip()
        self.report["device"]["fw_hash_sha2_384"] = f"{fw_hash_sha384}".strip()
        self.report["device"]["fw_hash_sha2_512"] = f"{fw_hash_sha512}".strip()
        if manifest is not None:
            self.report["device"]["manifest"] = manifest

    def add_audit(
        self,
        srp: str,
        methodology: str,
        date: str,
        report_ver: str,
        scope_number: int,
        cvss_ver: str = "3.1",
    ) -> None:
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

    def add_issue(
        self,
        title: str,
        cvss_score: str,
        cvss_vec: str,
        cwe: str,
        description: str,
        cve=None,
    ) -> None:
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
        """Returns the short-form report as a Python dict."""
        return self.report

    def get_json_report_as_str(self) -> str:
        """Return the short-form report as a formatted and indented string."""
        return json.dumps(self.get_report_as_dict(), indent=4)

    def print_json_report(self) -> None:
        """Pretty-prints the short-form report"""
        print(self.get_report_as_str())

    ###########################################################################
    # APIs for creating the CoRIM CBOR format methods
    ###########################################################################

    def _convert_to_corim_structure(self) -> Dict[str, Any]:
        """Convert internal JSON structure to CoRIM structure."""
        if "audit" not in self.report or "device" not in self.report:
            raise ValueError("Report must have both device and audit information")

        # Parse completion date to Unix timestamp with CBOR tag 1
        date_str = self.report["audit"]["completion_date"]
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            completion_timestamp = cbor2.CBORTag(1, int(dt.timestamp()))
        except ValueError:
            raise ValueError(f"Invalid date format: {date_str}. Expected YYYY-MM-DD")

        # Build fw-identifier structure
        fw_identifiers = []
        fw_id = {}

        # Add version information
        if self.report["device"]["fw_version"]:
            fw_id[0] = {  # fw-version
                0: self.report["device"]["fw_version"],  # version
                1: "semver",  # version-scheme (default)
            }

        # Add digests
        digests = self._get_fw_digests()
        if digests:
            fw_id[1] = digests  # fw-file-digests

        # Add repo tag
        if self.report["device"]["repo_tag"]:
            fw_id[2] = self.report["device"]["repo_tag"]  # repo-tag

        # Add manifest if present
        if "manifest" in self.report["device"]:
            manifest_entries = []
            for entry in self.report["device"]["manifest"]:
                manifest_entries.append(
                    {
                        0: entry["file_name"],  # filename
                        # file-hash (assuming SHA-512)
                        1: [[-44, bytes.fromhex(entry["file_hash"])]],
                    }
                )

            # Calculate manifest digest
            manifest_str = json.dumps(
                self.report["device"]["manifest"],
                sort_keys=False,
                separators=(",", ":"),
            ).encode("utf-8")
            manifest_digest = hashlib.sha512(manifest_str).digest()

            fw_id[3] = {  # src-manifest
                0: [[-44, manifest_digest]],  # manifest-digest
                1: manifest_entries,  # manifest
            }

        fw_identifiers.append(fw_id)

        # Convert device category to integer
        category_str = self.report["device"]["category"].lower()
        device_category = None
        for cat, val in DEVICE_CATEGORIES.items():
            if cat in category_str:
                device_category = val
                break

        # Convert issues
        corim_issues = []
        for issue in self.report["audit"]["issues"]:
            corim_issue = {
                0: issue["title"],  # title
                1: issue["cvss_score"],  # cvss-score
                2: issue["cvss_vector"],  # cvss-vector
                3: issue["cwe"],  # cwe
                4: issue["description"],  # description
            }

            # Add optional fields
            if "cvss_version" in self.report["audit"]:
                # cvss-version
                corim_issue[5] = self.report["audit"]["cvss_version"]

            if issue.get("cve"):
                corim_issue[6] = issue["cve"]  # cve

            corim_issues.append(corim_issue)

        # Build the ocp-safe-sfr-map
        sfr_map = {
            # review-framework-version
            0: self.report["review_framework_version"],
            1: self.report["audit"]["report_version"],  # report-version
            2: completion_timestamp,  # completion-date
            3: self.report["audit"]["scope_number"],  # scope-number
            4: fw_identifiers,  # fw-identifiers
        }

        if device_category is not None:
            sfr_map[5] = device_category  # device-category

        if corim_issues:
            sfr_map[6] = corim_issues  # issues

        return sfr_map

    def _build_corim_structure(self, sfr_map: Dict[str, Any]) -> Dict[str, Any]:
        """Build the complete CoRIM structure with embedded SFR data."""

        # Create the measurement-values-map with SFR extension
        measurement_values = {
            -1: sfr_map  # ocp-safe-sfr extension
        }

        # Create measurement-map for endorsement
        endorsement_measurement_map = {
            1: measurement_values  # mval
        }

        # Create measurement-map for conditions (with digests)
        condition_measurement_map = {
            1: {  # mval
                2: self._get_fw_digests()  # digests
            }
        }

        # Create endorsed-triple-record
        endorsed_triple = [
            # environment-map
            {
                0: {  # class
                    1: self.report["device"]["vendor"],  # vendor
                    2: self.report["device"]["product"],  # model
                }
            },
            # endorsement (array of measurement-map)
            [endorsement_measurement_map],
        ]

        # Create stateful-environment-record for conditions
        stateful_environment = [
            # environment-map
            {
                0: {  # class
                    1: self.report["device"]["vendor"],  # vendor
                    2: self.report["device"]["product"],  # model
                }
            },
            # claims-list (measurement-map array)
            [condition_measurement_map],
        ]

        # Create conditional-endorsement-triple-record
        conditional_endorsement = [
            # conditions (stateful-environment-record array)
            [stateful_environment],
            # endorsements (endorsed-triple-record array)
            [endorsed_triple],
        ]

        # Create concise-mid-tag
        comid = {
            1: {  # tag-identity
                # tag-id
                0: f"{self.report['device']['vendor'].lower().replace(' ', '-')}-review-comid-001"
            },
            4: {  # triples
                # conditional-endorsement-triples
                10: [conditional_endorsement]
            },
        }

        # Create the main CoRIM structure
        corim = {
            0: f"sfr-corim-{int(time.time())}",  # id
            1: [cbor2.CBORTag(COMID_TAG, cbor2.dumps(comid))],  # tags
            3: cbor2.CBORTag(
                111, OCP_SAFE_SFR_PROFILE_OID
            ),  # profile: OID 1.3.6.1.4.1.42623.1.1
            5: [  # entities
                {
                    0: self.report["audit"]["srp"],  # entity-name
                    2: [1],  # role: manifest-creator
                }
            ],
        }

        return corim

    def _get_fw_digests(self) -> List[List]:
        """Get firmware digests in CoRIM format."""
        digests = []
        if self.report["device"]["fw_hash_sha2_384"]:
            digests.append(
                [-43, bytes.fromhex(self.report["device"]["fw_hash_sha2_384"])]
            )
        if self.report["device"]["fw_hash_sha2_512"]:
            digests.append(
                [-44, bytes.fromhex(self.report["device"]["fw_hash_sha2_512"])]
            )
        return digests

    def get_report_as_corim_dict(self) -> Dict[str, Any]:
        """Returns the report as a CoRIM-structured dictionary."""
        sfr_map = self._convert_to_corim_structure()
        return self._build_corim_structure(sfr_map)

    def get_report_as_corim_cbor(self) -> bytes:
        """Returns the report as CBOR-encoded CoRIM bytes."""
        corim_dict = self.get_report_as_corim_dict()
        tagged_corim = cbor2.CBORTag(CORIM_TAG, corim_dict)
        return cbor2.dumps(tagged_corim)

    def get_corim_report_as_str(self) -> str:
        """return the report as human-readable CBOR diagnostic notation."""
        c = cbor2.loads(self.get_report_as_corim_cbor())
        return prettyprinter.pformat(c)

    def print_corim_report(self) -> None:
        """Pretty-prints the short-form report"""
        print(self.get_corim_report_as_str())

    ###########################################################################
    # APIs for signing the report
    ###########################################################################

    def get_signed_json_report(self) -> bytes:
        """Returns the signed short form report (a JWS) as a bytes object. May
        return a 'None' object if the report hasn't been signed yet.
        """
        return self.signed_json_report

    def sign_json_report_pem(self, priv_key: bytes, algo: str, kid: str) -> bool:
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
        pem = serialization.load_pem_private_key(
            priv_key, None, backend=default_backend()
        )

        # Ensure the correct private key types are passed
        if not isinstance(pem, (RSAPrivateKey, EllipticCurvePrivateKey)):
            print(
                "Expected 'priv_key' to be a 'RSAPrivateKey' or 'EllipticCurvePrivateKey'"
            )
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
                print(
                    f"RSA key is too small: {pem.key_size}, must be one of: {
                        ALLOWED_RSA_KEY_SIZES
                    }"
                )
                return False

        # Ensure the provided private key corresponds with the specified algo parameter.
        if (
            ((algo == "PS384") and (pem.key_size != 3072))
            or ((algo == "PS512") and (pem.key_size != 4096))
            or ((algo == "ES384") and (pem.key_size != 384))
            or ((algo == "ES512") and (pem.key_size != 521))
        ):
            print(f"Mismatch between algo={algo} and private key size: {pem.key_size}")
            return False

        # Set the JWS headers
        jws_headers = {"kid": f"{kid}"}

        # Finally, we can sign the short-form report.
        self.signed_json_report = jwt.encode(
            self.get_report_as_dict(), key=priv_key, algorithm=algo, headers=jws_headers
        )
        return True

    def sign_json_report_azure(self, vault: str, kid: str, debug: bool = False) -> bool:
        """Sign the JSON object to make a JSON Web Signature. Refer to RFC7515
        for additional details of the JWS specification.

        This uses an Azure Key Vault key for signing. Login must be performed
        using the Azure CLI (i.e., `az login`) before running this function.

        Only P-521 keys are supported currently. Any other key type will fail.

        vault:    The Azure Key Vault URL to use.
        kid:      The Key ID to be included in the JWS header. This field will
                    be used to uniquely identify the unique SRP key that was used
                    to sign the report. It also is used as the key name in Azure.

        Returns True on success, and False on failure.
        """

        if not debug:
            logger = logging.getLogger("azure")
            logger.setLevel(logging.ERROR)
        credential = DefaultAzureCredential(logging_enable=debug)
        key_client = KeyClient(vault_url=vault, credential=credential)
        key = key_client.get_key(kid)
        crypto_client = CryptographyClient(key, credential=credential)

        if key.key.crv != "P-521":
            print(f"Key must be a P-521 key, but is actually a {key.key.crv}.")
            return False

        jwt_payload = self.get_report_as_dict()
        jwt_payload["iat"] = round(time.time())
        jwt_headers = {"kid": f"{kid}", "alg": "ES512", "typ": "jwt"}

        token_components = {
            "header": base64.urlsafe_b64encode(json.dumps(jwt_headers).encode())
            .decode()
            .rstrip("="),
            "payload": base64.urlsafe_b64encode(json.dumps(jwt_payload).encode())
            .decode()
            .rstrip("="),
        }
        to_sign = f"{token_components.get('header')}.{token_components.get('payload')}"
        digest = hashlib.sha512(to_sign.encode()).digest()
        result = crypto_client.sign(SignatureAlgorithm.es512, digest)
        token_components["signature"] = (
            base64.urlsafe_b64encode(result.signature).decode().rstrip("=")
        )
        self.signed_json_report = f"{token_components.get('header')}.{
            token_components.get('payload')
        }.{token_components['signature']}"

        return True

    def get_signed_corim_report(self) -> bytes:
        """Returns the signed CoRIM report (COSE-Sign1)."""
        return self.signed_corim_report

    def _sign_corim_report_internal(self, signer) -> bool:
        """Sign the CoRIM report using COSE-Sign1 with the cwt library.

        Uses the cwt (CBOR Web Token) library for better COSE compatibility.
        do not call directly, use either sign_corim_report_pem() or sign_corim_report_azure()
        which provide appropriate signer modules.
        """
        # Get CoRIM payload as claims (cwt expects claims, not raw payload)
        corim_cbor = self.get_report_as_corim_cbor()

        # For COSE signing, we need to create claims structure
        # The CoRIM data becomes the payload claim
        claims = {
            # Use a custom claim number for CoRIM data
            -65537: corim_cbor  # Custom claim for CoRIM payload
        }

        # Sign using cwt library with the signer
        signed_corim_report = cwt.encode_and_sign(
            claims=claims,
            signers=[signer],
            tagged=True,  # Use CBOR tag for COSE_Sign1
        )

        self.signed_corim_report = signed_corim_report
        return True

    def sign_corim_report_pem(self, priv_key: bytes, algo: str, kid: str) -> bool:
        """Sign the CoRIM report using COSE-Sign1 with the cwt library.

        Uses the cwt (CBOR Web Token) library for better COSE compatibility.
        """
        try:
            # Load private key using cryptography
            pem = serialization.load_pem_private_key(
                priv_key, None, backend=default_backend()
            )

            # Map algorithm to COSE algorithm identifier
            cose_alg = None
            if (
                algo == "ES512"
                and isinstance(pem, EllipticCurvePrivateKey)
                and pem.curve.name == "secp521r1"
            ):
                cose_alg = -36  # ES512
            elif (
                algo == "ES384"
                and isinstance(pem, EllipticCurvePrivateKey)
                and pem.curve.name == "secp384r1"
            ):
                cose_alg = -35  # ES384
            elif algo == "PS512" and isinstance(pem, RSAPrivateKey):
                cose_alg = -38  # PS512
            elif algo == "PS384" and isinstance(pem, RSAPrivateKey):
                cose_alg = -37  # PS384
            else:
                print(f"Unsupported algorithm/key combination: {algo} with {type(pem)}")
                return False

            # Create Signer using cwt library
            signer = cwt.Signer.from_pem(priv_key, alg=cose_alg, kid=kid)

            # sign and return result
            return self._sign_corim_report_internal(signer)

        except Exception as e:
            print(f"Error signing CoRIM with cwt: {e}")
            return False

    def sign_corim_report_azure(self, vault: str, kid: str) -> bool:
        """Sign the CoRIM report using COSE-Sign1 with the cwt library.

        Uses the cwt (CBOR Web Token) library for better COSE compatibility.

        This uses an Azure Key Vault key for signing. Login must be performed
        using the Azure CLI (i.e., `az login`) before running this function.

        Only P-521 keys are supported currently. Any other key type will fail.

        vault:    The Azure Key Vault URL to use.
        kid:      The Key ID to be included in the JWS header. This field will
                    be used to uniquely identify the unique SRP key that was used
                    to sign the report. It also is used as the key name in Azure.

        Returns True on success, and False on failure.
        """
        try:
            # Create Signer using Azure KeyVault
            signer = AzureKeyVaultSigner(vault=vault, kid=kid)

            # sign and return result
            return self._sign_corim_report_internal(signer)

        except Exception as e:
            print(f"Error signing CoRIM with cwt/azure: {e}")
            return False

    ###########################################################################
    # APIs for verifying a signed report
    ###########################################################################

    def get_signed_json_report_kid(self, signed_json_report: bytes) -> str:
        """Read the unverified JWS header to extract the Key ID. This will be
        used to find the appropriate public key for verifying the report
        signature.

        signed_json_report: A bytes object containing the signed report as a JWS
                         object.

        Returns None if the 'kid' isn't present, otherwise return the 'kid' string.
        """
        header = jwt.get_unverified_header(signed_json_report)
        kid = header.get("kid", None)
        return kid

    def verify_signed_json_report(
        self, signed_json_report: bytes, pub_key: bytes
    ) -> dict:
        """Verify the signed report using the provided public key.

        signed_json_report: A bytes object containing the signed report as a JWS
                         object.
        pub_key:       A bytes object containing the public key used to verify
                         the signed report, which corresponds to the SRP's 'kid'.

        Returns a dictionary containing the decoded JSON short-form report
        payload.
        """
        decoded = jwt.decode(signed_json_report, pub_key, algorithms=ALLOWED_JWA_ALGOS)

        # verify additional contents of the report
        if self.verify_json_report_contents(decoded) is not True:
            raise Exception("JSON report contents failed to validate!")

        return decoded

    def verify_signed_corim_report(
        self, signed_corim_report: bytes, pub_key: bytes, kid: str
    ) -> bool:
        """Verify the signed report using the provided public key.

        signed_corim_report: A bytes object containing the signed report as a CoRIM CBOR object.
        pub_key:       A bytes object containing the public key used to verify the signed report, which corresponds to the SRP's 'kid'.

        Returns a dictionary containing the decoded short-form report payload.
        """
        try:
            cwt.decode(
                data=signed_corim_report,
                keys=cwt.COSEKey.from_pem(pub_key, alg=-36, kid=kid),
            )  # alg -36 is ES512
            return True

        except Exception as e:
            raise Exception(f"CBOR report contents failed to validate! {e}")

    def get_public_key_azure(self, vault, kid, debug: bool = False):
        """Get the public key of an Azure KeyVault key.

        vault:    The Azure Key Vault URL to use.
        kid:      The Azure key name to use.

        Returns the public key in PEM format.
        """
        if not debug:
            logger = logging.getLogger("azure")
            logger.setLevel(logging.ERROR)
        credential = DefaultAzureCredential(logging_enable=debug)
        key_client = KeyClient(vault_url=vault, credential=credential)
        key = key_client.get_key(kid)
        pub = EllipticCurvePublicNumbers(
            int.from_bytes(key.key.x, byteorder="big"),
            int.from_bytes(key.key.y, byteorder="big"),
            SECP521R1(),
        ).public_key()
        return pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def verify_signed_json_report_azure(
        self, signed_json_report: bytes, vault: str, kid: str, debug: bool = False
    ) -> dict:
        """Verify the signed report using an Azure KeyVault key.

        vault:    The Azure Key Vault URL to use.
        kid:      The Azure key name to use.
        signed_json_report: A bytes object containing the signed report as a JWS
                         object.

        Returns a dictionary containing the decoded JSON short-form report
        payload.
        """
        pubkey = self.get_public_key_azure(vault, kid, debug)
        decoded = jwt.decode(signed_json_report, pubkey, algorithms=ALLOWED_JWA_ALGOS)

        # verify additional contents of the report
        if self.verify_json_report_contents(decoded) is not True:
            raise Exception("Report contents failed to validate!")

        return decoded

    def verify_json_report_contents(self, decoded: dict) -> bool:
        """Verify the contents of the report wherever possible.

        decoded:  A SFR report, decoded, with its signature assumed to have already been validated.

        Returns True on success
        """

        # At least one of the hashes must be present for this JSON to be valid.
        if (
            "fw_hash_sha2_384" not in decoded["device"]
            or len(decoded["device"]["fw_hash_sha2_384"]) == 0
        ) and (
            "fw_hash_sha2_512" not in decoded["device"]
            or len(decoded["device"]["fw_hash_sha2_512"]) == 0
        ):
            # Suppress this error for the one report that has no hash:
            # https://github.com/opencomputeproject/OCP-Security-SAFE/blob/main/Reports/CHIPS_Alliance/2023/Caliptra
            if decoded["device"]["repo_tag"] != "release_v20231014_0":
                print("Neither fw_hash_sha2 is present!")
                return False

        # Validate hash lengths are correct
        if (
            "fw_hash_sha2_384" in decoded["device"]
            and len(decoded["device"]["fw_hash_sha2_384"])
            != hashlib.sha384().digest_size * 2
            and len(decoded["device"]["fw_hash_sha2_384"]) != 0
        ):
            l3 = len(decoded["device"]["fw_hash_sha2_384"])
            print(
                f"fw_hash_sha2_384 hash digest length must be {
                    hashlib.sha384().digest_size * 2
                } (found {l3})!"
            )
            return False
        if (
            "fw_hash_sha2_512" in decoded["device"]
            and len(decoded["device"]["fw_hash_sha2_512"])
            != hashlib.sha512().digest_size * 2
            and len(decoded["device"]["fw_hash_sha2_512"]) != 0
        ):
            l5 = len(decoded["device"]["fw_hash_sha2_512"])
            print(
                f"fw_hash_sha2_512 hash digest length must be {
                    hashlib.sha512().digest_size * 2
                } (found {l5})!"
            )
            return False

        # if there is a manifest list, then validate its hash(es)
        if "manifest" in decoded["device"]:
            # be as explicit about the JSON formatting as possible
            m_str = json.dumps(
                decoded["device"]["manifest"], sort_keys=False, separators=(",", ":")
            ).encode("utf-8")
            fw_hash_sha384 = hashlib.sha384(m_str, usedforsecurity=True).hexdigest()
            fw_hash_sha512 = hashlib.sha512(m_str, usedforsecurity=True).hexdigest()

            if (
                "fw_hash_sha2_384" in decoded["device"]
                and decoded["device"]["fw_hash_sha2_384"] != fw_hash_sha384
            ):
                print("fw_hash_sha2_384 does not match manifest's hash!")
                return False

            if (
                "fw_hash_sha2_512" in decoded["device"]
                and decoded["device"]["fw_hash_sha2_512"] != fw_hash_sha512
            ):
                print("fw_hash_sha2_512 does not match manifest's hash!")
                return False

        return True
