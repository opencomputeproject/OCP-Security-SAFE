This repository contains an example implementation of the [Open Compute Project's](https://www.opencompute.org/) short-form report generator for [Vendor Security Reviews](https://drive.google.com/file/d/18m0q3ZFZarYJzZ5lOuPShyBKIx6QfGVA/view).

The short-form report is a JSON object which must be signed according to the JSON Web Signature ([RFC-7515](https://www.rfc-editor.org/rfc/rfc7515)) specification.

**NEW: CoRIM Format Support** - The library now also supports generating reports in CoRIM (Concise Reference Integrity Manifest) format using CBOR encoding, which complies with the OCP SAFE SFR CDDL schema. This provides a more compact binary format while maintaining full backward compatibility with existing JSON workflows.

# Installation

To install all dependencies, simply run:

```
pip install -r requirements.txt
```

# The API

The `example_gen_sign_verify.py` script demonstrates how to use the API exported by `OcpReportLib.py`, covering all use cases from report generation, to signing, and also the signature verification process.

## New CoRIM Methods

In addition to the existing JSON methods, the following new methods are available for CoRIM format:

```python
# Generate CoRIM format
corim_dict = report.get_report_as_corim_dict()    # Returns CoRIM as Python dict
corim_cbor = report.get_report_as_corim_cbor()    # Returns CBOR-encoded bytes

# Sign CoRIM format (experimental)
report.sign_corim(private_key, "ES512", "key-id")  # COSE-Sign1 signing
signed_corim = report.get_signed_corim_report()    # Returns signed COSE
```

See `example_dual_format_generation.py` for a complete example of generating both JSON and CoRIM formats from the same data.

## Testing and Validation

The `tests/` directory contains comprehensive testing and validation scripts for both JSON and CoRIM formats:

- **Test Scripts**: Validate CoRIM generation and CDDL compliance
- **Analysis Tools**: Debug CBOR structure and schema issues  
- **Conversion Utilities**: Migrate existing JSON reports to CoRIM format

See `tests/README.md` for detailed information about running tests and validation tools.

## Integration With Workflows

### Report Generation (By Security Review Provider)

The Security Review Provider (SRP) should use `OcpReportLib.py` to generate the short-form report, by integrating it with their internal report generation apparatus. The `OcpReportLib.py` API is designed to be simple and flexible so as to not restrict how the SRP may choose to generate the report. It is designed to allow data to be easily imported from a variety of sources such as CSV files or REST APIs.

Use of the API is straight forward:

1. Call `add_device()` to add vendor and device-specific metadata to the report.
2. Call `add_audit()` to add audit details to the report.
3. Call `add_issue()` any number of times to add vulnerability details to the report.
4. Call `sign_report()` (or `sign_report_azure()`) to sign the JSON report.
5. **NEW:** Optionally call `get_report_as_corim_cbor()` and `sign_corim()` to generate CoRIM format.

When signing the report, the SRP must use an asymmetric signing key per those specified in the [Allowed Algorithms](#Allowed-Algorithms) section. [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault) support is included as an example of more sophisticated key management, however this Python package does not attempt to solve the key management problem in all possible ways, and we encourage SRPs to protect the private key as appropriate.

The SRP's public key and [Key ID](#Header-Fields), as well as the signed short-form report, will be shared with the OCP so that they can be published on the OCP website.

### Report Consumption (By OCP Members)

OCP members, such as cloud service providers, will be the primary consumers of these reports. Whenever an OCP member obtains a new firmware image from a vendor, they will pull the corresponding short-form report to decide whether the firmware image is safe to deploy into production.

1. The OCP member will extract the `kid` header field from the report, and use it to lookup the correct SRP public key.
2. The OCP member will then use the public key to verify the report's signature, using the `verify_signed_json_report()` API.
3. Once the report authenticity is proven, the firmware hash contained in the report (e.g., `fw_hash_sha2_384/512`) can be safely extracted.
4. This extracted hash can be compared to a locally-calculated hash of the vendor-provided firmware image.
5. If these hashes match, then the OCP member has now successfully verified that the firmware they wish to deploy has undergone a security audit.


# Format of the Short-Form Report

What follows is an example JSON payload for a hypothetical review of a typical binary firmware artifact:

```
{
    "review_framework_version": "1.0",
    "device": {
        "vendor": "ACME Inc",
        "product": "Roadrunner Trap",
        "category": "storage",
        "repo_tag": "release_v1_2_3",
        "fw_version": "1.2.3",
        "fw_hash_sha2_384": "0xcd484defa77e8c3e4a8dd73926e32365ea0dbd01e4eff017f211d4629cfcd8e4890dd66ab1bded9be865cd1c849800d4",
        "fw_hash_sha2_512": "0x84635baabc039a8c74aed163a8deceab8777fed32dc925a4a8dacfd478729a7b6ab1cb91d7d35b49e2bd007a80ae16f292be3ea2b9d9a88cb3cc8dff6a216988"
    },
    "audit": {
        "srp": "My Pentest Corporation",
        "methodology": "whitebox",
        "completion_date": "2023-06-25",
        "report_version": "1.2",
        "cvss_version": "3.1",
        "issues": [
            {
                "title": "Memory corruption when reading record from SPI flash",
                "cvss_score": "7.9",
                "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
                "cwe": "CWE-111",
                "description": "Due to insufficient input validation in the firmware, a local attacker who tampers with a configuration structure in SPI flash, can cause stack-based memory corruption.",
                "cve": null
            },
            {
                "title": "Debug commands enable arbitrary memory read/write",
                "cvss_score": "8.7",
                "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
                "cwe": "CWE-222",
                "description": "The firmware exposes debug command handlers that enable host-side drivers to read and write arbitrary regions of the device's SRAM.",
                "cve": "CVE-2014-10000"
            }
        ]
    }
}
```

This second example is an example JSON payload for a small SDK source code package and includes a manifest of file hashes:

```
{
    "review_framework_version": "1.1",
    "device": {
        "vendor": "ACME Inc",
        "product": "Roadrunner Trap",
        "category": "storage",
        "repo_tag": "release_v1_2_3",
        "fw_version": "1.2.3",
        "fw_hash_sha2_384": "848aff556097fc1eaf08253abd00af0aad0c317c3490e88bef09348658ce6e14829815fca075d9e03fcf236a47ff91dc",
        "fw_hash_sha2_512": "89142682f6d42edd356e4c3bdac3ae7d735ace1c2e058b04a2ac848a6b30238d52c9055f864c5306b12e784769e571de7fd1956437e10990cdbd928f17117662",
        "manifest": [
            {
                "file_name": "myapp/bin/myapp.elf",
                "file_hash": "b17acd5e84fb017ec305608a0a7d3998be6e464b9cbc1694a69aa9dbd2ccccc085562efdce9f5d36d28b4b4cd4dd7a958d9791a6a6b4e6ec87893781a4444643"
            },
            {
                "file_name": "myapp/inc/myapp.h",
                "file_hash": "b64cdd2a28a947a34db58d7317774c2caf2ec231ab3625a2aca3459f20a49fff856a12e977b5306677d35b2dbe3e1a793e508701df063e07e5de02a6890843cb"
            },
            {
                "file_name": "myapp/make.sh",
                "file_hash": "6d3311e93acd44690336aad7d4ff2947d5c6c6b4cfde728a3fa0770613e8a845c4e049337ee2614e6344809d2e36ec15544e44cfcaca2fafb85ae58cad2dd60e"
            },
            {
                "file_name": "myapp/src/myapp.c",
                "file_hash": "47385f4b7e2257896cf0d84ad0e84bf0a7150ee35667eb0f7ec0f2fc954cf10b0b963a90c67ba7d450d40a38190432079e9dd439ae75d987b56f67185c8ab5cb"
            }
        ]
    },
    "audit": {
        "srp": "My Pentest Corporation",
        "methodology": "whitebox",
        "completion_date": "2023-06-25",
        "report_version": "1.2",
        "scope_number": 1,
        "cvss_version": "3.1",
        "issues": [
            {
                "title": "Memory corruption when reading record from SPI flash",
                "cvss_score": "7.9",
                "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
                "cwe": "CWE-111",
                "description": "Due to insufficient input validation in the firmware, a local attacker who tampers with a configuration structure in SPI flash, can cause stack-based memory corruption.",
                "cve": null
            },
            {
                "title": "Debug commands enable arbitrary memory read/write",
                "cvss_score": "8.7",
                "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
                "cwe": "CWE-222",
                "description": "The firmware exposes debug command handlers that enable host-side drivers to read and write arbitrary regions of the device's SRAM.",
                "cve": "CVE-2014-10000"
            }
        ]
    }
}
```

These sample JSON reports and signed JWS can be found in this `samples/` folder in this repository.

## Payload Fields

The purpose of the various fields is explained below.

### `review_framework_version` field

This field is intended to match the version of the OCP [Vendor Security Review framework](https://drive.google.com/file/d/177hRzP05xE5OlvW7nuBH35SxaBSo1TRI/view). Currently this is version "`1.1`".

### `device` fields

A collection of fields that describe the vendor, device, and firmware version that was audited by a SRP.

* `vendor`: The name of the vendor that manufactured the device or firmware being tested.
* `product`: The name of the device. Usually a model name of number.
* `category`: The type of device that was audited. Usually a short string such as: `storage`, `network`, `gpu`, `cpu`, `apu`, or `bmc`.
* `repo_tag`: If applicable, the report can include the repository tag for the code that was audited. This may also be useful for ROM audits where the OCP Member is unable to verify the firmware hash.
* `fw_version`: The version of the firmware image that is attested by the signed short-form report. In most cases this will be the firmware version compiled by the vendor after the security audit completes, which contains fixes for all vulnerabilities that were found during the audit.
* `fw_hash_sha2_384`: A hex-encoded string containing the SHA2-384 hash of the firmware image. If the `manifest` field is present, it is a hash of that field instead.
* `fw_hash_sha2_512`: ... ditto, but using SHA2-512.
* `manifest`: A JSON list of filename and file hash pairs. This field is optional.

### `audit` fields

Several fields that describe the audit itself: Who delivered the audit, when the audit occured, what test methodology was followed, and so on.

* `srp`: The name of the Security Review Provider.
* `methodology`: The test methodology. Usually a short string like `whitebox` or `blackbox`.
* `completion_date`: When the security audit completed, in the `YYYY-MM-DD` format.
* `report_version`: Version of the report created by the SRP.
* `cvss_version`: Version of CVSS used to calculate scores for each issue. At present, we recommend CVSS version "`3.1`".

### `issues` list

This list of vulnerabilities that were **not fixed** by the device vendor before the firmware image was shipped. This list may be empty if the SRP found no vulnerabilities during the course of the security review.

* `title`: A brief summary of the issue. Usually taken directly from the SRP's audit report.
* `cvss_score`: The CVSS base score, represented as a string, such as "`7.1`".
* `cvss_vector`: The CVSS base vector. Temporal and environmental metrics are not used or tracked.
* `cwe`: The CWE identifier for the vulnerability, for example "`CWE-123`".
* `description`: A one or two sentence description of the issue. All device vendor sensitive information should be redacted.
* `cve`: This field is optional, as not all reported issues will be assigned a CVE number.


## Header Fields

* `alg`: The algorithm used to sign the report. Refer to the [Allowed Algorithms](#Allowed-Algorithms) section for more information.
* `kid`: The signed JWS object will make use of the [Key ID](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4) header parameter. This will be used by consumers of the short-form reports to ensure that they select the correct public key when verifying the signed report. The inclusion of this parameter is an acknowledgement that multiple SRPs will be chosen by the OCP for performing Vendor Security Reviews, and each SRP will use its own unique signing key.


# Allowed Algorithms

Certain limitations are placed on which algorithms are allowed to be used in this scheme. These requirements are listed below.

## Hashing of Firmware Images

Firmware images will be hashed using multiple algorithms to offer greater flexibility for OCP Members who consume these short-form reports. The required algorithms are:

* SHA2-384
* SHA2-512

## Signing the Short Form Report

When signing a short-form report, only the following JSON Web Algorithms ([RFC-7518](https://www.rfc-editor.org/rfc/rfc7518)) are allowed:

* PS384 - RSASSA-PSS using SHA-384 and MGF1 with SHA-384
* PS512 - RSASSA-PSS using SHA-512 and MGF1 with SHA-512
* ES384 - ECDSA using P-384 and SHA-384 (secp384r1: NIST/SECG curve over a 384 bit prime field)
* ES512 - ECDSA using P-521 and SHA-512 (secp521r1: NIST/SECG curve over a 521 bit prime field)

Note above that the RSA-PSS algorithms "PS384" and "PS512" are named after the hash-size, not the key-size. Although the JWA specification encourages key sizes of [2048 bits or larger](https://www.rfc-editor.org/rfc/rfc7518#section-3.5), we take a stricter stance, and allow only the following key-sizes:

* 3072 bits (384 bytes)
* 4096 bits (512 bytes)

