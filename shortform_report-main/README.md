This repository contains an example implementation of the [Open Compute Project's](https://www.opencompute.org/) short-form report generator for [Vendor Security Reviews](https://drive.google.com/file/d/18m0q3ZFZarYJzZ5lOuPShyBKIx6QfGVA/view).

The short-form report is a JSON object which must be signed according to the JSON Web Signature ([RFC-7515](https://www.rfc-editor.org/rfc/rfc7515)) specification. 


# Installation

To install all dependencies, simply run:

```
pip install -r requirements.txt
```

# The API

The `example_gen_sign_verify.py` script demonstrates how to use the API exported by `OcpReportLib.py`, covering all use cases from report generation, to signing, and also the signature verification process.


## Integration With Workflows

### Report Generation (By Security Review Provider)

The Security Review Provider (SRP) should use `OcpReportLib.py` to generate the short-form report, by integrating it with their internal report generation apparatus. The `OcpReportLib.py` API is designed to be simple and flexible so as to not restrict how the SRP may choose to generate the report. It is designed to allow data to be easily imported from a variety of sources such as CSV files or REST APIs.

Use of the API is straight forward:
1. Call `add_device()` to add vendor and device-specific metadata to the report.
2. Call `add_audit()` to add audit details to the report.
3. Call `add_issue()` any number of times to add vulnerability details to the report.
4. Call `sign_report()` to sign the JSON report.

When signing the report, the SRP must use an asymmetric signing key per those specified in the [Allowed Algorithms](#Allowed-Algorithms) section. This Python package does not attempt to solve the key management problem, and we encourage SRPs to protect the private key as appropriate.

The SRP's public key and [Key ID](#Header-Fields), as well as the signed short-form report, will be shared with the OCP so that they can be published on the OCP website.

### Report Consumption (By OCP Members)

OCP members, such as cloud service providers, will be the primary consumers of these reports. Whenever an OCP member obtains a new firmware image from a vendor, they will pull the corresponding short-form report to decide whether the firmware image is safe to deploy into production. 

1. The OCP member will extract the `kid` header field from the report, and use it to lookup the correct SRP public key.
2. The OCP member will then use the public key to verify the report's signature, using the `verify_signed_report()` API.
3. Once the report authenticity is proven, the firmware hash contained in the report (e.g., `fw_hash_sha2_384/512`) can be safely extracted.
4. This extracted hash can be compared to a locally-calculated hash of the vendor-provided firmware image. 
5. If these hashes match, then the OCP member has now successfully verified that the firmware they wish to deploy has undergone a security audit.


# Format of the Short-Form Report

What follows is an example JSON payload for a hypothetical review:

```
{
    "review_framework_version": "0.2",
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

A sample JSON report and signed JWS can be found in this `samples/` folder in this repository.

## Payload Fields

The purpose of the various fields is explained below.

### `review_framework_version` field

This field is intended to match the version of the OCP [Vendor Security Review framework](https://drive.google.com/file/d/177hRzP05xE5OlvW7nuBH35SxaBSo1TRI/view). Currently this is version "`0.2`".

### `device` fields

A collection of fields that describe the vendor, device, and firmware version that was audited by a SRP.

* `vendor`: The name of the vendor that manufactured the device or firmware being tested.
* `product`: The name of the device. Usually a model name of number.
* `category`: The type of device that was audited. Usually a short string such as: `storage`, `network`, `gpu`, `cpu`, `apu`, or `bmc`.
* `repo_tag`: If applicable, the report can include the repository tag for the code that was audited. This may also be useful for ROM audits where the OCP Member is unable to verify the firmware hash.
* `fw_version`: The version of the firmware image that is attested by the signed short-form report. In most cases this will be the firmware version compiled by the vendor after the security audit completes, which contains fixes for all vulnerabilities that were found during the audit.
* `fw_hash_sha2_384`: A hex-encoded string containing the SHA2-384 hash of the firmware image. Should be prefixed with "`0x`".
* `fw_hash_sha2_512`: ... ditto, but using SHA2-512.

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


