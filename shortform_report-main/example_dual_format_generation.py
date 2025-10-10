"""
Example script demonstrating dual-format SFR generation (JSON and CoRIM).

This script shows how to use the ExtendedShortFormReport class to generate
Security Findings Reports in both the original JSON format and the new
CoRIM (CBOR) format that complies with the OCP SAFE SFR CDDL schema.

Author: Extended from Jeremy Boone's original example
Date  : January 2025
"""

from OcpReportLib import ShortFormReport
import traceback
import sys
import json
import hashlib
import os

# Test key configuration (same as original example)
MY_PRIV_KEY = "testkey_p521.pem"
MY_PUB_KEY = "testkey_ecdsa_p521.pub"
MY_SIGN_ALGO = "ES512"
MY_KID = "Wile E Coyote"

MY_VAULT = "https://MYVAULT.vault.azure.net/"
MY_KID_AZURE = "srp-ocp-key"
MY_PUB_KEY_AZURE = "testkey_ecdsa_p521.pub"


def generate_test_keys():
    """Generate test keys if they don't exist."""
    if not os.path.exists(MY_PRIV_KEY):
        print("Generating test ECDSA P-521 key pair...")
        os.system(
            f"openssl ecparam -name secp521r1 -genkey -noout -out {MY_PRIV_KEY}")
        os.system(f"openssl ec -in {MY_PRIV_KEY} -pubout -out {MY_PUB_KEY}")
        print(f"Generated {MY_PRIV_KEY} and {MY_PUB_KEY}")


def main():
    print("=== OCP SAFE SFR Dual-Format Generation Example ===\n")

    # Generate test keys if needed
    generate_test_keys()

    # Create the report object
    rep = ShortFormReport(framework_ver="1.1")

    # Add device information (same API as original SFR generation library)
    fw_hash_sha384 = "cd484defa77e8c3e4a8dd73926e32365ea0dbd01e4eff017f211d4629cfcd8e4890dd66ab1bded9be865cd1c849800d4"
    fw_hash_sha512 = "84635baabc039a8c74aed163a8deceab8777fed32dc925a4a8dacfd478729a7b6ab1cb91d7d35b49e2bd007a80ae16f292be3ea2b9d9a88cb3cc8dff6a216988"

    rep.add_device(
        "ACME Inc",         # vendor name
        "Roadrunner Trap",  # product name
        "storage",          # device category
        "release_v1_2_3",   # repo tag
        "1.2.3",            # firmware version
        fw_hash_sha384,     # SHA-384 hash
        fw_hash_sha512      # SHA-512 hash
    )

    # Add audit information
    rep.add_audit(
        "My Pentest Corporation",  # SRP name
        "whitebox",               # Test methodology
        "2023-06-25",            # Test completion date
        "1.2",                   # Report version
        1,                       # The OCP SAFE scope level
    )

    # Add security issues
    rep.add_issue(
        "Memory corruption when reading record from SPI flash",
        "7.9",
        "AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
        "CWE-111",
        "Due to insufficient input validation in the firmware, a local"
        " attacker who tampers with a configuration structure in"
        " SPI flash, can cause stack-based memory corruption."
    )

    rep.add_issue(
        "Debug commands enable arbitrary memory read/write",
        "8.7",
        "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
        "CWE-222",
        "The firmware exposes debug command handlers that enable host-side"
        " drivers to read and write arbitrary regions of the device's"
        " SRAM.",
        cve="CVE-2014-10000"
    )

    print("=== JSON FORMAT OUTPUT ===")
    print(rep.get_json_report_as_str())

    print("\n=== CoRIM FORMAT OUTPUT ===")
    generated_files = []
    try:
        corim_cbor = rep.get_report_as_corim_cbor()
        print(f"CoRIM CBOR bytes ({len(corim_cbor)} bytes):")
        print(corim_cbor.hex())

        print("\nCoRIM structure (Python dict):")
        txt = rep.get_corim_report_as_str()
        filename = "example_report_unsigned.cbor.txt"
        with open(filename, "w") as f:
            f.write(txt)
        print(f"\nCoRIM saved to: {filename}")
        generated_files.append(filename)

        # Save CoRIM to file
        filename = "example_report_unsigned.cbor"
        with open(filename, "wb") as f:
            f.write(corim_cbor)
        print(f"\nCoRIM saved to: {filename}")
        generated_files.append(filename)

    except Exception as e:
        print(f"Error generating CoRIM: {e}")
        traceback.print_exc()

    print("\n=== SIGNING DEMONSTRATION ===")

    # Load private key
    try:
        with open(MY_PRIV_KEY, "rb") as f:
            privkey = f.read()
    except FileNotFoundError:
        print(f"Private key file {
              MY_PRIV_KEY} not found. Please generate keys first.")
        return

    # Save JSON report (unsigned)
    print("Saving JSON report...")
    json_report = rep.get_json_report_as_str()
    filename = "example_report_unsigned.json"
    with open(filename, "w") as f:
        f.write(json_report)
    print(f"JSON report saved to: {filename}")
    generated_files.append(filename)

    # Sign JSON format (test keys)
    print("\nSigning JSON report...")
    success_j1 = rep.sign_json_report_pem(privkey, MY_SIGN_ALGO, MY_KID)
    if success_j1:
        signed_json1 = rep.get_signed_json_report()
        print(f"JSON JWS signature created ({len(signed_json1)} bytes)")

        # Save signed JSON
        filename = "example_report_signed_testkey.jws"
        with open(filename, "w") as f:
            f.write(signed_json1.decode() if isinstance(
                signed_json1, bytes) else signed_json1)
        print(f"Signed JSON saved to: {filename}")
        generated_files.append(filename)
    else:
        print("Failed to sign JSON report")

    # Sign JSON format (azure)
    print("\nSigning JSON report...")
    try:
        success_j2 = rep.sign_json_report_azure(MY_VAULT, MY_KID_AZURE)
    except:
        success_j2 = False
    if success_j2:
        signed_json2 = rep.get_signed_json_report()
        print(f"JSON JWS signature created ({len(signed_json2)} bytes)")

        # Save signed JSON
        filename = "example_report_signed_azurekey.jws"
        with open(filename, "w") as f:
            f.write(signed_json2.decode() if isinstance(
                signed_json2, bytes) else signed_json2)
        print(f"Signed JSON saved to: {filename}")
        generated_files.append(filename)
    else:
        print("Failed to sign JSON report")
        print("Note: This test requires Azure Key Vault (see README.md)")

    # Sign CoRIM format (test key)
    print("\nSigning CoRIM report (test key)...")
    try:
        success_c1 = rep.sign_corim_report_pem(privkey, MY_SIGN_ALGO, MY_KID)
        if success_c1:
            signed_corim1 = rep.get_signed_corim_report()
            print(
                f"CoRIM COSE-Sign1 signature created ({len(signed_corim1)} bytes)")

            # Save signed CoRIM
            filename = "example_report_signed_testkey.cbor"
            with open(filename, "wb") as f:
                f.write(signed_corim1)
            print(f"Signed CoRIM saved to: {filename}")
            generated_files.append(filename)
        else:
            print("Failed to sign CoRIM report")
    except Exception as e:
        print(f"Error signing CoRIM: {e}")

    # Sign CoRIM format (azure)
    print("\nSigning CoRIM report (azure)...")
    try:
        success_c2 = rep.sign_corim_report_azure( MY_VAULT, MY_KID_AZURE )
    except Exception as e:
        print(f"Error signing CoRIM: {e}")
    if success_c2:
        signed_corim2 = rep.get_signed_corim_report()
        print(
            f"CoRIM COSE-Sign1 signature created ({len(signed_corim2)} bytes)")

        # Save signed CoRIM
        filename = "example_report_signed_azurekey.cbor"
        with open(filename, "wb") as f:
            f.write(signed_corim2)
        print(f"Signed CoRIM saved to: {filename}")
        generated_files.append(filename)
    else:
        print("Failed to sign CoRIM report")
        print("Note: This test requires Azure Key Vault (see README.md)")

    print("\n=== VERIFICATION DEMONSTRATION ===")

    # Verify JSON signature (test key)
    if success_j1 and os.path.exists(MY_PUB_KEY):
        try:
            with open(MY_PUB_KEY, "rb") as f:
                pubkey = f.read()

            print("Verifying JSON signature (test key)...")
            rep.verify_signed_json_report(signed_json1, pubkey)
            print("JSON signature verification: SUCCESS")

        except Exception as e:
            print(f"JSON verification failed: {e}")

    # Verify JSON signature (azure)
    if success_j2 and os.path.exists(MY_PUB_KEY_AZURE):
        try:
            with open(MY_PUB_KEY_AZURE, "rb") as f:
                pubkey = f.read()

            print("Verifying JSON signature (azure)...")
            rep.verify_signed_json_report(signed_json2, pubkey)
            print("JSON signature verification: SUCCESS")

        except Exception as e:
            print(f"JSON verification failed: {e}")

    # Verify CBOR signature (test key)
    if success_c1 and os.path.exists(MY_PUB_KEY):
        try:
            with open(MY_PUB_KEY, "rb") as f:
                pubkey = f.read()

            print("Verifying CoRIM CBOR signature (test key)...")
            rep.verify_signed_corim_report(signed_corim1, pubkey, MY_KID)
            print("CoRIM CBOR signature verification: SUCCESS")

        except Exception as e:
            print(f"CoRIM CBOR verification failed: {e}")

    # Verify CBOR signature
    if success_c2 and os.path.exists(MY_PUB_KEY_AZURE):
        try:
            with open(MY_PUB_KEY_AZURE, "rb") as f:
                pubkey = f.read()

            print("Verifying CoRIM CBOR signature (azure)...")
            rep.verify_signed_corim_report(signed_corim2, pubkey, MY_KID_AZURE)
            print("CoRIM CBOR signature verification: SUCCESS")

        except Exception as e:
            print(f"CoRIM CBOR verification failed: {e}")

    print("\n=== FORMAT COMPARISON ===")

    # Compare file sizes
    files_info = []
    for filename in generated_files:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            files_info.append((filename, size))

    if files_info:
        print("File size comparison:")
        for filename, size in files_info:
            print(f"  {filename}: {size} bytes")

    print("\n=== SUMMARY ===")
    if success_j1:
        print("✓ ", end='')
    else:
        print("x ", end='')
    print("JSON format: Backward compatible, uses JWS signing (test key)")
    if success_j2:
        print("✓ ", end='')
    else:
        print("x ", end='')
    print("JSON format: Backward compatible, uses JWS signing (azure key)")
    if success_c1:
        print("✓ ", end='')
    else:
        print("x ", end='')
    print("CoRIM format: New CBOR format, uses COSE-Sign1 signing (test key)")
    if success_c2:
        print("✓ ", end='')
    else:
        print("x ", end='')
    print("CoRIM format: New CBOR format, uses COSE-Sign1 signing (azure key)")

    print("\nFiles generated:")
    for filename in generated_files:
        if os.path.exists(filename):
            print(f"  {filename}")


if __name__ == "__main__":
    main()
