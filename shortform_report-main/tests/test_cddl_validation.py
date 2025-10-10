#!/usr/bin/env python3
"""
Test script to validate CoRIM generation against CDDL schema.
This script generates a CoRIM and outputs diagnostic information to help debug CDDL compliance.
"""

import sys
import os
import cbor2
import json
from datetime import datetime

# Add parent directory to path to import OcpReportLib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OcpReportLib import ShortFormReport

def cbor_to_diagnostic(cbor_data):
    """Convert CBOR data to a more readable diagnostic format."""
    try:
        # Decode CBOR and pretty print the structure
        decoded = cbor2.loads(cbor_data)
        return json.dumps(decoded, indent=2, default=str)
    except Exception as e:
        return f"Error decoding CBOR: {e}"

def test_corim_generation():
    """Test CoRIM generation and output diagnostic information."""
    print("=== Testing CoRIM Generation ===\n")
    
    # Create a test report
    report = ShortFormReport("1.1")
    
    # Add device information
    report.add_device(
        vendor="Test Vendor",
        product="Test Product",
        category="cpu",
        repo_tag="v1.0.0",
        fw_ver="1.2.3",
        fw_hash_sha384="a" * 96,  # 48 bytes = 96 hex chars
        fw_hash_sha512="b" * 128,  # 64 bytes = 128 hex chars
    )
    
    # Add audit information
    report.add_audit(
        srp="Test SRP",
        methodology="whitebox",
        date="2025-01-02",
        report_ver="1.0",
        scope_number=2,
        cvss_ver="3.1"
    )
    
    # Add a test issue
    report.add_issue(
        title="Test Issue",
        cvss_score="7.5",
        cvss_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-200",
        description="Test vulnerability description",
        cve="CVE-2025-0001"
    )
    
    print("1. Generated JSON report structure:")
    print(json.dumps(report.get_report_as_dict(), indent=2))
    print("\n" + "="*80 + "\n")
    
    print("2. Converting to CoRIM structure...")
    try:
        corim_dict = report.get_report_as_corim_dict()
        print("CoRIM dictionary structure:")
        print(json.dumps(corim_dict, indent=2, default=str))
        print("\n" + "="*80 + "\n")
        
        print("3. Generating CBOR...")
        corim_cbor = report.get_report_as_corim_cbor()
        print(f"Generated CBOR length: {len(corim_cbor)} bytes")
        print(f"CBOR hex: {corim_cbor[:100].hex()}..." if len(corim_cbor) > 100 else f"CBOR hex: {corim_cbor.hex()}")
        print("\n" + "="*80 + "\n")
        
        print("4. CBOR diagnostic representation:")
        diagnostic = cbor_to_diagnostic(corim_cbor)
        print(diagnostic)
        print("\n" + "="*80 + "\n")
        
        # Save the CBOR for external validation
        with open("test_corim_output.cbor", "wb") as f:
            f.write(corim_cbor)
        print("5. Saved CBOR to 'test_corim_output.cbor' for external validation")
        
        # Test signing (optional)
        print("\n6. Testing CoRIM signing...")
        try:
            # Generate a test key for signing
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            
            # Generate P-521 key for ES512
            private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Try to sign
            if report.sign_corim_report_pem(private_pem, "ES512", "test-key-001"):
                signed_corim = report.get_signed_corim_report()
                print(f"Successfully signed CoRIM! Signed length: {len(signed_corim)} bytes")
                
                # Save signed CoRIM
                with open("test_corim_signed.cbor", "wb") as f:
                    f.write(signed_corim)
                print("Saved signed CoRIM to 'test_corim_signed.cbor'")
            else:
                print("CoRIM signing failed, but generation succeeded")
                
        except Exception as e:
            print(f"Signing test failed: {e}")
            print("This is expected if cwt library is not available")
        
        return True
        
    except Exception as e:
        print(f"Error generating CoRIM: {e}")
        import traceback
        traceback.print_exc()
        return False

def analyze_structure():
    """Analyze the generated structure against expected CDDL format."""
    print("\n=== Structure Analysis ===\n")
    
    try:
        with open("test_corim_output.cbor", "rb") as f:
            cbor_data = f.read()
        
        # Decode and analyze structure
        decoded = cbor2.loads(cbor_data)
        
        print("Top-level structure analysis:")
        if hasattr(decoded, 'tag') and decoded.tag == 501:
            print("✓ Correct CoRIM CBOR tag (501) found")
            corim_content = decoded.value
        else:
            print("✗ Missing or incorrect CoRIM CBOR tag")
            corim_content = decoded
        
        print(f"CoRIM content type: {type(corim_content)}")
        
        if isinstance(corim_content, dict):
            print("CoRIM structure keys:", list(corim_content.keys()))
            
            # Check for required fields
            required_fields = [0, 1, 5]  # id, tags, entities
            for field in required_fields:
                if field in corim_content:
                    print(f"✓ Required field {field} present")
                else:
                    print(f"✗ Required field {field} missing")
            
            # Analyze tags structure
            if 1 in corim_content:  # tags
                tags = corim_content[1]
                print(f"Tags structure: {type(tags)}, length: {len(tags) if hasattr(tags, '__len__') else 'N/A'}")
                
                if isinstance(tags, list) and len(tags) > 0:
                    first_tag = tags[0]
                    if hasattr(first_tag, 'tag') and first_tag.tag == 506:
                        print("✓ Correct COMID CBOR tag (506) found in tags")
                    else:
                        print("✗ Missing or incorrect COMID CBOR tag in tags")
        
        return True
        
    except Exception as e:
        print(f"Error analyzing structure: {e}")
        return False

if __name__ == "__main__":
    print("CoRIM CDDL Validation Test")
    print("=" * 50)
    
    success = test_corim_generation()
    if success:
        analyze_structure()
        print("\n=== Test Summary ===")
        print("✓ CoRIM generation completed")
        print("✓ CBOR output saved for validation")
        print("\nNext steps:")
        print("1. Use a CDDL validator tool to check 'test_corim_output.cbor' against the schema")
        print("2. Compare structure with the example in ocp-safe-sfr-fw-example.diag")
        print("3. Check for any remaining structural differences")
    else:
        print("\n✗ CoRIM generation failed")
        sys.exit(1)
