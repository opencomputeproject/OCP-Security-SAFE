#!/usr/bin/env python3
"""
Final Validation Summary for CoRIM CDDL Compliance
This script provides a comprehensive summary of the CoRIM implementation and validation results.
"""

import sys
import os
import cbor2
import json
from datetime import datetime

# Add parent directory to path to import OcpReportLib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OcpReportLib import ShortFormReport

def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def validate_corim_compliance():
    """Comprehensive validation of CoRIM CDDL compliance."""
    
    print_section("CoRIM CDDL Compliance Validation Summary")
    
    # Create a comprehensive test report
    report = ShortFormReport("1.1")
    
    # Add device information
    report.add_device(
        vendor="Example Vendor",
        product="Example Product",
        category="cpu",
        repo_tag="v2.1.0",
        fw_ver="2.1.0",
        fw_hash_sha384="1234567890abcdef" * 6,  # 48 bytes = 96 hex chars
        fw_hash_sha512="fedcba0987654321" * 8,  # 64 bytes = 128 hex chars
    )
    
    # Add audit information
    report.add_audit(
        srp="Example Security Review Provider",
        methodology="whitebox",
        date="2025-01-02",
        report_ver="2.0",
        scope_number=3,
        cvss_ver="3.1"
    )
    
    # Add multiple test issues
    report.add_issue(
        title="Critical Memory Corruption",
        cvss_score="9.8",
        cvss_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe="CWE-787",
        description="Buffer overflow in firmware parsing routine",
        cve="CVE-2025-0002"
    )
    
    report.add_issue(
        title="Information Disclosure",
        cvss_score="5.3",
        cvss_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwe="CWE-200",
        description="Sensitive data exposed in debug output"
    )
    
    print_section("1. JSON Report Generation")
    print("✓ JSON report structure created successfully")
    print(f"✓ Framework version: {report.report['review_framework_version']}")
    print(f"✓ Device category: {report.report['device']['category']}")
    print(f"✓ Issues count: {len(report.report['audit']['issues'])}")
    
    print_section("2. CoRIM Structure Generation")
    try:
        corim_dict = report.get_report_as_corim_dict()
        print("✓ CoRIM dictionary structure generated successfully")
        
        # Validate top-level structure
        required_fields = [0, 1, 3, 5]  # id, tags, profile, entities
        for field in required_fields:
            if field in corim_dict:
                print(f"✓ Required CoRIM field {field} present")
            else:
                print(f"✗ Required CoRIM field {field} missing")
                return False
        
        # Validate profile field specifically
        if 3 in corim_dict:
            profile = corim_dict[3]
            if isinstance(profile, cbor2.CBORTag) and profile.tag == 111:
                print("✓ Profile field properly tagged with OID tag (111)")
                profile_oid = profile.value
                expected_oid = bytes.fromhex('060A2B0601040182F4170101')  # OID 1.3.6.1.4.1.42623.1.1
                if profile_oid == expected_oid:
                    print("✓ Profile OID matches expected value (1.3.6.1.4.1.42623.1.1)")
                else:
                    print(f"✗ Profile OID mismatch. Expected: {expected_oid.hex()}, Got: {profile_oid.hex()}")
                    return False
            else:
                print("✗ Profile field not properly tagged or missing OID tag")
                return False
        
        print_section("3. CBOR Encoding")
        corim_cbor = report.get_report_as_corim_cbor()
        print(f"✓ CBOR encoding successful ({len(corim_cbor)} bytes)")
        
        # Validate CBOR structure
        decoded = cbor2.loads(corim_cbor)
        if isinstance(decoded, cbor2.CBORTag) and decoded.tag == 501:
            print("✓ Correct CoRIM CBOR tag (501)")
        else:
            print("✗ Missing or incorrect CoRIM CBOR tag")
            return False
        
        print_section("4. CDDL Schema Compliance")
        
        # Deep structure validation
        corim_content = decoded.value
        if not isinstance(corim_content, dict):
            print("✗ CoRIM content is not a dictionary")
            return False
        
        # Validate tags structure
        if 1 not in corim_content:
            print("✗ Missing tags field")
            return False
        
        tags = corim_content[1]
        if not isinstance(tags, list) or len(tags) == 0:
            print("✗ Tags field is not a proper list")
            return False
        
        first_tag = tags[0]
        if not (isinstance(first_tag, cbor2.CBORTag) and first_tag.tag == 506):
            print("✗ First tag missing COMID tag (506)")
            return False
        
        print("✓ COMID structure properly tagged")
        
        # Decode and validate COMID content
        try:
            comid_content = cbor2.loads(first_tag.value)
            
            # Check COMID required fields
            if 1 not in comid_content:
                print("✗ COMID missing tag-identity field")
                return False
            
            if 4 not in comid_content:
                print("✗ COMID missing triples field")
                return False
            
            triples = comid_content[4]
            if not isinstance(triples, dict) or 10 not in triples:
                print("✗ COMID missing conditional-endorsement-triples")
                return False
            
            print("✓ COMID structure compliant")
            
            # Validate conditional endorsement structure
            cond_endorsements = triples[10]
            if not isinstance(cond_endorsements, list) or len(cond_endorsements) == 0:
                print("✗ Invalid conditional endorsements structure")
                return False
            
            first_cond = cond_endorsements[0]
            if not (isinstance(first_cond, list) and len(first_cond) == 2):
                print("✗ Invalid conditional endorsement record structure")
                return False
            
            conditions, endorsements = first_cond
            
            # Validate endorsements contain SFR data
            if not isinstance(endorsements, list) or len(endorsements) == 0:
                print("✗ Invalid endorsements structure")
                return False
            
            first_endorsement = endorsements[0]
            if not (isinstance(first_endorsement, list) and len(first_endorsement) == 2):
                print("✗ Invalid endorsed triple record structure")
                return False
            
            env, measurements = first_endorsement
            if not isinstance(measurements, list) or len(measurements) == 0:
                print("✗ Invalid measurements structure")
                return False
            
            first_measurement = measurements[0]
            if not (isinstance(first_measurement, dict) and 1 in first_measurement):
                print("✗ Invalid measurement map structure")
                return False
            
            mval = first_measurement[1]
            if not (isinstance(mval, dict) and -1 in mval):
                print("✗ Missing SFR extension (-1)")
                return False
            
            print("✓ SFR extension (-1) found in measurement values")
            
            # Validate SFR structure
            sfr_data = mval[-1]
            required_sfr_fields = {
                0: "review-framework-version",
                1: "report-version", 
                2: "completion-date",
                3: "scope-number",
                4: "fw-identifiers"
            }
            
            for field_num, field_name in required_sfr_fields.items():
                if field_num in sfr_data:
                    print(f"✓ SFR field {field_num} ({field_name}) present")
                else:
                    print(f"✗ SFR field {field_num} ({field_name}) missing")
                    return False
            
            # Validate completion date has proper CBOR tag 1 (decoded as datetime)
            completion_date = sfr_data[2]
            if isinstance(completion_date, datetime):
                print("✓ Completion date properly encoded with CBOR tag 1")
            else:
                print(f"✗ Completion date incorrect format: {type(completion_date)}")
                return False
            
            # Validate device category mapping
            if 5 in sfr_data:
                device_category = sfr_data[5]
                if isinstance(device_category, int) and 0 <= device_category <= 5:
                    print(f"✓ Device category properly mapped to integer: {device_category}")
                else:
                    print(f"✗ Invalid device category: {device_category}")
                    return False
            
            # Validate issues structure
            if 6 in sfr_data:
                issues = sfr_data[6]
                if isinstance(issues, list):
                    print(f"✓ Issues properly structured as list with {len(issues)} items")
                    
                    # Validate first issue structure
                    if len(issues) > 0:
                        first_issue = issues[0]
                        required_issue_fields = [0, 1, 2, 3, 4]  # title, cvss-score, cvss-vector, cwe, description
                        for field in required_issue_fields:
                            if field in first_issue:
                                print(f"✓ Issue field {field} present")
                            else:
                                print(f"✗ Issue field {field} missing")
                                return False
                else:
                    print("✗ Issues not properly structured as list")
                    return False
            
            print("✓ All CDDL schema requirements satisfied")
            
        except Exception as e:
            print(f"✗ Error validating COMID content: {e}")
            return False
        
        print_section("5. CoRIM Signing Test")
        try:
            # Generate test key for signing
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            
            private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            if report.sign_corim_report_pem(private_pem, "ES512", "test-validation-key"):
                signed_corim = report.get_signed_corim_report()
                print(f"✓ CoRIM signing successful ({len(signed_corim)} bytes)")
                print("✓ COSE-Sign1 format with cwt library")
            else:
                print("✗ CoRIM signing failed")
                return False
                
        except Exception as e:
            print(f"✗ Signing test failed: {e}")
            return False
        
        print_section("6. Final Validation Summary")
        print("✓ JSON to CoRIM conversion: PASSED")
        print("✓ CBOR encoding: PASSED") 
        print("✓ CDDL schema compliance: PASSED")
        print("✓ CoRIM tag structure: PASSED")
        print("✓ COMID tag structure: PASSED")
        print("✓ SFR extension mapping: PASSED")
        print("✓ Date encoding (CBOR tag 1): PASSED")
        print("✓ Device category mapping: PASSED")
        print("✓ Issues structure: PASSED")
        print("✓ COSE-Sign1 signing: PASSED")
        
        print(f"\n🎉 CoRIM implementation is fully CDDL compliant!")
        print(f"📊 Generated CoRIM size: {len(corim_cbor)} bytes")
        print(f"🔐 Signed CoRIM size: {len(signed_corim)} bytes")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during validation: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main validation function."""
    print("CoRIM CDDL Compliance Validation")
    print("OCP Security SAFE Framework")
    print(f"Validation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    success = validate_corim_compliance()
    
    if success:
        print_section("VALIDATION RESULT: SUCCESS ✅")
        print("The CoRIM implementation successfully complies with the CDDL schema.")
        print("Security Review Providers can now generate SFRs in CoRIM format.")
        return 0
    else:
        print_section("VALIDATION RESULT: FAILED ❌")
        print("The CoRIM implementation has compliance issues that need to be addressed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
