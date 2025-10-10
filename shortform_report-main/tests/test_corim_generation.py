"""
Test script for CoRIM SFR generation functionality.

This script validates that the extended library correctly generates
CoRIM format reports that comply with the OCP SAFE SFR CDDL schema.

Author: Extended from Jeremy Boone's original OcpReportLib.py
Date  : January 2025
"""

import sys
import os
import json
import traceback

# Add parent directory to path to import OcpReportLib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from OcpReportLib import ShortFormReport

def test_basic_functionality():
    """Test basic report generation in both formats."""
    print("=== Testing Basic Functionality ===")
    
    try:
        # Create report
        rep = ShortFormReport(framework_ver="1.1")
        
        # Add test data
        rep.add_device(
            vendor="Test Vendor",
            product="Test Device",
            category="storage",
            repo_tag="test_v1.0.0",
            fw_ver="1.0.0",
            fw_hash_sha384="a" * 96,  # Valid length hex string
            fw_hash_sha512="b" * 128  # Valid length hex string
        )
        
        rep.add_audit(
            srp="Test SRP",
            methodology="whitebox",
            date="2023-01-01",
            report_ver="1.0",
            scope_number=1
        )
        
        rep.add_issue(
            title="Test Issue",
            cvss_score="5.0",
            cvss_vec="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            cwe="CWE-000",
            description="Test vulnerability description"
        )
        
        # Test JSON generation
        json_dict = rep.get_report_as_dict()
        json_str = rep.get_json_report_as_str()
        
        assert isinstance(json_dict, dict)
        assert isinstance(json_str, str)
        assert "device" in json_dict
        assert "audit" in json_dict
        
        print("✓ JSON generation: PASS")
        
        # Test CoRIM generation
        corim_dict = rep.get_report_as_corim_dict()
        corim_cbor = rep.get_report_as_corim_cbor()
        
        assert isinstance(corim_dict, dict)
        assert isinstance(corim_cbor, bytes)
        assert len(corim_cbor) > 0
        
        print("✓ CoRIM generation: PASS")
        
        return True
        
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        traceback.print_exc()
        return False

def test_schema_compliance():
    """Test that generated CoRIM complies with expected structure."""
    print("\n=== Testing Schema Compliance ===")
    
    try:
        rep = ShortFormReport()
        
        rep.add_device(
            vendor="ACME Corp",
            product="Test Widget",
            category="gpu",  # Test different category
            repo_tag="v2.1.0",
            fw_ver="2.1.0",
            fw_hash_sha384="c" * 96,
            fw_hash_sha512="d" * 128
        )
        
        rep.add_audit(
            srp="Compliance Test SRP",
            methodology="blackbox",
            date="2023-12-31",
            report_ver="2.0",
            scope_number=2
        )
        
        # Add multiple issues
        rep.add_issue(
            title="Critical Issue",
            cvss_score="9.8",
            cvss_vec="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe="CWE-787",
            description="Critical buffer overflow",
            cve="CVE-2023-12345"
        )
        
        rep.add_issue(
            title="Medium Issue",
            cvss_score="6.1",
            cvss_vec="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cwe="CWE-79",
            description="Cross-site scripting vulnerability"
        )
        
        # Generate CoRIM and validate structure
        corim_dict = rep.get_report_as_corim_dict()
        
        # Check top-level structure
        assert 0 in corim_dict  # id
        assert 1 in corim_dict  # tags
        assert 5 in corim_dict  # entities
        
        print("✓ Top-level CoRIM structure: PASS")
        
        # Validate SFR data structure
        sfr_map = rep._convert_to_corim_structure()
        
        # Check required SFR fields
        assert 0 in sfr_map  # review-framework-version
        assert 1 in sfr_map  # report-version
        assert 2 in sfr_map  # completion-date
        assert 3 in sfr_map  # scope-number
        assert 4 in sfr_map  # fw-identifiers
        
        # Check optional fields
        assert 5 in sfr_map  # device-category (should be 2 for GPU)
        assert sfr_map[5] == 2  # GPU category
        assert 6 in sfr_map  # issues
        assert len(sfr_map[6]) == 2  # Two issues added
        
        print("✓ SFR structure compliance: PASS")
        
        # Check fw-identifiers structure
        fw_ids = sfr_map[4]
        assert isinstance(fw_ids, list)
        assert len(fw_ids) > 0
        
        fw_id = fw_ids[0]
        assert 0 in fw_id  # fw-version
        assert 1 in fw_id  # fw-file-digests
        assert 2 in fw_id  # repo-tag
        
        print("✓ Firmware identifier structure: PASS")
        
        # Check issues structure
        issues = sfr_map[6]
        for issue in issues:
            assert 0 in issue  # title
            assert 1 in issue  # cvss-score
            assert 2 in issue  # cvss-vector
            assert 3 in issue  # cwe
            assert 4 in issue  # description
        
        print("✓ Issues structure: PASS")
        
        return True
        
    except Exception as e:
        print(f"✗ Schema compliance test failed: {e}")
        traceback.print_exc()
        return False

def test_device_categories():
    """Test device category mapping."""
    print("\n=== Testing Device Categories ===")
    
    categories = [
        ("storage", 0),
        ("network", 1),
        ("gpu", 2),
        ("cpu", 3),
        ("apu", 4),
        ("bmc", 5)
    ]
    
    try:
        for category_str, expected_int in categories:
            rep = ShortFormReport()
            
            rep.add_device(
                vendor="Test",
                product="Test",
                category=category_str,
                repo_tag="test",
                fw_ver="1.0",
                fw_hash_sha384="a" * 96,
                fw_hash_sha512="b" * 128
            )
            
            rep.add_audit(
                srp="Test",
                methodology="test",
                date="2023-01-01",
                report_ver="1.0",
                scope_number=1
            )
            
            sfr_map = rep._convert_to_corim_structure()
            
            if 5 in sfr_map:  # device-category is optional
                assert sfr_map[5] == expected_int, f"Category {category_str} should map to {expected_int}, got {sfr_map[5]}"
            
            print(f"✓ Category '{category_str}' → {expected_int}: PASS")
        
        return True
        
    except Exception as e:
        print(f"✗ Device category test failed: {e}")
        traceback.print_exc()
        return False

def test_error_handling():
    """Test error handling for invalid inputs."""
    print("\n=== Testing Error Handling ===")
    
    try:
        # Test missing required data
        rep = ShortFormReport()
        
        try:
            # Should fail - no device or audit data
            corim_dict = rep.get_report_as_corim_dict()
            print("✗ Should have failed with missing data")
            return False
        except ValueError:
            print("✓ Missing data validation: PASS")
        
        # Test invalid date format
        rep.add_device("Test", "Test", "storage", "test", "1.0", "a"*96, "b"*128)
        rep.add_audit("Test", "test", "invalid-date", "1.0", 1)
        
        try:
            sfr_map = rep._convert_to_corim_structure()
            print("✗ Should have failed with invalid date")
            return False
        except ValueError:
            print("✓ Invalid date validation: PASS")
        
        return True
        
    except Exception as e:
        print(f"✗ Error handling test failed: {e}")
        traceback.print_exc()
        return False

def test_backward_compatibility():
    """Test that original API still works."""
    print("\n=== Testing Backward Compatibility ===")
    
    try:
        # Import with original alias
        from OcpReportLib import ShortFormReport
        
        # Use exactly like original library
        rep = ShortFormReport()
        
        rep.add_device(
            "Test Vendor",
            "Test Product", 
            "storage",
            "test_tag",
            "1.0.0",
            "a" * 96,
            "b" * 128
        )
        
        rep.add_audit(
            "Test SRP",
            "whitebox",
            "2023-01-01",
            "1.0",
            1
        )
        
        rep.add_issue(
            "Test Issue",
            "5.0",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "CWE-000",
            "Test description"
        )
        
        # Original methods should work
        json_dict = rep.get_report_as_dict()
        json_str = rep.get_json_report_as_str()
        
        assert isinstance(json_dict, dict)
        assert isinstance(json_str, str)
        
        print("✓ Original API compatibility: PASS")
        
        # New methods should also work
        corim_cbor = rep.get_report_as_corim_cbor()
        assert isinstance(corim_cbor, bytes)
        
        print("✓ Extended API availability: PASS")
        
        return True
        
    except Exception as e:
        print(f"✗ Backward compatibility test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("OCP SAFE SFR CoRIM Generation Test Suite")
    print("=" * 50)
    
    tests = [
        test_basic_functionality,
        test_schema_compliance,
        test_device_categories,
        test_error_handling,
        test_backward_compatibility
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! CoRIM generation is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
