#!/usr/bin/env python3
"""
Test script for the human-readable CBOR inspector.
Generates a sample CoRIM and demonstrates the inspector tool.
"""

import sys
import os
from OcpReportLib import ShortFormReport
from cbor_human_inspector import inspect_corim_structure

def generate_test_corim():
    """Generate a test CoRIM file for demonstration."""
    print("🔧 Generating test CoRIM file...")
    
    # Create a comprehensive test report
    report = ShortFormReport("1.1")
    
    # Add device information
    report.add_device(
        vendor="ACME Corporation",
        product="SecureChip X1000",
        category="storage",
        repo_tag="v3.2.1",
        fw_ver="3.2.1-release",
        fw_hash_sha384="a1b2c3d4e5f6" * 8,  # 48 bytes
        fw_hash_sha512="f6e5d4c3b2a1" * 10 + "f6e5d4c3",  # 64 bytes
    )
    
    # Add audit information
    report.add_audit(
        srp="Example Security Review Provider Inc.",
        methodology="whitebox",
        date="2025-01-15",
        report_ver="2.1",
        scope_number=5,
        cvss_ver="3.1"
    )
    
    # Add some realistic security issues
    report.add_issue(
        title="Buffer Overflow in Firmware Parser",
        cvss_score="9.1",
        cvss_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe="CWE-787",
        description="A critical buffer overflow vulnerability was discovered in the firmware parsing routine that could allow remote code execution. The vulnerability occurs when processing malformed firmware update packages.",
        cve="CVE-2025-0123"
    )
    
    report.add_issue(
        title="Cryptographic Key Exposure",
        cvss_score="7.5",
        cvss_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-200",
        description="Sensitive cryptographic keys are exposed in debug output when verbose logging is enabled.",
        cve="CVE-2025-0124"
    )
    
    report.add_issue(
        title="Insufficient Input Validation",
        cvss_score="5.3",
        cvss_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwe="CWE-20",
        description="Input validation is insufficient for certain configuration parameters, potentially leading to information disclosure."
    )
    
    # Generate CBOR
    corim_cbor = report.get_report_as_corim_cbor()
    
    # Save to file
    output_file = "test_corim_sample.cbor"
    with open(output_file, "wb") as f:
        f.write(corim_cbor)
    
    print(f"✅ Test CoRIM saved to: {output_file}")
    print(f"📊 File size: {len(corim_cbor)} bytes")
    
    return output_file, corim_cbor

def main():
    """Main test function."""
    print("=" * 80)
    print("  CBOR Human Inspector Test & Demonstration")
    print("=" * 80)
    
    # Generate test CoRIM
    corim_file, corim_data = generate_test_corim()
    
    print("\n" + "=" * 80)
    print("  Running Human-Readable Inspector")
    print("=" * 80)
    
    # Run the inspector
    inspect_corim_structure(corim_data, show_raw_data=False)
    
    print("\n" + "=" * 80)
    print("  Test Complete")
    print("=" * 80)
    print(f"📂 Generated file: {corim_file}")
    print("🔍 You can also run the inspector directly:")
    print(f"   python cbor_human_inspector.py {corim_file}")
    print("   python cbor_human_inspector.py {corim_file} --show-raw")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
