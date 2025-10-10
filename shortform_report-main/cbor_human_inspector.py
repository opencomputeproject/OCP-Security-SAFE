#!/usr/bin/env python3
"""
Human-Readable CBOR CoRIM Inspector
This tool provides a clear, auditor-friendly view of CBOR CoRIM files.
"""

import cbor2
import sys
import os
from datetime import datetime
import json

# Add parent directory to path to import OcpReportLib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def print_header(title, level=1):
    """Print formatted headers for different levels."""
    if level == 1:
        print(f"\n{'='*80}")
        print(f"  {title}")
        print(f"{'='*80}")
    elif level == 2:
        print(f"\n{'-'*60}")
        print(f"  {title}")
        print(f"{'-'*60}")
    elif level == 3:
        print(f"\n{'·'*40}")
        print(f"  {title}")
        print(f"{'·'*40}")

def format_bytes_display(data, max_length=32):
    """Format bytes for human-readable display."""
    if len(data) <= max_length:
        return data.hex()
    else:
        return f"{data[:max_length//2].hex()}...{data[-max_length//2:].hex()} ({len(data)} bytes total)"

def format_oid_display(oid_bytes):
    """Convert OID bytes to human-readable dotted notation."""
    try:
        # Simple OID decoder for common cases
        if oid_bytes.hex() == '060a2b0601040182f4170101':
            return "1.3.6.1.4.1.42623.1.1 (OCP SAFE SFR Profile)"
        elif oid_bytes.hex() == '2b0601040182f4170101':
            return "1.3.6.1.4.1.42623.1.1 (OCP SAFE SFR Profile - DER content only)"
        else:
            return f"Unknown OID: {oid_bytes.hex()}"
    except:
        return f"Invalid OID: {oid_bytes.hex()}"

def explain_cbor_tag(tag_num):
    """Provide human-readable explanations for CBOR tags."""
    tag_explanations = {
        1: "POSIX timestamp (seconds since epoch)",
        111: "Object Identifier (OID)",
        501: "CoRIM (CBOR Object Representation of Information Model)",
        506: "COMID (Concise Module Identifier)",
        # Add more as needed
    }
    return tag_explanations.get(tag_num, f"CBOR tag {tag_num}")

def explain_corim_field(field_num):
    """Explain CoRIM top-level fields."""
    corim_fields = {
        0: "CoRIM ID - Unique identifier for this CoRIM",
        1: "Tags - List of COMID tags containing the actual data",
        2: "Dependent RIMs - References to other CoRIMs (optional)",
        3: "Profile - Identifies the CoRIM profile being used",
        4: "RIM Validity - Validity period for this CoRIM (optional)",
        5: "Entities - Information about entities involved in creating this CoRIM"
    }
    return corim_fields.get(field_num, f"Unknown CoRIM field {field_num}")

def explain_comid_field(field_num):
    """Explain COMID fields."""
    comid_fields = {
        0: "Language - Language tag for text content (optional)",
        1: "Tag Identity - Unique identifier for this COMID tag",
        2: "Entities - Entities responsible for this COMID (optional)",
        3: "Linked Tags - References to other tags (optional)",
        4: "Triples - The actual attestation data (reference/endorsed/conditional values)"
    }
    return comid_fields.get(field_num, f"Unknown COMID field {field_num}")

def explain_sfr_field(field_num):
    """Explain SFR extension fields."""
    sfr_fields = {
        0: "Review Framework Version - Version of the OCP SAFE framework used",
        1: "Report Version - Version of this specific security review report",
        2: "Completion Date - When the security review was completed",
        3: "Scope Number - Numerical identifier for the review scope",
        4: "Firmware Identifiers - Information about the reviewed firmware",
        5: "Device Category - Type of device (CPU, GPU, BMC, etc.)",
        6: "Issues - List of security issues found during review",
        7: "Methodology - Review methodology used (whitebox, blackbox, etc.)",
        8: "Security Review Provider - Organization that performed the review"
    }
    return sfr_fields.get(field_num, f"Unknown SFR field {field_num}")

def explain_device_category(category_num):
    """Explain device category numbers."""
    categories = {
        0: "CPU (Central Processing Unit)",
        1: "GPU (Graphics Processing Unit)", 
        2: "BMC (Baseboard Management Controller)",
        3: "NIC (Network Interface Controller)",
        4: "Storage (Storage devices)",
        5: "Other (Other device types)"
    }
    return categories.get(category_num, f"Unknown category {category_num}")

def inspect_corim_structure(cbor_data, show_raw_data=False):
    """Provide human-readable inspection of CoRIM structure."""
    
    print_header("CBOR CoRIM Human-Readable Inspector", 1)
    print(f"📊 Total CBOR size: {len(cbor_data)} bytes")
    print(f"🔍 Analysis timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if show_raw_data:
        print(f"📋 Raw CBOR data (first 100 bytes): {cbor_data[:100].hex()}")
    
    try:
        # Decode the top-level CBOR
        decoded = cbor2.loads(cbor_data)
        
        print_header("Top-Level Structure Analysis", 2)
        
        if isinstance(decoded, cbor2.CBORTag):
            print(f"✅ CBOR Tag Found: {decoded.tag} ({explain_cbor_tag(decoded.tag)})")
            
            if decoded.tag == 501:  # CoRIM tag
                print("✅ This is a valid CoRIM structure")
                corim_content = decoded.value
                
                if isinstance(corim_content, dict):
                    print(f"✅ CoRIM contains {len(corim_content)} top-level fields")
                    
                    # First, validate required fields
                    print_header("Required Fields Validation", 3)
                    required_fields = {
                        0: "CoRIM ID",
                        1: "Tags", 
                        3: "Profile",
                        5: "Entities"
                    }
                    
                    validation_passed = True
                    for field_num, field_name in required_fields.items():
                        if field_num in corim_content:
                            print(f"✅ Required field {field_num} ({field_name}) is present")
                        else:
                            print(f"❌ MISSING REQUIRED FIELD {field_num} ({field_name})")
                            validation_passed = False
                    
                    if not validation_passed:
                        print(f"\n⚠️  WARNING: This CoRIM is missing required fields and may not be valid!")
                    
                    print_header("CoRIM Fields Breakdown", 3)
                    
                    # Check for profile field specifically if missing
                    if 3 not in corim_content:
                        print(f"\n🔸 Field 3: {explain_corim_field(3)}")
                        print(f"   ❌ CRITICAL: Profile field is MISSING!")
                        print(f"   ❌ CoRIM MUST include profile OID 1.3.6.1.4.1.42623.1.1 for OCP SAFE SFR")
                        print(f"   ❌ This CoRIM will not validate against the OCP SAFE SFR profile")
                    
                    for field_num in sorted(corim_content.keys()):
                        field_value = corim_content[field_num]
                        print(f"\n🔸 Field {field_num}: {explain_corim_field(field_num)}")
                        
                        if field_num == 0:  # CoRIM ID
                            if isinstance(field_value, bytes):
                                print(f"   Value: {format_bytes_display(field_value)}")
                            else:
                                print(f"   Value: {field_value}")
                        
                        elif field_num == 1:  # Tags
                            if isinstance(field_value, list):
                                print(f"   📝 Contains {len(field_value)} COMID tag(s)")
                                
                                for i, tag in enumerate(field_value):
                                    print(f"\n   📋 COMID Tag #{i+1}:")
                                    if isinstance(tag, cbor2.CBORTag) and tag.tag == 506:
                                        print(f"      ✅ Proper COMID tag (506)")
                                        
                                        try:
                                            comid_content = cbor2.loads(tag.value)
                                            inspect_comid_content(comid_content, indent="      ")
                                        except Exception as e:
                                            print(f"      ❌ Error decoding COMID: {e}")
                                    else:
                                        print(f"      ❌ Invalid COMID tag structure")
                            else:
                                print(f"   ❌ Tags field should be a list, found: {type(field_value)}")
                        
                        elif field_num == 3:  # Profile
                            if isinstance(field_value, cbor2.CBORTag) and field_value.tag == 111:
                                print(f"   ✅ Proper OID tag (111)")
                                oid_display = format_oid_display(field_value.value)
                                print(f"   🆔 Profile: {oid_display}")
                            else:
                                print(f"   ❌ Profile should be OID tag (111), found: {type(field_value)}")
                        
                        elif field_num == 5:  # Entities
                            if isinstance(field_value, list):
                                print(f"   👥 Contains {len(field_value)} entity/entities")
                                for i, entity in enumerate(field_value):
                                    if isinstance(entity, dict):
                                        print(f"      Entity #{i+1}:")
                                        if 0 in entity:  # entity-name
                                            print(f"         Name: {entity[0]}")
                                        if 1 in entity:  # reg-id
                                            print(f"         Registration ID: {entity[1]}")
                                        if 2 in entity:  # role
                                            roles = entity[2]
                                            if isinstance(roles, list):
                                                role_names = []
                                                for role in roles:
                                                    if role == 0:
                                                        role_names.append("tag-creator")
                                                    elif role == 1:
                                                        role_names.append("tag-maintainer")
                                                    else:
                                                        role_names.append(f"role-{role}")
                                                print(f"         Roles: {', '.join(role_names)}")
                            else:
                                print(f"   ❌ Entities should be a list, found: {type(field_value)}")
                        
                        else:
                            print(f"   Value type: {type(field_value)}")
                            if isinstance(field_value, (str, int, float)):
                                print(f"   Value: {field_value}")
                            elif isinstance(field_value, bytes):
                                print(f"   Value: {format_bytes_display(field_value)}")
                
                else:
                    print(f"❌ CoRIM content should be a dictionary, found: {type(corim_content)}")
            else:
                print(f"❌ Expected CoRIM tag (501), found tag {decoded.tag}")
        else:
            print(f"❌ Expected CBOR tag at top level, found: {type(decoded)}")
    
    except Exception as e:
        print(f"❌ Error decoding CBOR: {e}")
        import traceback
        traceback.print_exc()

def inspect_comid_content(comid_content, indent=""):
    """Inspect COMID content in detail."""
    if not isinstance(comid_content, dict):
        print(f"{indent}❌ COMID content should be a dictionary")
        return
    
    print(f"{indent}📋 COMID contains {len(comid_content)} fields")
    
    for field_num in sorted(comid_content.keys()):
        field_value = comid_content[field_num]
        print(f"\n{indent}🔹 Field {field_num}: {explain_comid_field(field_num)}")
        
        if field_num == 1:  # Tag Identity
            if isinstance(field_value, dict):
                if 0 in field_value:  # tag-id
                    tag_id = field_value[0]
                    if isinstance(tag_id, bytes):
                        print(f"{indent}   Tag ID: {format_bytes_display(tag_id)}")
                    else:
                        print(f"{indent}   Tag ID: {tag_id}")
        
        elif field_num == 4:  # Triples
            if isinstance(field_value, dict):
                print(f"{indent}   📊 Triples structure:")
                
                if 10 in field_value:  # conditional-endorsement-triples
                    cond_endorsements = field_value[10]
                    if isinstance(cond_endorsements, list):
                        print(f"{indent}      🔄 {len(cond_endorsements)} conditional endorsement(s)")
                        
                        for i, cond_endorsement in enumerate(cond_endorsements):
                            if isinstance(cond_endorsement, list) and len(cond_endorsement) == 2:
                                conditions, endorsements = cond_endorsement
                                print(f"\n{indent}      📋 Conditional Endorsement #{i+1}:")
                                print(f"{indent}         Conditions: {len(conditions) if isinstance(conditions, list) else 'Invalid'}")
                                
                                if isinstance(endorsements, list):
                                    print(f"{indent}         Endorsements: {len(endorsements)}")
                                    
                                    for j, endorsement in enumerate(endorsements):
                                        if isinstance(endorsement, list) and len(endorsement) == 2:
                                            env, measurements = endorsement
                                            print(f"\n{indent}         🎯 Endorsement #{j+1}:")
                                            print(f"{indent}            Environment: {type(env).__name__}")
                                            
                                            if isinstance(measurements, list):
                                                print(f"{indent}            📏 {len(measurements)} measurement(s):")
                                                
                                                for k, measurement in enumerate(measurements):
                                                    if isinstance(measurement, dict) and 1 in measurement:
                                                        mval = measurement[1]
                                                        print(f"\n{indent}            📊 Measurement #{k+1}:")
                                                        
                                                        if isinstance(mval, dict):
                                                            for ext_key, ext_value in mval.items():
                                                                if ext_key == -1:  # SFR extension
                                                                    print(f"{indent}               🔐 SFR Extension (-1) Found!")
                                                                    inspect_sfr_data(ext_value, indent + "                  ")
                                                                else:
                                                                    print(f"{indent}               Extension {ext_key}: {type(ext_value).__name__}")

def inspect_sfr_data(sfr_data, indent=""):
    """Inspect SFR extension data in detail."""
    if not isinstance(sfr_data, dict):
        print(f"{indent}❌ SFR data should be a dictionary")
        return
    
    print(f"{indent}📋 SFR Data contains {len(sfr_data)} fields:")
    
    for field_num in sorted(sfr_data.keys()):
        field_value = sfr_data[field_num]
        print(f"\n{indent}🔸 Field {field_num}: {explain_sfr_field(field_num)}")
        
        if field_num == 0:  # Framework version
            print(f"{indent}   Version: {field_value}")
        
        elif field_num == 1:  # Report version
            print(f"{indent}   Version: {field_value}")
        
        elif field_num == 2:  # Completion date
            if isinstance(field_value, datetime):
                print(f"{indent}   Date: {field_value.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                print(f"{indent}   ✅ Properly encoded with CBOR timestamp tag")
            else:
                print(f"{indent}   Date: {field_value} (Type: {type(field_value).__name__})")
                print(f"{indent}   ❌ Should be datetime with CBOR tag 1")
        
        elif field_num == 3:  # Scope number
            print(f"{indent}   Scope: {field_value}")
        
        elif field_num == 4:  # Firmware identifiers
            if isinstance(field_value, dict):
                print(f"{indent}   📦 Firmware Info:")
                for fw_key, fw_value in field_value.items():
                    if fw_key == 0:  # vendor
                        print(f"{indent}      Vendor: {fw_value}")
                    elif fw_key == 1:  # product
                        print(f"{indent}      Product: {fw_value}")
                    elif fw_key == 2:  # version
                        print(f"{indent}      Version: {fw_value}")
                    elif fw_key == 3:  # hash-sha384
                        print(f"{indent}      SHA384: {format_bytes_display(fw_value)}")
                    elif fw_key == 4:  # hash-sha512
                        print(f"{indent}      SHA512: {format_bytes_display(fw_value)}")
                    else:
                        print(f"{indent}      Field {fw_key}: {fw_value}")
        
        elif field_num == 5:  # Device category
            if isinstance(field_value, int):
                print(f"{indent}   Category: {field_value} ({explain_device_category(field_value)})")
            else:
                print(f"{indent}   Category: {field_value} (Type: {type(field_value).__name__})")
        
        elif field_num == 6:  # Issues
            if isinstance(field_value, list):
                print(f"{indent}   🚨 {len(field_value)} security issue(s) found:")
                
                for i, issue in enumerate(field_value):
                    if isinstance(issue, dict):
                        print(f"\n{indent}      🔴 Issue #{i+1}:")
                        if 0 in issue:  # title
                            print(f"{indent}         Title: {issue[0]}")
                        if 1 in issue:  # cvss-score
                            print(f"{indent}         CVSS Score: {issue[1]}")
                        if 2 in issue:  # cvss-vector
                            print(f"{indent}         CVSS Vector: {issue[2]}")
                        if 3 in issue:  # cwe
                            print(f"{indent}         CWE: {issue[3]}")
                        if 4 in issue:  # description
                            desc = issue[4]
                            if len(desc) > 100:
                                desc = desc[:100] + "..."
                            print(f"{indent}         Description: {desc}")
                        if 5 in issue:  # cve
                            print(f"{indent}         CVE: {issue[5]}")
            else:
                print(f"{indent}   Issues: {type(field_value).__name__}")
        
        elif field_num == 7:  # Methodology
            print(f"{indent}   Method: {field_value}")
        
        elif field_num == 8:  # Security Review Provider
            print(f"{indent}   Provider: {field_value}")
        
        else:
            print(f"{indent}   Value: {field_value} (Type: {type(field_value).__name__})")

def main():
    """Main function for command-line usage."""
    if len(sys.argv) < 2:
        print("Usage: python cbor_human_inspector.py <cbor_file> [--show-raw]")
        print("\nThis tool provides human-readable inspection of CBOR CoRIM files.")
        print("Perfect for auditors who need to visually verify CoRIM contents.")
        print("\nOptions:")
        print("  --show-raw    Show raw CBOR data in addition to decoded structure")
        print("\nExample:")
        print("  python cbor_human_inspector.py my_corim.cbor")
        print("  python cbor_human_inspector.py my_corim.cbor --show-raw")
        return 1
    
    cbor_file = sys.argv[1]
    show_raw = "--show-raw" in sys.argv
    
    if not os.path.exists(cbor_file):
        print(f"❌ Error: File '{cbor_file}' not found")
        return 1
    
    try:
        with open(cbor_file, "rb") as f:
            cbor_data = f.read()
        
        print(f"📂 Inspecting file: {cbor_file}")
        inspect_corim_structure(cbor_data, show_raw_data=show_raw)
        
        print_header("Inspection Complete", 2)
        print("✅ Human-readable analysis finished successfully")
        print("📋 This report can be used by auditors to verify CoRIM structure and content")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
