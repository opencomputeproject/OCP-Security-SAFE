#!/usr/bin/env python3
"""
CBOR Structure Analyzer for CoRIM validation.
This script decodes CBOR and provides detailed structure analysis.
"""

import cbor2
from datetime import datetime

def decode_cbor_recursively(data, indent=0):
    """Recursively decode CBOR data and format it for analysis."""
    prefix = "  " * indent
    
    if isinstance(data, cbor2.CBORTag):
        print(f"{prefix}CBORTag({data.tag}): {type(data.value).__name__}")
        if isinstance(data.value, bytes):
            print(f"{prefix}  Raw bytes length: {len(data.value)}")
            # Try to decode nested CBOR
            try:
                nested = cbor2.loads(data.value)
                print(f"{prefix}  Nested content:")
                decode_cbor_recursively(nested, indent + 2)
            except:
                print(f"{prefix}  Binary data (first 50 bytes): {data.value[:50].hex()}")
        else:
            decode_cbor_recursively(data.value, indent + 1)
    elif isinstance(data, dict):
        print(f"{prefix}Dict with {len(data)} keys:")
        for key, value in data.items():
            print(f"{prefix}  Key {key} ({type(key).__name__}):")
            decode_cbor_recursively(value, indent + 2)
    elif isinstance(data, list):
        print(f"{prefix}List with {len(data)} items:")
        for i, item in enumerate(data):
            print(f"{prefix}  Item {i}:")
            decode_cbor_recursively(item, indent + 2)
    elif isinstance(data, bytes):
        print(f"{prefix}Bytes ({len(data)}): {data[:20].hex()}{'...' if len(data) > 20 else ''}")
    elif isinstance(data, str):
        print(f"{prefix}String: '{data}'")
    elif isinstance(data, int):
        if data == 1759435582:  # Unix timestamp
            dt = datetime.fromtimestamp(data)
            print(f"{prefix}Integer: {data} (timestamp: {dt})")
        else:
            print(f"{prefix}Integer: {data}")
    else:
        print(f"{prefix}{type(data).__name__}: {data}")

def analyze_corim_structure():
    """Analyze the generated CoRIM structure."""
    print("=== CoRIM Structure Analysis ===\n")
    
    try:
        with open("test_corim_output.cbor", "rb") as f:
            cbor_data = f.read()
        
        print(f"Total CBOR size: {len(cbor_data)} bytes")
        print(f"First 50 bytes: {cbor_data[:50].hex()}\n")
        
        # Decode the CBOR
        decoded = cbor2.loads(cbor_data)
        
        print("=== Decoded Structure ===")
        decode_cbor_recursively(decoded)
        
        print("\n=== Structure Validation ===")
        
        # Validate top-level structure
        if isinstance(decoded, cbor2.CBORTag) and decoded.tag == 501:
            print("✓ Top-level CoRIM tag (501) is correct")
            corim_content = decoded.value
            
            if isinstance(corim_content, dict):
                print("✓ CoRIM content is a dictionary")
                
                # Check required fields
                required_fields = {0: "id", 1: "tags", 3: "profile", 5: "entities"}
                for field_num, field_name in required_fields.items():
                    if field_num in corim_content:
                        print(f"✓ Field {field_num} ({field_name}) present")
                    else:
                        print(f"✗ Field {field_num} ({field_name}) missing")
                
                # Validate profile field specifically
                if 3 in corim_content:
                    profile = corim_content[3]
                    if isinstance(profile, cbor2.CBORTag) and profile.tag == 111:
                        print("✓ Profile field properly tagged with OID tag (111)")
                        profile_oid = profile.value
                        expected_oid = bytes.fromhex('060A2B0601040182F4170101')  # OID 1.3.6.1.4.1.42623.1.1
                        if profile_oid == expected_oid:
                            print("✓ Profile OID matches expected value (1.3.6.1.4.1.42623.1.1)")
                        else:
                            print(f"✗ Profile OID mismatch. Expected: {expected_oid.hex()}, Got: {profile_oid.hex()}")
                    else:
                        print("✗ Profile field not properly tagged or missing OID tag")
                
                # Analyze tags structure
                if 1 in corim_content:
                    tags = corim_content[1]
                    if isinstance(tags, list) and len(tags) > 0:
                        print(f"✓ Tags field is a list with {len(tags)} items")
                        
                        first_tag = tags[0]
                        if isinstance(first_tag, cbor2.CBORTag) and first_tag.tag == 506:
                            print("✓ First tag has correct COMID tag (506)")
                            
                            # Decode the COMID content
                            try:
                                comid_content = cbor2.loads(first_tag.value)
                                print("✓ COMID content successfully decoded")
                                
                                # Check COMID structure
                                if isinstance(comid_content, dict):
                                    print("✓ COMID content is a dictionary")
                                    
                                    if 1 in comid_content:  # tag-identity
                                        print("✓ COMID has tag-identity field")
                                    
                                    if 4 in comid_content:  # triples
                                        print("✓ COMID has triples field")
                                        triples = comid_content[4]
                                        
                                        if isinstance(triples, dict) and 10 in triples:
                                            print("✓ Triples has conditional-endorsement-triples field (10)")
                                            
                                            cond_endorsements = triples[10]
                                            if isinstance(cond_endorsements, list):
                                                print(f"✓ Conditional endorsements is a list with {len(cond_endorsements)} items")
                                                
                                                # Analyze the structure deeper
                                                if len(cond_endorsements) > 0:
                                                    first_cond = cond_endorsements[0]
                                                    if isinstance(first_cond, list) and len(first_cond) == 2:
                                                        print("✓ First conditional endorsement has correct structure [conditions, endorsements]")
                                                        
                                                        conditions, endorsements = first_cond
                                                        
                                                        # Check conditions
                                                        if isinstance(conditions, list):
                                                            print(f"✓ Conditions is a list with {len(conditions)} items")
                                                        
                                                        # Check endorsements
                                                        if isinstance(endorsements, list):
                                                            print(f"✓ Endorsements is a list with {len(endorsements)} items")
                                                            
                                                            if len(endorsements) > 0:
                                                                first_endorsement = endorsements[0]
                                                                if isinstance(first_endorsement, list) and len(first_endorsement) == 2:
                                                                    print("✓ First endorsement has correct structure [environment, measurements]")
                                                                    
                                                                    env, measurements = first_endorsement
                                                                    if isinstance(measurements, list) and len(measurements) > 0:
                                                                        first_measurement = measurements[0]
                                                                        if isinstance(first_measurement, dict) and 1 in first_measurement:
                                                                            mval = first_measurement[1]
                                                                            if isinstance(mval, dict) and -1 in mval:
                                                                                print("✓ Found SFR extension (-1) in measurement values")
                                                                                
                                                                                # Validate SFR data structure
                                                                                sfr_data = mval[-1]
                                                                                if isinstance(sfr_data, dict):
                                                                                    print(f"  - SFR data contains {len(sfr_data)} fields")
                                                                                    if 0 in sfr_data:
                                                                                        print(f"  - Framework version: {sfr_data[0]}")
                                                                                    if 1 in sfr_data:
                                                                                        print(f"  - Report version: {sfr_data[1]}")
                                                                                    if 3 in sfr_data:
                                                                                        print(f"  - Scope number: {sfr_data[3]}")
                                                                                sfr_data = mval[-1]
                                                                                
                                                                                # Check SFR structure
                                                                                sfr_fields = {
                                                                                    0: "review-framework-version",
                                                                                    1: "report-version", 
                                                                                    2: "completion-date",
                                                                                    3: "scope-number",
                                                                                    4: "fw-identifiers"
                                                                                }
                                                                                
                                                                                for field_num, field_name in sfr_fields.items():
                                                                                    if field_num in sfr_data:
                                                                                        print(f"✓ SFR field {field_num} ({field_name}) present")
                                                                                    else:
                                                                                        print(f"✗ SFR field {field_num} ({field_name}) missing")
                                                                                
                                                                                # Check completion date format
                                                                                if 2 in sfr_data:
                                                                                    completion_date = sfr_data[2]
                                                                                    if isinstance(completion_date, cbor2.CBORTag) and completion_date.tag == 1:
                                                                                        print("✓ Completion date has correct CBOR tag (1)")
                                                                                        timestamp = completion_date.value
                                                                                        dt = datetime.fromtimestamp(timestamp)
                                                                                        print(f"  Date: {dt}")
                                                                                    elif isinstance(completion_date, datetime):
                                                                                        print("✓ Completion date properly decoded as datetime (CBOR tag 1 was present)")
                                                                                        print(f"  Date: {completion_date}")
                                                                                    else:
                                                                                        print("✗ Completion date missing CBOR tag (1)")
                                                                                        print(f"  Found type: {type(completion_date)}, value: {completion_date}")
                                            
                            except Exception as e:
                                print(f"✗ Error decoding COMID content: {e}")
                        else:
                            print("✗ First tag missing COMID tag (506)")
                    else:
                        print("✗ Tags field is not a proper list")
                else:
                    print("✗ Tags field missing")
            else:
                print("✗ CoRIM content is not a dictionary")
        else:
            print("✗ Missing or incorrect top-level CoRIM tag")
        
    except Exception as e:
        print(f"Error analyzing structure: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    analyze_corim_structure()
