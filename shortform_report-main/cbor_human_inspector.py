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

def format_bytes_display(data, max_length=16):
    """Format bytes for human-readable display."""
    if len(data) <= max_length:
        return data.hex()
    else:
        start_bytes = max_length // 2
        end_bytes = max_length // 2
        return f"{data[:start_bytes].hex()}...{data[-end_bytes:].hex()} ({len(data)} bytes total)"

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

def explain_environment_field(field_num):
    """Explain environment fields in identity claims."""
    env_fields = {
        0: "Class ID - Identifies the class/type of the component",
        1: "Instance ID - Unique identifier for this specific instance",
        2: "Group ID - Group identifier for related components"
    }
    return env_fields.get(field_num, f"Environment field {field_num}")

def explain_class_id_field(field_num):
    """Explain class-id fields."""
    class_fields = {
        0: "Type - Type identifier for the class",
        1: "Vendor - Vendor name or identifier", 
        2: "Model/Product - Product or model name"
    }
    return class_fields.get(field_num, f"Class field {field_num}")

def explain_measurement_field(field_num):
    """Explain measurement fields."""
    measurement_fields = {
        0: "Measurement Key - Key identifying the measurement type",
        1: "Measurement Values - The actual measurement data",
        2: "Measurement Metadata - Additional metadata about the measurement"
    }
    return measurement_fields.get(field_num, f"Measurement field {field_num}")

def format_identity_claim_human_readable(claim, indent=""):
    """Format identity claims in a more human-readable way."""
    if isinstance(claim, list) and len(claim) == 2:
        # This looks like [environment, measurements] structure
        env, measurements = claim
        result = f"Identity Claim Structure:\n"
        
        # Format environment
        result += f"{indent}   Environment: "
        if isinstance(env, dict):
            result += "{\n"
            for env_key, env_value in env.items():
                result += f"{indent}      {explain_environment_field(env_key)}: "
                if env_key == 0 and isinstance(env_value, dict):  # class-id
                    result += "{\n"
                    for cid_key, cid_value in env_value.items():
                        result += f"{indent}         {explain_class_id_field(cid_key)}: "
                        if isinstance(cid_value, cbor2.CBORTag):
                            result += f"CBOR Tag {cid_value.tag}: {cid_value.value}\n"
                        elif isinstance(cid_value, bytes):
                            result += f"{format_bytes_display(cid_value)}\n"
                        else:
                            result += f"{cid_value}\n"
                    result += f"{indent}      }}\n"
                elif isinstance(env_value, bytes):
                    result += f"{format_bytes_display(env_value)}\n"
                else:
                    result += f"{env_value}\n"
            result += f"{indent}   }}\n"
        else:
            result += f"{env}\n"
        
        # Format measurements/claims
        result += f"{indent}   Claims/Measurements: "
        if isinstance(measurements, list):
            result += f"[\n"
            for i, measurement in enumerate(measurements):
                if isinstance(measurement, dict):
                    result += f"{indent}      Measurement #{i+1}: {{\n"
                    for m_key, m_value in measurement.items():
                        result += f"{indent}         {explain_measurement_field(m_key)}: "
                        if m_key == 1 and isinstance(m_value, dict):  # measurement-values
                            result += "{\n"
                            for mv_key, mv_value in m_value.items():
                                if mv_key == 1029:  # SFR extension key
                                    result += f"{indent}            SFR Extension (1029): {{\n"
                                    if isinstance(mv_value, dict):
                                        for sfr_key, sfr_value in mv_value.items():
                                            result += f"{indent}               {explain_sfr_field(sfr_key)}: "
                                            if sfr_key == 2 and isinstance(sfr_value, datetime):
                                                result += f"{sfr_value.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                                            elif sfr_key == 5 and isinstance(sfr_value, list):
                                                result += f"{len(sfr_value)} security issue(s)\n"
                                            elif sfr_key == 4:
                                                # Format firmware identifiers with enhanced byte display
                                                if isinstance(sfr_value, list):
                                                    result += f"[{len(sfr_value)} firmware item(s)]\n"
                                                    for fw_idx, fw_item in enumerate(sfr_value):
                                                        if isinstance(fw_item, dict):
                                                            result += f"{indent}                  Firmware #{fw_idx+1}:\n"
                                                            for fw_key, fw_value in fw_item.items():
                                                                if fw_key == 1 and isinstance(fw_value, list):  # hash arrays
                                                                    result += f"{indent}                     Hash Arrays:\n"
                                                                    for hash_idx, hash_item in enumerate(fw_value):
                                                                        if isinstance(hash_item, list) and len(hash_item) == 2:
                                                                            hash_type, hash_value = hash_item
                                                                            if isinstance(hash_value, bytes):
                                                                                hash_type_name = "SHA384" if hash_type == 7 else "SHA512" if hash_type == 8 else f"Type {hash_type}"
                                                                                result += f"{indent}                        {hash_type_name}: {format_bytes_display(hash_value)}\n"
                                                                else:
                                                                    result += f"{indent}                     {fw_key}: {fw_value}\n"
                                                else:
                                                    result += f"{sfr_value}\n"
                                            else:
                                                result += f"{sfr_value}\n"
                                    result += f"{indent}            }}\n"
                                else:
                                    result += f"{indent}            Extension {mv_key}: {mv_value}\n"
                            result += f"{indent}         }}\n"
                        else:
                            result += f"{format_value_recursively(m_value, indent + '            ')}\n"
                    result += f"{indent}      }}\n"
                else:
                    result += f"{indent}      Item #{i+1}: {measurement}\n"
            result += f"{indent}   ]\n"
        else:
            result += f"{measurements}\n"
        
        return result.rstrip()
    else:
        return format_value_recursively(claim, indent)

def format_value_recursively(value, indent="", max_depth=5, current_depth=0):
    """Recursively format CBOR values to show actual leaf data."""
    if current_depth >= max_depth:
        return f"{type(value).__name__} (max depth reached)"
    
    if isinstance(value, dict):
        if len(value) == 0:
            return "{} (empty dict)"
        
        result_lines = []
        for k, v in value.items():
            formatted_value = format_value_recursively(v, indent + "   ", max_depth, current_depth + 1)
            result_lines.append(f"{indent}   {k}: {formatted_value}")
        return "{\n" + "\n".join(result_lines) + f"\n{indent}}}"
    
    elif isinstance(value, list):
        if len(value) == 0:
            return "[] (empty list)"
        
        result_lines = []
        for i, item in enumerate(value):
            formatted_item = format_value_recursively(item, indent + "   ", max_depth, current_depth + 1)
            result_lines.append(f"{indent}   [{i}]: {formatted_item}")
        return "[\n" + "\n".join(result_lines) + f"\n{indent}]"
    
    elif isinstance(value, bytes):
        return format_bytes_display(value)
    
    elif isinstance(value, cbor2.CBORTag):
        return f"CBOR Tag {value.tag}: {format_value_recursively(value.value, indent, max_depth, current_depth + 1)}"
    
    elif isinstance(value, datetime):
        return f"{value.strftime('%Y-%m-%d %H:%M:%S UTC')} (datetime)"
    
    else:
        return str(value)

def explain_cbor_tag(tag_num):
    """Provide human-readable explanations for CBOR tags."""
    tag_explanations = {
        1: "POSIX timestamp (seconds since epoch)",
        18: "COSE-Sign (Multi-Signer COSE Signature)",
        61: "COSE-Sign1 (Single Signer COSE Signature)",
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

def explain_triple_type(triple_num):
    """Explain different types of triples in COMID."""
    triple_types = {
        0: "Reference Triples - Reference values for comparison",
        1: "Endorsed Triples - Endorsed/attested values", 
        9: "Identity Triples - Identity claims and attestations",
        10: "Conditional Endorsement Triples - Conditional endorsements with conditions"
    }
    return triple_types.get(triple_num, f"Unknown Triple Type {triple_num}")

def explain_sfr_field(field_num):
    """Explain SFR extension fields."""
    sfr_fields = {
        0: "Review Framework Version - Version of the OCP SAFE framework used",
        1: "Report Version - Version of this specific security review report",
        2: "Completion Date - When the security review was completed",
        3: "Scope Number - Numerical identifier for the review scope",
        4: "Firmware Identifiers - Information about the reviewed firmware",
        6: "Issues - List of security issues found during review",
        7: "Methodology - Review methodology used (whitebox, blackbox, etc.)",
        8: "Security Review Provider - Organization that performed the review"
    }
    return sfr_fields.get(field_num, f"Unknown SFR field {field_num}")

def extract_corim_from_cose_sign1(cose_sign1_value):
    """Extract CoRIM payload from COSE-Sign1 structure."""
    try:
        # Handle case where COSE-Sign1 value is wrapped in another CBOR tag
        actual_value = cose_sign1_value
        if isinstance(cose_sign1_value, cbor2.CBORTag):
            print(f"   🔍 COSE-Sign1 value is wrapped in CBOR tag {cose_sign1_value.tag}")
            actual_value = cose_sign1_value.value
        
        # COSE-Sign1 structure: [protected, unprotected, payload, signature]
        if isinstance(actual_value, list) and len(actual_value) >= 3:
            payload = actual_value[2]  # The payload is the third element
            print(f"   🔍 Extracted payload from COSE-Sign1, type: {type(payload)}")
            
            if isinstance(payload, bytes):
                # The payload should contain a CBOR-encoded structure with CoRIM data
                # According to the cwt library usage in OcpReportLib, the CoRIM is in a claims structure
                try:
                    claims = cbor2.loads(payload)
                    print(f"   🔍 Decoded claims from payload, type: {type(claims)}")
                    # Look for the CoRIM data in the claims (custom claim -65537 based on OcpReportLib)
                    if isinstance(claims, dict) and -65537 in claims:
                        corim_cbor = claims[-65537]
                        print(f"   ✅ Found CoRIM data in custom claim -65537")
                        if isinstance(corim_cbor, bytes):
                            # Decode the CoRIM CBOR
                            corim_decoded = cbor2.loads(corim_cbor)
                            if isinstance(corim_decoded, cbor2.CBORTag) and corim_decoded.tag == 501:
                                return corim_decoded.value
                except Exception as e:
                    print(f"   ⚠️  Error decoding claims from payload: {e}")
                    
                # Fallback: try to decode payload directly as CoRIM
                try:
                    corim_decoded = cbor2.loads(payload)
                    print(f"   🔍 Direct payload decode result: {type(corim_decoded)}")
                    if isinstance(corim_decoded, cbor2.CBORTag) and corim_decoded.tag == 501:
                        print(f"   ✅ Found CoRIM tag (501) directly in payload")
                        return corim_decoded.value
                    elif isinstance(corim_decoded, dict):
                        # Might be the CoRIM content directly
                        print(f"   ✅ Found CoRIM content directly in payload")
                        return corim_decoded
                except Exception as e:
                    print(f"   ⚠️  Error decoding payload directly: {e}")
            
            print(f"   ⚠️  Payload type: {type(payload)}, length: {len(payload) if hasattr(payload, '__len__') else 'N/A'}")
            return None
        else:
            print(f"   ❌ Invalid COSE-Sign1 structure: expected list with ≥3 elements, got {type(actual_value)}")
            if isinstance(actual_value, list):
                print(f"   🔍 List has {len(actual_value)} elements")
            return None
    except Exception as e:
        print(f"   ❌ Error extracting CoRIM from COSE-Sign1: {e}")
        import traceback
        traceback.print_exc()
        return None

def extract_corim_from_cose_sign(cose_sign_value):
    """Extract CoRIM payload from COSE-Sign structure (multi-signer)."""
    try:
        # Handle case where COSE-Sign value is wrapped in another CBOR tag
        actual_value = cose_sign_value
        if isinstance(cose_sign_value, cbor2.CBORTag):
            print(f"   🔍 COSE-Sign value is wrapped in CBOR tag {cose_sign_value.tag}")
            actual_value = cose_sign_value.value
        
        # COSE-Sign structure: [protected, unprotected, payload, signatures]
        if isinstance(actual_value, list) and len(actual_value) >= 3:
            payload = actual_value[2]  # The payload is the third element
            print(f"   🔍 Extracted payload from COSE-Sign, type: {type(payload)}")
            
            if len(actual_value) >= 4:
                signatures = actual_value[3]
                if isinstance(signatures, list):
                    print(f"   🔍 Found {len(signatures)} signature(s) in COSE-Sign")
            
            if isinstance(payload, bytes):
                # The payload should contain a CBOR-encoded structure with CoRIM data
                # According to the cwt library usage in OcpReportLib, the CoRIM is in a claims structure
                try:
                    claims = cbor2.loads(payload)
                    print(f"   🔍 Decoded claims from payload, type: {type(claims)}")
                    # Look for the CoRIM data in the claims (custom claim -65537 based on OcpReportLib)
                    if isinstance(claims, dict) and -65537 in claims:
                        corim_cbor = claims[-65537]
                        print(f"   ✅ Found CoRIM data in custom claim -65537")
                        if isinstance(corim_cbor, bytes):
                            # Decode the CoRIM CBOR
                            corim_decoded = cbor2.loads(corim_cbor)
                            if isinstance(corim_decoded, cbor2.CBORTag) and corim_decoded.tag == 501:
                                return corim_decoded.value
                except Exception as e:
                    print(f"   ⚠️  Error decoding claims from payload: {e}")
                    
                # Fallback: try to decode payload directly as CoRIM
                try:
                    corim_decoded = cbor2.loads(payload)
                    print(f"   🔍 Direct payload decode result: {type(corim_decoded)}")
                    if isinstance(corim_decoded, cbor2.CBORTag) and corim_decoded.tag == 501:
                        print(f"   ✅ Found CoRIM tag (501) directly in payload")
                        return corim_decoded.value
                    elif isinstance(corim_decoded, dict):
                        # Might be the CoRIM content directly
                        print(f"   ✅ Found CoRIM content directly in payload")
                        return corim_decoded
                except Exception as e:
                    print(f"   ⚠️  Error decoding payload directly: {e}")
            
            print(f"   ⚠️  Payload type: {type(payload)}, length: {len(payload) if hasattr(payload, '__len__') else 'N/A'}")
            return None
        else:
            print(f"   ❌ Invalid COSE-Sign structure: expected list with ≥3 elements, got {type(actual_value)}")
            if isinstance(actual_value, list):
                print(f"   🔍 List has {len(actual_value)} elements")
            return None
    except Exception as e:
        print(f"   ❌ Error extracting CoRIM from COSE-Sign: {e}")
        import traceback
        traceback.print_exc()
        return None

def inspect_corim_content_details(corim_content):
    """Inspect the detailed content of a CoRIM structure."""
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
                        elif isinstance(tag, bytes):
                            print(f"      🔍 COMID stored as raw bytes, attempting to decode...")
                            
                            try:
                                # Try to decode the bytes as CBOR
                                decoded_tag = cbor2.loads(tag)
                                if isinstance(decoded_tag, cbor2.CBORTag) and decoded_tag.tag == 506:
                                    print(f"      ✅ Found COMID tag (506) after decoding bytes")
                                    # The value might already be decoded or might need further decoding
                                    if isinstance(decoded_tag.value, bytes):
                                        comid_content = cbor2.loads(decoded_tag.value)
                                    else:
                                        comid_content = decoded_tag.value
                                    inspect_comid_content(comid_content, indent="      ")
                                elif isinstance(decoded_tag, dict):
                                    print(f"      ✅ Found COMID content directly in bytes")
                                    inspect_comid_content(decoded_tag, indent="      ")
                                else:
                                    print(f"      ❌ Decoded bytes but found unexpected structure: {type(decoded_tag)}")
                            except Exception as e:
                                print(f"      ❌ Error decoding COMID bytes: {e}")
                        else:
                            print(f"      ❌ Invalid COMID tag structure: {type(tag)}")
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
                inspect_corim_content_details(decoded.value)
                
            elif decoded.tag == 61:  # COSE-Sign1 tag
                print("✅ This is a signed CoRIM with COSE-Sign1 signature")
                print("🔓 Extracting CoRIM payload from COSE signature...")
                
                # Extract CoRIM from COSE-Sign1 structure
                corim_payload = extract_corim_from_cose_sign1(decoded.value)
                if corim_payload:
                    print("✅ Successfully extracted CoRIM payload from signature")
                    inspect_corim_content_details(corim_payload)
                else:
                    print("❌ Failed to extract CoRIM payload from COSE-Sign1 structure")
                    
            elif decoded.tag == 18:  # COSE-Sign tag
                print("✅ This is a signed CoRIM with COSE-Sign signature (multi-signer)")
                print("🔓 Extracting CoRIM payload from COSE signature...")
                
                # Extract CoRIM from COSE-Sign structure
                corim_payload = extract_corim_from_cose_sign(decoded.value)
                if corim_payload:
                    print("✅ Successfully extracted CoRIM payload from signature")
                    inspect_corim_content_details(corim_payload)
                else:
                    print("❌ Failed to extract CoRIM payload from COSE-Sign structure")
            else:
                print(f"❌ Expected CoRIM tag (501), COSE-Sign1 tag (61), or COSE-Sign tag (18), found tag {decoded.tag}")
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
                print(f"{indent}      📋 Found {len(field_value)} triple type(s)")
                
                # Check for different types of triples
                triples_found = False
                
                # Check for reference-triples (field 0)
                if 0 in field_value:
                    ref_triples = field_value[0]
                    if isinstance(ref_triples, list):
                        print(f"{indent}      📚 Reference Triples: {len(ref_triples)} item(s)")
                        triples_found = True
                        for i, triple in enumerate(ref_triples):
                            print(f"{indent}         📖 Reference #{i+1}: {type(triple).__name__}")
                
                # Check for endorsed-triples (field 1)  
                if 1 in field_value:
                    end_triples = field_value[1]
                    if isinstance(end_triples, list):
                        print(f"{indent}      ✅ Endorsed Triples: {len(end_triples)} item(s)")
                        triples_found = True
                        for i, triple in enumerate(end_triples):
                            print(f"{indent}         ✅ Endorsement #{i+1}: {type(triple).__name__}")
                
                # Check for identity-triples (field 9)
                if 9 in field_value:
                    identity_triples = field_value[9]
                    if isinstance(identity_triples, list):
                        print(f"{indent}      🆔 Identity Triples: {len(identity_triples)} item(s)")
                        triples_found = True
                        
                        for i, identity_triple in enumerate(identity_triples):
                            if isinstance(identity_triple, list) and len(identity_triple) == 2:
                                env, claims = identity_triple
                                print(f"\n{indent}         🆔 Identity #{i+1}:")
                                print(f"{indent}            Environment: {type(env).__name__}")
                                
                                if isinstance(claims, list):
                                    print(f"{indent}            🏷️  {len(claims)} identity claim(s):")
                                    
                                    for j, claim in enumerate(claims):
                                        if isinstance(claim, dict):
                                            print(f"\n{indent}            📋 Identity Claim #{j+1}:")
                                            
                                            # Check for common identity claim fields
                                            if 0 in claim:  # class-id
                                                class_id = claim[0]
                                                if isinstance(class_id, dict):
                                                    print(f"{indent}               🏷️  Class ID:")
                                                    for cid_key, cid_value in class_id.items():
                                                        if cid_key == 0:  # type
                                                            print(f"{indent}                  Type: {cid_value}")
                                                        elif cid_key == 1:  # value
                                                            if isinstance(cid_value, bytes):
                                                                print(f"{indent}                  Value: {format_bytes_display(cid_value)}")
                                                            else:
                                                                print(f"{indent}                  Value: {cid_value}")
                                                        else:
                                                            print(f"{indent}                  Field {cid_key}: {cid_value}")
                                                else:
                                                    print(f"{indent}               🏷️  Class ID: {class_id}")
                                            
                                            if 1 in claim:  # instance-id
                                                instance_id = claim[1]
                                                if isinstance(instance_id, bytes):
                                                    print(f"{indent}               🆔 Instance ID: {format_bytes_display(instance_id)}")
                                                else:
                                                    print(f"{indent}               🆔 Instance ID: {instance_id}")
                                            
                                            # Check for other claim fields
                                            for claim_key in claim.keys():
                                                if claim_key not in [0, 1]:
                                                    claim_value = claim[claim_key]
                                                    print(f"{indent}               Field {claim_key}: {format_value_recursively(claim_value, indent + '                  ')}")
                                        elif isinstance(claim, list):
                                            print(f"\n{indent}            📋 Identity Claim #{j+1} (List with {len(claim)} items):")
                                            # Use the enhanced identity claim formatter
                                            formatted_claim = format_identity_claim_human_readable(claim, indent + "            ")
                                            print(f"{indent}            {formatted_claim}")
                                        else:
                                            print(f"{indent}            📋 Identity Claim #{j+1}: {format_value_recursively(claim, indent + '               ')}")
                                else:
                                    print(f"{indent}            🏷️  Claims: {type(claims).__name__}")
                            else:
                                print(f"{indent}         🆔 Identity #{i+1}: Invalid structure - {type(identity_triple).__name__}")
                
                # Check for conditional-endorsement-triples (field 10)
                if 10 in field_value:
                    cond_endorsements = field_value[10]
                    if isinstance(cond_endorsements, list):
                        print(f"{indent}      🔄 Conditional Endorsement Triples: {len(cond_endorsements)} item(s)")
                        triples_found = True
                        
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
                                            else:
                                                print(f"{indent}            📏 Measurements: {type(measurements).__name__}")
                                        else:
                                            print(f"{indent}         🎯 Endorsement #{j+1}: Invalid structure - {type(endorsement).__name__}")
                                else:
                                    print(f"{indent}         Endorsements: {type(endorsements).__name__}")
                            else:
                                print(f"{indent}      📋 Conditional Endorsement #{i+1}: Invalid structure - {type(cond_endorsement).__name__}")
                
                # Check for any other triple types
                for triple_key in field_value.keys():
                    if triple_key not in [0, 1, 9, 10]:
                        triple_data = field_value[triple_key]
                        print(f"{indent}      🔍 {explain_triple_type(triple_key)}: {type(triple_data).__name__}")
                        if isinstance(triple_data, list):
                            print(f"{indent}         Contains {len(triple_data)} item(s)")
                        triples_found = True
                
                if not triples_found:
                    print(f"{indent}      ⚠️  No recognized triple types found in triples structure")
                    print(f"{indent}      🔍 Available keys: {list(field_value.keys())}")
            else:
                print(f"{indent}   ❌ Triples field should be a dictionary, found: {type(field_value)}")

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
            elif isinstance(field_value, list):
                print(f"{indent}   📦 Firmware Info ({len(field_value)} items):")
                for i, fw_item in enumerate(field_value):
                    print(f"{indent}      Firmware #{i+1}:")
                    if isinstance(fw_item, dict):
                        for fw_key, fw_value in fw_item.items():
                            if fw_key == 0:  # vendor
                                if isinstance(fw_value, dict):
                                    print(f"{indent}         Vendor Info:")
                                    for v_key, v_value in fw_value.items():
                                        if v_key == 0:
                                            print(f"{indent}            Version: {v_value}")
                                        else:
                                            print(f"{indent}            Field {v_key}: {v_value}")
                                else:
                                    print(f"{indent}         Vendor: {fw_value}")
                            elif fw_key == 1:  # product - often contains hash arrays
                                if isinstance(fw_value, list):
                                    print(f"{indent}         Product Hashes ({len(fw_value)} items):")
                                    for j, hash_item in enumerate(fw_value):
                                        if isinstance(hash_item, list) and len(hash_item) == 2:
                                            hash_type, hash_value = hash_item
                                            if isinstance(hash_value, bytes):
                                                hash_type_name = "SHA384" if hash_type == 7 else "SHA512" if hash_type == 8 else f"Hash Type {hash_type}"
                                                print(f"{indent}            {hash_type_name}: {format_bytes_display(hash_value)}")
                                            else:
                                                print(f"{indent}            Hash #{j+1}: Type {hash_type}, Value: {hash_value}")
                                        else:
                                            print(f"{indent}            Hash #{j+1}: {hash_item}")
                                else:
                                    print(f"{indent}         Product: {fw_value}")
                            elif fw_key == 2:  # version
                                print(f"{indent}         Version: {fw_value}")
                            elif fw_key == 3:  # hash-sha384
                                print(f"{indent}         SHA384: {format_bytes_display(fw_value)}")
                            elif fw_key == 4:  # hash-sha512
                                print(f"{indent}         SHA512: {format_bytes_display(fw_value)}")
                            else:
                                print(f"{indent}         Field {fw_key}: {fw_value}")
                    else:
                        print(f"{indent}         {format_value_recursively(fw_item, indent + '         ')}")
            else:
                print(f"{indent}   📦 Firmware Info: {format_value_recursively(field_value, indent + '      ')}")
                
        elif field_num == 5:  # Issues
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

def show_help():
    """Display help information."""
    print("CBOR CoRIM Human-Readable Inspector")
    print("=" * 50)
    print("\nDESCRIPTION:")
    print("  This tool provides human-readable inspection of CBOR CoRIM files.")
    print("  Perfect for auditors who need to visually verify CoRIM contents.")
    print("  Supports both unsigned CoRIMs and signed CoRIMs (COSE-Sign1/COSE-Sign).")
    print("\nUSAGE:")
    print("  python cbor_human_inspector.py <cbor_file> [options]")
    print("\nARGUMENTS:")
    print("  cbor_file     Path to the CBOR CoRIM file to inspect")
    print("\nOPTIONS:")
    print("  --show-raw    Show raw CBOR data in addition to decoded structure")
    print("  --help, -h    Show this help message and exit")
    print("\nEXAMPLES:")
    print("  python cbor_human_inspector.py my_corim.cbor")
    print("  python cbor_human_inspector.py my_corim.cbor --show-raw")
    print("  python cbor_human_inspector.py signed_corim.jws")
    print("\nSUPPORTED FORMATS:")
    print("  • Unsigned CoRIMs (CBOR tag 501)")
    print("  • COSE-Sign1 signed CoRIMs (CBOR tag 61)")
    print("  • COSE-Sign multi-signer CoRIMs (CBOR tag 18)")
    print("\nOUTPUT:")
    print("  The tool provides detailed analysis including:")
    print("  • CoRIM structure validation")
    print("  • COMID tag inspection")
    print("  • Identity claims and measurements")
    print("  • SFR extension data (if present)")
    print("  • Human-readable field explanations")

def main():
    """Main function for command-line usage."""
    # Check for help flags first
    if "--help" in sys.argv or "-h" in sys.argv:
        show_help()
        return 0
    
    if len(sys.argv) < 2:
        print("Usage: python cbor_human_inspector.py <cbor_file> [options]")
        print("Use --help for detailed usage information.")
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
