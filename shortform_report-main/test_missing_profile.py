#!/usr/bin/env python3
"""
Test script to demonstrate profile validation by creating a CoRIM without the profile field.
This shows how the inspector flags missing required fields.
"""

import cbor2
import sys
import os
from datetime import datetime
from cbor_human_inspector import inspect_corim_structure

def create_corim_without_profile():
    """Create a CoRIM structure missing the profile field for testing."""
    
    # Create a minimal COMID content
    comid_content = {
        1: {  # tag-identity
            0: "test-comid-without-profile"  # tag-id
        },
        4: {  # triples
            10: [  # conditional-endorsement-triples
                [
                    [{}],  # conditions (empty for simplicity)
                    [  # endorsements
                        [
                            {},  # environment (empty for simplicity)
                            [  # measurements
                                {
                                    1: {  # measurement-values-map
                                        -1: {  # SFR extension
                                            0: "1.1",  # framework version
                                            1: "1.0",  # report version
                                            2: cbor2.CBORTag(1, int(datetime.now().timestamp())),  # completion date
                                            3: 1,  # scope number
                                            4: {  # firmware identifiers
                                                0: "Test Vendor",
                                                1: "Test Product",
                                                2: "1.0.0"
                                            },
                                            5: [  # issues
                                                {
                                                    0: "Test Issue",
                                                    1: "5.0",
                                                    2: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                                    3: "CWE-200",
                                                    4: "Test description"
                                                }
                                            ]
                                        }
                                    }
                                }
                            ]
                        ]
                    ]
                ]
            ]
        }
    }
    
    # Encode COMID as CBOR
    comid_cbor = cbor2.dumps(comid_content)
    
    # Create CoRIM structure WITHOUT profile field (field 3)
    corim_content = {
        0: "test-corim-no-profile",  # CoRIM ID
        1: [  # Tags
            cbor2.CBORTag(506, comid_cbor)  # COMID tag
        ],
        # NOTE: Field 3 (profile) is intentionally missing!
        5: [  # Entities
            {
                0: "Test Entity",  # entity-name
                2: [1]  # roles (tag-maintainer)
            }
        ]
    }
    
    # Wrap in CoRIM tag
    corim_tagged = cbor2.CBORTag(501, corim_content)
    
    # Encode as CBOR
    corim_cbor = cbor2.dumps(corim_tagged)
    
    return corim_cbor

def main():
    """Main test function."""
    print("=" * 80)
    print("  Testing Profile Validation - Missing Profile Field")
    print("=" * 80)
    print("Creating a CoRIM structure WITHOUT the required profile field...")
    print("This should trigger validation warnings in the inspector.")
    
    # Create CoRIM without profile
    corim_data = create_corim_without_profile()
    
    # Save to file for inspection
    output_file = "test_corim_no_profile.cbor"
    with open(output_file, "wb") as f:
        f.write(corim_data)
    
    print(f"\n✅ Test CoRIM (missing profile) saved to: {output_file}")
    print(f"📊 File size: {len(corim_data)} bytes")
    
    print("\n" + "=" * 80)
    print("  Running Inspector on CoRIM Missing Profile")
    print("=" * 80)
    
    # Run the inspector - this should show validation errors
    inspect_corim_structure(corim_data, show_raw_data=False)
    
    print("\n" + "=" * 80)
    print("  Test Complete")
    print("=" * 80)
    print(f"📂 Generated file: {output_file}")
    print("🔍 You can also run the inspector directly:")
    print(f"   python cbor_human_inspector.py {output_file}")
    print("\n⚠️  Expected result: Inspector should flag missing profile field!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
