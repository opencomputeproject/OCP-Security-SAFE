# CBOR CoRIM Human-Readable Inspector - Auditor Guide

## Overview

The CBOR CoRIM Human-Readable Inspector is a tool designed specifically for security auditors and reviewers who need to visually inspect and verify the contents of CBOR-encoded CoRIM (CBOR Object Representation of Information Model) files. This tool converts the binary CBOR format into a clear, human-readable report that shows all fields, their meanings, and their values.

## Why This Tool is Needed

CBOR is a binary format that is not human-readable in its raw form. While CBOR is efficient for machine processing, auditors need to be able to:

- **Verify Data Integrity**: Ensure all expected fields are present and correctly formatted
- **Validate Content**: Check that security review data matches expectations
- **Audit Compliance**: Confirm that CoRIM files follow the OCP SAFE SFR profile specification
- **Troubleshoot Issues**: Identify problems in CoRIM generation or encoding

## Quick Start

### Basic Usage

```bash
# Inspect a CoRIM file
python cbor_human_inspector.py my_security_review.cbor

# Show raw CBOR data in addition to decoded structure (currently only supports unsigned CoRIM)
python cbor_human_inspector.py my_security_review.cbor --show-raw
```

## Understanding the Output

The inspector provides a hierarchical view of the CoRIM structure with clear explanations:

### 1. Top-Level Information
```
📊 Total CBOR size: 1286 bytes
🔍 Analysis timestamp: 2025-01-15 14:30:22
✅ CBOR Tag Found: 501 (CoRIM (CBOR Object Representation of Information Model))
```

### 2. CoRIM Fields Breakdown

The tool explains each field with its purpose:

- **Field 0 (CoRIM ID)**: Unique identifier for this CoRIM
- **Field 1 (Tags)**: List of COMID tags containing the actual security review data
- **Field 3 (Profile)**: Should show OID 1.3.6.1.4.1.42623.1.1 for OCP SAFE SFR
- **Field 5 (Entities)**: Information about who created/maintains this CoRIM

### 3. Security Review Data (SFR Extension)

The most important section for auditors shows the actual security review findings:

```
🔐 SFR Extension (-1) Found!
   📋 SFR Data contains 7 fields:
   
   🔸 Field 0: Review Framework Version
   🔸 Field 1: Report Version  
   🔸 Field 2: Completion Date
   🔸 Field 3: Scope Number
   🔸 Field 4: Firmware Identifiers
   🔸 Field 5: Device Category
   🔸 Field 6: Issues - List of security issues found
```

### 4. Security Issues Detail

Each security issue is clearly displayed:

```
🔴 Issue #1:
   Title: Buffer Overflow in Firmware Parser
   CVSS Score: 9.1
   CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
   CWE: CWE-787
   Description: A critical buffer overflow vulnerability...
   CVE: CVE-2025-0123
```

## Validation Checklist for Auditors

When reviewing a CoRIM file, verify the following:

### ✅ Structure Validation
- [ ] File has correct CoRIM CBOR tag (501)
- [ ] CoRIM contains required fields (0, 1, 3, 5) - **Inspector automatically checks this**
- [ ] Profile field (3) contains OID 1.3.6.1.4.1.42623.1.1 - **Inspector flags if missing**
- [ ] Tags field (1) contains at least one COMID tag (506)

### ✅ SFR Extension Validation
- [ ] SFR extension (-1) is present in measurement values
- [ ] All required SFR fields are present (0-6)
- [ ] Completion date is properly encoded with CBOR timestamp tag
- [ ] Device category is a valid integer (0-5)
- [ ] Framework version matches expected value

### ✅ Security Issues Validation
- [ ] Each issue has required fields: title, CVSS score, CVSS vector, CWE, description
- [ ] CVSS scores are valid (0.0-10.0)
- [ ] CVSS vectors follow proper format
- [ ] CWE identifiers are properly formatted
- [ ] CVE identifiers are present when applicable

### ✅ Data Quality Validation
- [ ] Firmware identifiers contain vendor, product, version information
- [ ] Hash values are properly formatted (SHA384/SHA512)
- [ ] Entity information includes name and roles
- [ ] All text fields contain meaningful content

## Common Issues and Troubleshooting

### Missing Profile Field
```
❌ Profile should be OID tag (111), found: <type>
```
**Solution**: The CoRIM must include the OCP SAFE SFR profile OID. Check CoRIM generation code.

### Incorrect Extension Value
```
❌ Missing SFR extension (-1)
```
**Solution**: Verify that the SFR extension is using -1 (private extension) instead of 1029.

### Invalid Date Encoding
```
❌ Should be datetime with CBOR tag 1
```
**Solution**: Completion dates must be encoded with CBOR timestamp tag (1).

### Missing Required Fields
```
❌ Required CoRIM field X missing
```
**Solution**: Check that all mandatory CoRIM fields are included during generation.

## Device Category Reference

The tool automatically translates device category numbers:

- **0**: CPU (Central Processing Unit)
- **1**: GPU (Graphics Processing Unit)
- **2**: BMC (Baseboard Management Controller)
- **3**: NIC (Network Interface Controller)
- **4**: Storage (Storage devices)
- **5**: Other (Other device types)

## CBOR Tag Reference

Common CBOR tags you'll see in the output:

- **Tag 1**: POSIX timestamp (seconds since epoch)
- **Tag 111**: Object Identifier (OID)
- **Tag 501**: CoRIM (CBOR Object Representation of Information Model)
- **Tag 506**: COMID (Concise Module Identifier)

## Advanced Usage

### Comparing Multiple CoRIMs

```bash
# Inspect multiple files for comparison
python cbor_human_inspector.py review_v1.cbor > review_v1_analysis.txt
python cbor_human_inspector.py review_v2.cbor > review_v2_analysis.txt
diff review_v1_analysis.txt review_v2_analysis.txt
```

### Automated Validation

The inspector can be integrated into automated validation workflows:

```bash
# Check if inspection succeeds (exit code 0 = success)
if python cbor_human_inspector.py security_review.cbor; then
    echo "CoRIM structure is valid"
else
    echo "CoRIM has structural issues"
fi
```

### Raw Data Analysis

Use `--show-raw` to see the actual CBOR bytes for deep analysis:

```bash
python cbor_human_inspector.py review.cbor --show-raw
```

This shows the first 100 bytes of raw CBOR data, useful for debugging encoding issues.

## Integration with Other Tools

### With CDDL Validation

The human inspector complements CDDL schema validation:

1. **First**: Run CDDL validation to check schema compliance
2. **Then**: Use human inspector to verify content and meaning
3. **Finally**: Review the human-readable output for audit purposes

### With JSON Reports

The inspector works with CoRIM files generated from JSON security review reports:

```
JSON Report → CoRIM Generation → CBOR Encoding → Human Inspector
```

## Best Practices for Auditors

1. **Always inspect the profile field** - Ensure it contains the correct OCP SAFE SFR OID
2. **Verify issue count matches expectations** - Check that all reported issues are present
3. **Validate timestamps** - Ensure completion dates are reasonable and properly encoded
4. **Check firmware identifiers** - Verify they match the actual firmware being reviewed
5. **Review CVSS scores** - Ensure they align with the severity of described issues
6. **Examine entity information** - Confirm the Security Review Provider is correctly identified

## Support and Troubleshooting

If you encounter issues with the inspector:

1. **Check file format**: Ensure the file is a valid CBOR file
2. **Verify file size**: Empty or corrupted files will cause errors
3. **Review error messages**: The tool provides detailed error information
