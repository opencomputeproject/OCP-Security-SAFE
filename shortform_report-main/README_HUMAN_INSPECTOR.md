# Human-Readable CBOR CoRIM Inspector

## Overview

This directory contains tools for generating and inspecting CBOR-encoded CoRIM (CBOR Object Representation of Information Model) files in a human-readable format. These tools are specifically designed for security auditors and reviewers who need to visually verify the contents of binary CBOR files.

## Files in This Package

### Core Tools

- **`cbor_human_inspector.py`** - Main human-readable CBOR inspector tool
- **`test_human_inspector.py`** - Test script that generates sample CoRIM and demonstrates the inspector
- **`AUDITOR_GUIDE.md`** - Comprehensive guide for auditors on how to use these tools

### Supporting Files

- **`OcpReportLib.py`** - Library for generating Security Review Reports in CoRIM format
- **`tests/final_validation_summary.py`** - Comprehensive CDDL compliance validation
- **`tests/cbor_structure_analyzer.py`** - Technical CBOR structure analysis

## Quick Start

### 1. Generate and Inspect a Test CoRIM

```bash
# Generate a sample CoRIM file and inspect it
python test_human_inspector.py
```

This will:
- Create a sample security review report
- Convert it to CoRIM format
- Encode it as CBOR
- Display a human-readable analysis

### 2. Inspect an Existing CoRIM File

```bash
# Basic inspection
python cbor_human_inspector.py your_corim_file.cbor

# Include raw CBOR data
python cbor_human_inspector.py your_corim_file.cbor --show-raw
```

## Key Features

### 🔍 Human-Readable Analysis
- Converts binary CBOR to clear, structured text
- Explains the purpose of each field
- Shows field names instead of just numbers
- Provides context for CBOR tags and data types

### ✅ Validation Indicators
- Visual checkmarks (✅) for correct structures
- Warning symbols (❌) for issues or missing data
- Clear explanations of what each validation means

### 📊 Detailed Content Display
- Security issues with CVSS scores, CWE identifiers, and descriptions
- Firmware information including hashes and versions
- Timestamp formatting and validation

### 🎯 Auditor-Focused Output
- Structured for systematic review
- Highlights critical security information
- Provides validation checklists
- Supports audit trail documentation

## Example Output

```
================================================================================
  CBOR CoRIM Human-Readable Inspector
================================================================================
📊 Total CBOR size: 1286 bytes
🔍 Analysis timestamp: 2025-01-15 14:30:22

------------------------------------------------------------
  Top-Level Structure Analysis
------------------------------------------------------------
✅ CBOR Tag Found: 501 (CoRIM (CBOR Object Representation of Information Model))
✅ This is a valid CoRIM structure
✅ CoRIM contains 4 top-level fields

🔸 Field 3: Profile - Identifies the CoRIM profile being used
   ✅ Proper OID tag (111)
   🆔 Profile: 1.3.6.1.4.1.42623.1.1 (OCP SAFE SFR Profile)

🔐 SFR Extension (-1) Found!
   📋 SFR Data contains 7 fields:
   
   🔸 Field 6: Issues - List of security issues found during review
      🚨 3 security issue(s) found:
      
      🔴 Issue #1:
         Title: Buffer Overflow in Firmware Parser
         CVSS Score: 9.1
         CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
         CWE: CWE-787
         Description: A critical buffer overflow vulnerability...
         CVE: CVE-2025-0123
```

## Use Cases

### For Security Auditors
- **Verify CoRIM Structure**: Ensure all required fields are present and correctly formatted
- **Review Security Issues**: Examine reported vulnerabilities in detail
- **Validate Compliance**: Check that CoRIMs follow OCP SAFE SFR profile specifications
- **Create Audit Reports**: Generate human-readable documentation for audit trails

### For Security Review Providers
- **Quality Assurance**: Verify that generated CoRIMs contain expected data
- **Debugging**: Identify issues in CoRIM generation processes
- **Client Communication**: Provide clear explanations of CoRIM contents

### For Framework Developers
- **Testing**: Validate CoRIM generation and encoding
- **Debugging**: Analyze CBOR structure issues
- **Documentation**: Create examples and demonstrations

## Integration with OCP SAFE Framework

This tool is specifically designed for the OCP Security SAFE (Security Assurance Framework for Ecosystems) and supports:

- **OCP SAFE SFR Profile**: OID 1.3.6.1.4.1.42623.1.1
- **Private Extension (-1)**: For OCP SAFE SFR data
- **CDDL Schema Compliance**: Validates against the OCP SAFE SFR CDDL profile
- **Security Review Reports**: Structured security assessment data

## Technical Details

### Supported CBOR Features
- CBOR tags (timestamps, OIDs, CoRIM, COMID)
- Nested CBOR structures
- Binary data formatting
- Dictionary and array structures

### Validation Capabilities
- Required field presence checking
- Data type validation
- CBOR tag verification
- OID format validation
- Timestamp encoding verification

### Output Formats
- Structured text with Unicode symbols
- Hierarchical indentation
- Color-coded status indicators (when terminal supports it)
- Raw CBOR hex dump (optional)

## Dependencies

- `cbor2` - CBOR encoding/decoding
- `datetime` - Timestamp handling
- Standard Python libraries

## Error Handling

The tool provides clear error messages for common issues:
- Invalid CBOR files
- Missing required fields
- Incorrect data types
- Malformed structures

## Contributing

When extending this tool:
1. Maintain the human-readable focus
2. Add clear explanations for new fields
3. Include validation logic for new structures
4. Update the auditor guide with new features

## License

This tool is part of the OCP Security SAFE framework and follows the same licensing terms.
