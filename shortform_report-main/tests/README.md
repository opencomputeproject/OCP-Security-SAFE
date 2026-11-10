# Testing and Validation Scripts

This directory contains testing and validation scripts for the OCP SAFE SFR CoRIM implementation.

## Scripts Overview

### Core Testing Scripts

- **`test_corim_generation.py`** - Comprehensive test suite for CoRIM generation functionality
  - Tests basic JSON to CoRIM conversion
  - Validates schema compliance
  - Validates error handling
  - Tests backward compatibility

- **`test_cddl_validation.py`** - CDDL schema validation testing
  - Generates test CoRIM and validates against CDDL schema
  - Outputs diagnostic information for debugging
  - Tests CoRIM signing functionality

- **`test_assessment_types.py`** - Assessment-type discriminator tests against the CDDL profile
  - Validates `issue-entry` fragments from `Documentation/corim_profile/examples/assessment-types/`
  - `valid/` fixtures must be accepted (including `cvss` both with and without `assessment-type`)
  - `invalid/` fixtures must be rejected (`jil` and `qualitative-rating` without the tag, or any wrong or unknown tag)
  - Also checks that the integer enum values in `OcpReportLib.py` match the JIL enums in the CDDL
  - Requires the Ruby tools `cddlc`, `cddl` and `diag2cbor.rb` (`gem install cddl cddlc cbor-diag`)

### Analysis and Debugging Tools

- **`cbor_structure_analyzer.py`** - CBOR structure analysis tool
  - Decodes CBOR data recursively
  - Provides detailed structure validation
  - Helps debug CDDL compliance issues

- **`final_validation_summary.py`** - Comprehensive validation summary
  - Complete end-to-end validation of CoRIM implementation
  - Tests all aspects of CDDL compliance
  - Provides detailed validation report

### Utility Scripts

- **`json_to_corim_converter.py`** - Migration utility for existing reports
  - Converts existing JSON SFR reports to CoRIM format
  - Supports single file and batch directory conversion
  - Provides conversion statistics and error reporting

## Running the Tests

### Individual Test Scripts

```bash
# Run comprehensive test suite
python tests/test_corim_generation.py

# Run CDDL validation test
python tests/test_cddl_validation.py

# Run assessment-type CDDL accept/reject tests (needs the Ruby CDDL tools)
python tests/test_assessment_types.py

# Run final validation summary
python tests/final_validation_summary.py

# Analyze CBOR structure (requires test_corim_output.cbor)
python tests/cbor_structure_analyzer.py
```

### Convert Existing Reports

```bash
# Convert single JSON file
python tests/json_to_corim_converter.py path/to/report.json

# Convert all JSON files in a directory
python tests/json_to_corim_converter.py path/to/reports/ -o path/to/output/

# Dry run to see what would be converted
python tests/json_to_corim_converter.py path/to/reports/ --dry-run
```

## Test Dependencies

The test scripts require the following additional dependencies beyond the main library requirements:

- `cryptography` - For key generation in signing tests
- `cbor2` - For CBOR encoding/decoding
- `cwt` - For COSE signing operations

These are already included in the main `requirements.txt` file.

## Expected Outputs

### Successful Test Run

When all tests pass, you should see output like:

```
✓ JSON generation: PASS
✓ CoRIM generation: PASS
✓ Top-level CoRIM structure: PASS
✓ SFR structure compliance: PASS
✓ All tests passed! CoRIM generation is working correctly.
```

### Validation Summary

The final validation summary provides comprehensive compliance checking:

```
✓ JSON to CoRIM conversion: PASSED
✓ CBOR encoding: PASSED
✓ CDDL schema compliance: PASSED
✓ CoRIM tag structure: PASSED
✓ COMID tag structure: PASSED
✓ SFR extension mapping: PASSED
🎉 CoRIM implementation is fully CDDL compliant!
```

## Troubleshooting

If tests fail:

1. Check that all dependencies are installed: `pip install -r requirements.txt`
2. Ensure you're running from the correct directory
3. Check the detailed error output for specific issues
4. Use the structure analyzer to debug CBOR format issues
5. Verify that the CDDL schema files are present and accessible

## Integration with CI/CD

These scripts are designed to be integrated with GitHub Actions workflows for automated validation of incoming reports in both JSON and CBOR formats.
