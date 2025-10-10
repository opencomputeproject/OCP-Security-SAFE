# Testing and Validation Scripts

This directory contains testing and validation scripts for the OCP SAFE SFR CoRIM implementation.

## Scripts Overview

### Core Testing Scripts

- **`test_corim_generation.py`** - Comprehensive test suite for CoRIM generation functionality
  - Tests basic JSON to CoRIM conversion
  - Validates schema compliance
  - Tests device category mapping
  - Validates error handling
  - Tests backward compatibility

- **`test_cddl_validation.py`** - CDDL schema validation testing
  - Generates test CoRIM and validates against CDDL schema
  - Outputs diagnostic information for debugging
  - Tests CoRIM signing functionality

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
