#!/bin/bash

# Local Test Script for GitHub Actions Workflow
# This script simulates the validate-reports.yml workflow locally

set -e  # Exit on any error

echo "🧪 Local GitHub Actions Workflow Test"
echo "====================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
    esac
}

# Function to run a job step
run_step() {
    local step_name=$1
    echo ""
    echo "🔄 Running: $step_name"
    echo "----------------------------------------"
}

# Check prerequisites
check_prerequisites() {
    run_step "Checking Prerequisites"
    
    # Check if we're in the right directory
    if [ ! -d "shortform_report-main" ]; then
        print_status "ERROR" "Must run from repository root (shortform_report-main directory not found)"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_status "ERROR" "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check for venv module
    if ! python3 -c "import venv" 2>/dev/null; then
        print_status "ERROR" "Python venv module is required but not available. Install with: sudo apt-get install python3-venv"
        exit 1
    fi
    
    # Create and activate virtual environment
    print_status "INFO" "Setting up virtual environment..."
    cd shortform_report-main
    
    if [ ! -d ".venv" ]; then
        print_status "INFO" "Creating virtual environment..."
        python3 -m venv .venv
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Check if packages are installed in venv
    if ! python -c "import cbor2, cwt" 2>/dev/null; then
        print_status "INFO" "Installing Python dependencies in virtual environment..."
        pip install -r requirements.txt
    fi
    
    print_status "SUCCESS" "Virtual environment ready"
    cd ..
    
    # Check Ruby (optional for CDDL validation)
    if command -v ruby &> /dev/null; then
        print_status "INFO" "Ruby found - CDDL validation will be available"
        RUBY_AVAILABLE=true
        
        # Check for CDDL gems
        if ! gem list | grep -q "cddl"; then
            print_status "WARNING" "CDDL gems not installed. Install with: sudo gem install cddl cddlc cbor-diag"
            CDDL_AVAILABLE=false
        else
            CDDL_AVAILABLE=true
        fi
    else
        print_status "WARNING" "Ruby not found - CDDL validation will be skipped"
        RUBY_AVAILABLE=false
        CDDL_AVAILABLE=false
    fi
    
    print_status "SUCCESS" "Prerequisites check completed"
}

# Job 1: Validate CBOR Reports
validate_cbor_reports() {
    run_step "Job 1: Validate CBOR CoRIM Reports"
    
    # Find CBOR files
    cbor_files=$(find Reports/ -name "*.cbor" 2>/dev/null || echo "")
    
    if [ -z "$cbor_files" ]; then
        print_status "INFO" "No CBOR files found in Reports directory"
    else
        print_status "INFO" "Found CBOR files:"
        echo "$cbor_files"
        
        if [ "$CDDL_AVAILABLE" = true ]; then
            # Prepare CDDL schema
            print_status "INFO" "Preparing CDDL schema..."
            if curl -L -o corim-base-upstream.cddl https://github.com/ietf-rats-wg/draft-ietf-rats-corim/releases/download/cddl-draft-ietf-rats-corim-08/corim-autogen.cddl 2>/dev/null; then
                if cddlc -t cddl corim-base-upstream.cddl Documentation/corim_profile/ocp-safe-sfr-profile.cddl > combined.cddl 2>/dev/null; then
                    print_status "SUCCESS" "CDDL schema prepared"
                    
                    # Validate each CBOR file
                    validation_failed=false
                    while IFS= read -r file; do
                        if [ -n "$file" ] && [ -f "$file" ]; then
                            print_status "INFO" "Validating $file..."
                            if cddl combined.cddl validate "$file" 2>/dev/null; then
                                print_status "SUCCESS" "$file: Valid CBOR structure"
                            else
                                print_status "ERROR" "$file: CDDL validation failed"
                                validation_failed=true
                            fi
                        fi
                    done <<< "$cbor_files"
                    
                    if [ "$validation_failed" = false ]; then
                        print_status "SUCCESS" "All CBOR files passed CDDL validation!"
                    else
                        print_status "ERROR" "Some CBOR files failed CDDL validation"
                        return 1
                    fi
                else
                    print_status "ERROR" "Failed to concatenate CDDL schemas"
                    return 1
                fi
            else
                print_status "ERROR" "Failed to fetch upstream CDDL schema"
                return 1
            fi
        else
            print_status "WARNING" "CDDL tools not available - skipping CBOR validation"
        fi
    fi
    
    # Test CoRIM generation
    print_status "INFO" "Testing CoRIM generation functionality..."
    cd shortform_report-main
    source .venv/bin/activate
    
    if python tests/test_corim_generation.py; then
        print_status "SUCCESS" "CoRIM generation tests passed"
    else
        print_status "ERROR" "CoRIM generation tests failed"
        cd ..
        return 1
    fi
    
    if python tests/test_cddl_validation.py; then
        print_status "SUCCESS" "CDDL validation tests passed"
    else
        print_status "ERROR" "CDDL validation tests failed"
        cd ..
        return 1
    fi
    
    cd ..
    print_status "SUCCESS" "CBOR validation completed successfully"
    return 0
}

# Job 2: Validate CDDL Schema
validate_cddl_schema() {
    run_step "Job 2: Validate CDDL Schema and Examples"
    
    if [ "$CDDL_AVAILABLE" = false ]; then
        print_status "WARNING" "CDDL tools not available - skipping schema validation"
        return 0
    fi
    
    # Convert DIAG to CBOR
    if diag2cbor.rb Documentation/corim_profile/examples/ocp-safe-sfr-fw-example.diag > example.cbor 2>/dev/null; then
        print_status "SUCCESS" "Converted DIAG to CBOR"
    else
        print_status "ERROR" "Failed to convert DIAG to CBOR"
        return 1
    fi
    
    # Fetch and concatenate CDDL
    if curl -L -o corim-base-upstream.cddl https://github.com/ietf-rats-wg/draft-ietf-rats-corim/releases/download/cddl-draft-ietf-rats-corim-08/corim-autogen.cddl 2>/dev/null; then
        print_status "SUCCESS" "Fetched upstream CDDL"
    else
        print_status "ERROR" "Failed to fetch upstream CDDL"
        return 1
    fi
    
    if cddlc -t cddl corim-base-upstream.cddl Documentation/corim_profile/ocp-safe-sfr-profile.cddl > combined.cddl 2>/dev/null; then
        print_status "SUCCESS" "Concatenated CDDL schemas"
    else
        print_status "ERROR" "Failed to concatenate CDDL schemas"
        return 1
    fi
    
    # Validate example against CDDL
    if cddl combined.cddl validate example.cbor 2>/dev/null; then
        print_status "SUCCESS" "Example CBOR validates against CDDL schema"
    else
        print_status "ERROR" "Example CBOR failed CDDL validation"
        return 1
    fi
    
    print_status "SUCCESS" "CDDL schema validation completed successfully"
    return 0
}

# Job 3: Integration Test
integration_test() {
    run_step "Job 3: Integration Test - JSON to CoRIM Conversion"
    
    cd shortform_report-main
    
    # Find a sample JSON file
    sample_json=$(find ../Reports/ -name "*.json" -not -name "*_converted*" | head -1)
    
    if [ -n "$sample_json" ] && [ -f "$sample_json" ]; then
        print_status "INFO" "Testing conversion of: $sample_json"
        
        # Activate venv and convert JSON to CoRIM
        source .venv/bin/activate
        if python tests/json_to_corim_converter.py "$sample_json" -o test_converted.cbor; then
            print_status "SUCCESS" "JSON to CoRIM conversion completed"
            
            # Validate converted CBOR if CDDL tools available
            if [ "$CDDL_AVAILABLE" = true ] && [ -f "test_converted.cbor" ]; then
                cd ..
                if cddl combined.cddl validate shortform_report-main/test_converted.cbor 2>/dev/null; then
                    print_status "SUCCESS" "Converted CBOR validates against CDDL schema"
                    cd shortform_report-main
                else
                    print_status "ERROR" "Converted CBOR failed CDDL validation"
                    cd shortform_report-main
                    return 1
                fi
            else
                print_status "INFO" "CDDL validation skipped (tools not available)"
            fi
            
            # Clean up
            rm -f test_converted.cbor
        else
            print_status "ERROR" "JSON to CoRIM conversion failed"
            cd ..
            return 1
        fi
    else
        print_status "INFO" "No sample JSON files found for conversion testing"
        print_status "INFO" "Running final validation summary instead..."
        
        if python3 tests/final_validation_summary.py; then
            print_status "SUCCESS" "Final validation summary passed"
        else
            print_status "ERROR" "Final validation summary failed"
            cd ..
            return 1
        fi
    fi
    
    cd ..
    print_status "SUCCESS" "Integration test completed successfully"
    return 0
}

# Main execution
main() {
    echo "Starting local workflow test..."
    echo ""
    
    # Track job results
    cbor_result=0
    cddl_result=0
    integration_result=0
    
    # Run all jobs
    check_prerequisites
    
    validate_cbor_reports || cbor_result=$?
    validate_cddl_schema || cddl_result=$?
    integration_test || integration_result=$?
    
    # Summary
    echo ""
    echo "📊 Workflow Test Summary"
    echo "========================"
    
    if [ $cbor_result -eq 0 ]; then
        print_status "SUCCESS" "CBOR Reports: PASSED"
    else
        print_status "ERROR" "CBOR Reports: FAILED"
    fi
    
    if [ $cddl_result -eq 0 ]; then
        print_status "SUCCESS" "CDDL Schema: PASSED"
    else
        print_status "ERROR" "CDDL Schema: FAILED"
    fi
    
    if [ $integration_result -eq 0 ]; then
        print_status "SUCCESS" "Integration Test: PASSED"
    else
        print_status "ERROR" "Integration Test: FAILED"
    fi
    
    echo ""
    echo "🧹 Cleaning up temporary files..."
    rm -f corim-base-upstream.cddl combined.cddl example.cbor
    
    # Overall result
    if [ $cbor_result -eq 0 ] && [ $cddl_result -eq 0 ] && [ $integration_result -eq 0 ]; then
        echo ""
        print_status "SUCCESS" "🎉 All workflow jobs passed! Ready to push to GitHub."
        exit 0
    else
        echo ""
        print_status "ERROR" "❌ Some workflow jobs failed. Fix issues before pushing."
        exit 1
    fi
}

# Run main function
main "$@"
