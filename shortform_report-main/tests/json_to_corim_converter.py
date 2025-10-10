"""
JSON to CoRIM Conversion Utility

This utility converts existing OCP SAFE SFR JSON reports to the new CoRIM format.
It handles the schema differences and provides migration capabilities for existing reports.

Author: Extended from Jeremy Boone's original OcpReportLib.py
Date  : January 2025
"""

import json
import sys
import os
import argparse
from typing import Dict, Any, Optional
from datetime import datetime

# Add parent directory to path to import OcpReportLib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from OcpReportLib import ShortFormReport

class JsonToCorimConverter:
    """Converter class for migrating JSON SFR reports to CoRIM format."""
    
    def __init__(self):
        self.warnings = []
        self.errors = []
    
    def convert_json_file(self, json_file_path: str, output_cbor_path: Optional[str] = None) -> bool:
        """Convert a JSON SFR file to CoRIM format.
        
        Args:
            json_file_path: Path to the input JSON file
            output_cbor_path: Optional path for output CBOR file
            
        Returns:
            True if conversion successful, False otherwise
        """
        try:
            # Load JSON report
            with open(json_file_path, 'r') as f:
                json_data = json.load(f)
            
            # Convert to CoRIM
            corim_data = self.convert_json_data(json_data)
            
            if not corim_data:
                return False
            
            # Generate output filename if not provided
            if output_cbor_path is None:
                base_name = os.path.splitext(json_file_path)[0]
                output_cbor_path = f"{base_name}_converted.cbor"
            
            # Save CBOR file
            with open(output_cbor_path, 'wb') as f:
                f.write(corim_data)
            
            print(f"✓ Converted {json_file_path} to {output_cbor_path}")
            return True
            
        except Exception as e:
            self.errors.append(f"Failed to convert {json_file_path}: {e}")
            return False
    
    def convert_json_data(self, json_data: Dict[str, Any]) -> Optional[bytes]:
        """Convert JSON data structure to CoRIM CBOR bytes.
        
        Args:
            json_data: The JSON report data as a dictionary
            
        Returns:
            CBOR bytes if successful, None if failed
        """
        try:
            # Validate JSON structure
            if not self._validate_json_structure(json_data):
                return None
            
            # Create ShortFormReport and populate it
            rep = ShortFormReport(
                framework_ver=json_data.get("review_framework_version", "1.1")
            )
            
            # Extract device information
            device = json_data.get("device", {})
            rep.add_device(
                vendor=device.get("vendor", "Unknown Vendor"),
                product=device.get("product", "Unknown Product"),
                category=device.get("category", "storage"),
                repo_tag=device.get("repo_tag", ""),
                fw_ver=device.get("fw_version", ""),
                fw_hash_sha384=device.get("fw_hash_sha2_384", ""),
                fw_hash_sha512=device.get("fw_hash_sha2_512", ""),
                manifest=device.get("manifest")
            )
            
            # Extract audit information
            audit = json_data.get("audit", {})
            rep.add_audit(
                srp=audit.get("srp", "Unknown SRP"),
                methodology=audit.get("methodology", "unknown"),
                date=audit.get("completion_date", "1970-01-01"),
                report_ver=audit.get("report_version", "1.0"),
                scope_number=audit.get("scope_number", 1),
                cvss_ver=audit.get("cvss_version", "3.1")
            )
            
            # Extract issues
            issues = audit.get("issues", [])
            for issue in issues:
                rep.add_issue(
                    title=issue.get("title", "Unknown Issue"),
                    cvss_score=issue.get("cvss_score", "0.0"),
                    cvss_vec=issue.get("cvss_vector", ""),
                    cwe=issue.get("cwe", "CWE-000"),
                    description=issue.get("description", "No description"),
                    cve=issue.get("cve")
                )
            
            # Generate CoRIM CBOR
            return rep.get_report_as_corim_cbor()
            
        except Exception as e:
            self.errors.append(f"Conversion failed: {e}")
            return None
    
    def _validate_json_structure(self, json_data: Dict[str, Any]) -> bool:
        """Validate that the JSON has the expected SFR structure."""
        required_fields = ["device", "audit"]
        missing_fields = []
        
        for field in required_fields:
            if field not in json_data:
                missing_fields.append(field)
        
        if missing_fields:
            self.errors.append(f"Missing required fields: {missing_fields}")
            return False
        
        # Check device fields
        device = json_data["device"]
        device_warnings = []
        
        if not device.get("vendor"):
            device_warnings.append("Missing device vendor")
        if not device.get("product"):
            device_warnings.append("Missing device product")
        if not device.get("fw_hash_sha2_384") and not device.get("fw_hash_sha2_512"):
            device_warnings.append("Missing firmware hashes")
        
        # Check audit fields
        audit = json_data["audit"]
        audit_warnings = []
        
        if not audit.get("srp"):
            audit_warnings.append("Missing SRP name")
        if not audit.get("completion_date"):
            audit_warnings.append("Missing completion date")
        if not audit.get("scope_number"):
            audit_warnings.append("Missing scope number")
        
        # Add warnings
        self.warnings.extend(device_warnings + audit_warnings)
        
        return True
    
    def convert_directory(self, input_dir: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """Convert all JSON files in a directory to CoRIM format.
        
        Args:
            input_dir: Directory containing JSON files
            output_dir: Optional output directory for CBOR files
            
        Returns:
            Dictionary with conversion statistics
        """
        if output_dir is None:
            output_dir = input_dir
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        stats = {
            "total_files": 0,
            "converted": 0,
            "failed": 0,
            "skipped": 0
        }
        
        # Find all JSON files
        json_files = []
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if file.endswith('.json') and not file.endswith('_converted.json'):
                    json_files.append(os.path.join(root, file))
        
        stats["total_files"] = len(json_files)
        
        print(f"Found {len(json_files)} JSON files to convert...")
        
        for json_file in json_files:
            try:
                # Calculate relative path for output
                rel_path = os.path.relpath(json_file, input_dir)
                output_path = os.path.join(output_dir, rel_path)
                output_path = os.path.splitext(output_path)[0] + "_converted.cbor"
                
                # Ensure output subdirectory exists
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                # Convert file
                if self.convert_json_file(json_file, output_path):
                    stats["converted"] += 1
                else:
                    stats["failed"] += 1
                    
            except Exception as e:
                print(f"Error processing {json_file}: {e}")
                stats["failed"] += 1
        
        return stats
    
    def print_summary(self):
        """Print conversion warnings and errors."""
        if self.warnings:
            print("\n⚠️  Warnings:")
            for warning in self.warnings:
                print(f"  - {warning}")
        
        if self.errors:
            print("\n❌ Errors:")
            for error in self.errors:
                print(f"  - {error}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert OCP SAFE SFR JSON reports to CoRIM format"
    )
    parser.add_argument(
        "input",
        help="Input JSON file or directory containing JSON files"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output CBOR file or directory (default: same as input with _converted suffix)"
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Process directories recursively"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be converted without actually converting"
    )
    
    args = parser.parse_args()
    
    converter = JsonToCorimConverter()
    
    if os.path.isfile(args.input):
        # Single file conversion
        if args.input.endswith('.json'):
            print(f"Converting single file: {args.input}")
            
            if args.dry_run:
                print(f"Would convert {args.input} to CoRIM format")
                return
            
            success = converter.convert_json_file(args.input, args.output)
            converter.print_summary()
            
            if success:
                print("✅ Conversion completed successfully")
            else:
                print("❌ Conversion failed")
                sys.exit(1)
        else:
            print("Error: Input file must be a JSON file")
            sys.exit(1)
    
    elif os.path.isdir(args.input):
        # Directory conversion
        print(f"Converting directory: {args.input}")
        
        if args.dry_run:
            # Count JSON files
            json_count = 0
            for root, dirs, files in os.walk(args.input):
                json_count += len([f for f in files if f.endswith('.json')])
            print(f"Would convert {json_count} JSON files to CoRIM format")
            return
        
        stats = converter.convert_directory(args.input, args.output)
        converter.print_summary()
        
        print(f"\n📊 Conversion Statistics:")
        print(f"  Total files found: {stats['total_files']}")
        print(f"  Successfully converted: {stats['converted']}")
        print(f"  Failed: {stats['failed']}")
        print(f"  Skipped: {stats['skipped']}")
        
        if stats['failed'] > 0:
            print("⚠️  Some conversions failed. Check errors above.")
            sys.exit(1)
        else:
            print("✅ All conversions completed successfully")
    
    else:
        print(f"Error: Input path '{args.input}' does not exist")
        sys.exit(1)


if __name__ == "__main__":
    main()
