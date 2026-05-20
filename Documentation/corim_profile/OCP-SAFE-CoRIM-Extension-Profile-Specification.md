# OCP Profile for IETF Concise Reference Integrity Manifest (CoRIM) Security Framework Review Extension (Draft)

**Version 0.1 (Git commit c1b3501)**

## Table of Contents

1. [List of Tables](#list-of-tables)
2. [Acknowledgements](#acknowledgements)
3. [Compliance with OCP Tenets](#compliance-with-ocp-tenets)
4. [Overview](#overview)
5. [Integration with OCP Attestation Framework](#integration-with-ocp-attestation-framework)
6. [Terms and Definitions](#terms-and-definitions)
7. [Introduction](#introduction)
8. [Motivation](#motivation)
9. [Scope](#scope)
10. [CoRIM Profile Structure](#corim-profile-structure)
11. [OCP S.A.F.E. SFR Extension](#ocp-safe-sfr-extension)
12. [Security Considerations](#security-considerations)
13. [Implementation Guidelines](#implementation-guidelines)
14. [Appendix](#appendix)
15. [References](#references)


## List of Tables

- Table 1: OCP S.A.F.E. SFR Map Fields
- Table 2: Firmware Identifier Components
- Table 3: Issue Entry Structure
- Table 4: CVSS Structure

## Acknowledgements

The Contributors of this Specification would like to acknowledge the following:

- Alex Tzonkov (AMD)
- Eric Eilertson (MSFT)
- Rob Wood (Tetrel Security)
- Fabrizio D'Amato (AMD)
- Isaac Assay (AMD)
- Matt King (NVIDIA)
- Thomas Fossati (Linaro)

## Compliance with OCP Tenets

### Openness
This specification is open and builds upon established IETF standards for CoRIM while extending them for OCP S.A.F.E. security review requirements.

### Efficiency
This specification provides an efficient method for embedding security review findings within standardized reference integrity manifests, reducing overhead and complexity.

### Impact
This specification enables standardized security review reporting across diverse datacenter hardware components, significantly improving security transparency and assessment capabilities.

### Sustainability
This specification promotes sustainable security practices by providing a standardized framework for ongoing security assessments and reviews.

## Overview

This profile extends the IETF Concise Reference Integrity Manifest (CoRIM) specification to support OCP S.A.F.E. Short Form Report (SFR) reporting. The extension enables security auditors and review providers to embed comprehensive security assessment findings directly within CoRIM structures, providing a standardized method for representing security review results alongside reference integrity measurements.

The profile defines a dedicated extension to the CoRIM measurement-values-map that encapsulates security review metadata, firmware identifiers, vulnerability findings, and assessment scope information. This approach ensures that security review data maintains the same cryptographic integrity guarantees as the underlying reference measurements while providing rich contextual information for security evaluation.

The primary objective is to establish a unified format for security review reporting that integrates seamlessly with existing CoRIM-based supply chain security infrastructure, enabling automated processing and verification of security assessment results across diverse platforms.

## Terms and Definitions

- **CoRIM**: Concise Reference Integrity Manifest
- **SFR**: Short Form Report
- **S.A.F.E.**: Security Appraisal Framework and Evaluation
- **CDDL**: Concise Data Definition Language
- **CBOR**: Concise Binary Object Representation
- **CVSS**: Common Vulnerability Scoring System
- **CWE**: Common Weakness Enumeration
- **CVE**: Common Vulnerabilities and Exposures
- **OID**: Object Identifier
- **SRP**: Security Review Provider

## Introduction

This specification details how security review providers should represent their assessment findings within a CoRIM extension profile. The extension leverages the existing CoRIM measurement-values-map structure to embed OCP S.A.F.E. SFR-specific data, ensuring compatibility with standard CoRIM processing tools while providing rich security assessment context.

The specification defines the essential data structures required to represent comprehensive security review findings, including vulnerability assessments, firmware identification, scope definitions, and metadata about the review process itself. By embedding this information within CoRIM structures, the specification enables cryptographic verification of security review integrity alongside traditional reference measurements.

## Motivation

Modern datacenter security requires comprehensive assessment of firmware and hardware components across diverse vendor ecosystems. Traditional security review reporting lacks standardization, making it difficult for Cloud Service Providers (CSPs) and system integrators to consistently evaluate and compare security postures across different components.

This specification addresses these challenges by:

1. **Standardizing Security Review Reporting**: Providing a common format for representing security assessment findings
2. **Enabling Cryptographic Verification**: Leveraging CoRIM's integrity protection mechanisms to ensure security review authenticity
3. **Facilitating Automated Processing**: Supporting machine-readable security assessment data for automated policy enforcement
4. **Improving Supply Chain Transparency**: Enabling verifiable security assessment results throughout the hardware supply chain

## Scope

This profile defines a CoRIM extension for representing OCP S.A.F.E. Security Framework Review findings. The extension is designed to be:

- **Review Framework Flexible**: Accommodating various security assessment methodologies and frameworks
- **Vulnerability Standard Compliant**: Supporting CVSS, CWE, and CVE standard vulnerability representations
- **Cryptographically Verifiable**: Maintaining CoRIM's integrity protection properties

The profile focuses solely on the representation of security review findings and does not define:
- Security assessment methodologies
- Vulnerability discovery processes
- Remediation procedures
- Policy enforcement mechanisms

## CoRIM Profile Structure

The OCP S.A.F.E. SFR CoRIM profile is identified by the Object Identifier (OID) `1.3.6.1.4.1.42623.1.1` and extends the standard CoRIM measurement-values-map with security review specific data structures.

### Profile Identification

```cddl
ocp-safe-sfr-profile-oid = h'060A2B0601040182F4170101' ; OID 1.3.6.1.4.1.42623.1.1 in DER encoding
```

### Extension Integration

The profile integrates with CoRIM through the measurement-values-map extension mechanism:

```cddl
$$measurement-values-map-extension //= (
  &(ocp-safe-sfr: -1) => ocp-safe-sfr-map ; Private extension for OCP S.A.F.E. SFR
)
```

## OCP S.A.F.E. SFR Extension

### Core Data Structure

The OCP S.A.F.E. SFR extension is represented by the `ocp-safe-sfr-map` structure, which contains all security review findings and metadata:

```cddl
ocp-safe-sfr-map = {
  &(review-framework-version: 0) => tstr
  &(report-version: 1) => tstr
  &(completion-date: 2) => time
  &(scope-number: 3) => integer
  ? &(fw-identifiers: 4) => [ + fw-identifier ]
  ? &(issues: 5) => [ + issue-entry ]
  ? &(solid-version: 6) => tstr
  * $$ocp-safe-sfr-map-ext
}
```

### Field Definitions

#### Mandatory Fields

**Table 1: OCP S.A.F.E. SFR Map Fields**

| Field | Key | Type | Description |
|-------|-----|------|-------------|
| review-framework-version | 0 | tstr | Version of the OCP S.A.F.E. framework used for the review |
| report-version | 1 | tstr | Version of the specific security review report |
| completion-date | 2 | time | Date when the security review was completed |
| scope-number | 3 | integer | Numerical identifier for the review scope |

#### Optional Fields

| Field | Key | Type | Description |
|-------|-----|------|-------------|
| fw-identifiers | 4 | array | Array of firmware identifier objects |
| issues | 5 | array | Array of security issues identified during review |
| solid-version | 6 | tstr | Version of the SOLID requirements checked against |

### Firmware Identifiers

Firmware identifiers provide detailed information about the firmware components that were subject to security review:

```cddl
fw-identifier = non-empty<{
  ? &(fw-version: 0) => version-map
  ? &(fw-file-digests: 1) => digests-type
  ? &(repo-tag: 2) => tstr
  ? &(src-manifest: 3) => src-manifest
}>
```

**Table 2: Firmware Identifier Components**

| Field | Key | Type | Description |
|-------|-----|------|-------------|
| fw-version | 0 | version-map | Semantic version information |
| fw-file-digests | 1 | digests-type | Cryptographic hashes of firmware files |
| repo-tag | 2 | tstr | Source repository tag or commit identifier |
| src-manifest | 3 | src-manifest | Source code manifest with file hashes |

### Security Issues

Security issues identified during the review are represented using the `issue-entry` structure:

```cddl
issue-entry = {
  &(title: 0) => tstr
  &(description: 1) => tstr
  &(assessment: 2) => $assessment
  ?&(cwe: 3) => tstr
  ?&(cve: 4) => tstr
  * $$ocp-safe-issue-entry-ext
}

$assessment /= cvss

cvss = {
  &(cvss-score: 0) => tstr
  &(cvss-vector: 1) => tstr
  ? &(cvss-version: 2) => tstr
}
```

**Table 3: Issue Entry Structure**

| Field | Key | Type | Required | Description |
|-------|-----|------|----------|-------------|
| title | 0 | tstr | Yes | Brief title describing the security issue |
| description | 1 | tstr | Yes | Detailed description of the security issue |
| assessment | 2 | $assessment | Yes | Assessment used (e.g., CVSS) |
| cwe | 3 | tstr | No | Common Weakness Enumeration identifier |
| cve | 4 | tstr | No | CVE identifier if assigned |

### Assessments

The specification supports various assessments for vulnerability scoring. Currently, CVSS is the primary supported assesment:

**Table 4: CVSS Structure**

| Field | Key | Type | Required | Description |
|-------|-----|------|----------|-------------|
| cvss-score | 0 | tstr | Yes | CVSS numerical score (e.g., "7.9") |
| cvss-vector | 1 | tstr | Yes | CVSS vector string |
| cvss-version | 2 | tstr | No | CVSS version used for scoring (default: "3.1") |

### Source Manifest Support

For comprehensive firmware tracking, the profile supports source code manifests:

```cddl
src-manifest = {
  &(manifest-digest: 0) => digests-type 
  &(manifest: 1) => [ + manifest-entry ]
}

manifest-entry = {
  &(filename: 0) => tstr
  &(file-hash: 1) => digests-type 
}
```

## Security Considerations

### Cryptographic Integrity

The OCP S.A.F.E. SFR extension inherits all cryptographic integrity protections provided by the underlying CoRIM structure. Security review findings are protected by the same digital signatures that protect reference measurements, ensuring:

- **Authenticity**: Verification that security review data originates from authorized review providers
- **Integrity**: Detection of any tampering with security assessment findings
- **Non-repudiation**: Cryptographic proof of review provider responsibility for findings

### Data Sensitivity

Security review findings may contain sensitive information about vulnerabilities and system weaknesses. Implementers should consider:

- **Access Control**: Restricting access to security review data based on organizational policies
- **Disclosure Coordination**: Following responsible disclosure practices for vulnerability information
- **Data Retention**: Implementing appropriate retention policies for security assessment data

### Verification Requirements

Consumers of OCP S.A.F.E. SFR CoRIM data MUST:

1. Verify the cryptographic integrity of the CoRIM structure
2. Validate the review provider's authorization and credentials
3. Check the freshness and validity period of security review findings
4. Ensure compatibility between review framework versions and local policies

## Implementation Guidelines

### Review Provider Requirements

Security Review Providers implementing this profile MUST:

1. **Use Assigned OID**: Include the correct OCP S.A.F.E. SFR profile OID in all CoRIM structures
2. **Maintain Data Integrity**: Ensure all security review findings are accurately represented
3. **Follow CVSS Standards**: Use standardized CVSS scoring and vector formats
4. **Provide Complete Metadata**: Include all mandatory fields in the SFR extension
5. **Sign CoRIM Structures**: Apply appropriate cryptographic signatures to ensure integrity

### Consumer Implementation

Systems consuming OCP S.A.F.E. SFR CoRIM data SHOULD:

1. **Validate Profile Compatibility**: Check for supported profile OID before processing
2. **Implement Policy Enforcement**: Define policies for handling different severity levels
4. **Maintain Audit Trails**: Log all security review data processing activities

### Interoperability Considerations

To ensure broad interoperability:

- **Standard Compliance**: Adhere to all referenced IETF and industry standards
- **Version Compatibility**: Support backward compatibility with previous framework versions
- **Extension Points**: Use defined extension mechanisms for vendor-specific additions
- **Error Handling**: Implement robust error handling for malformed or incomplete data

## Appendix

### Profile CDDL

[This file](./ocp-safe-sfr-profile.cddl) contains the formal definition.

### Example CoRIM with SFR Extension

[This example file](./examples/ocp-safe-sfr-fw-example.diag) demonstrates a complete CoRIM structure containing OCP S.A.F.E. SFR security review findings.

## References

[1] "Concise Reference Integrity Manifest." IETF, Nov. 2020. Available: https://datatracker.ietf.org/doc/draft-ietf-rats-corim

[2] "Concise Binary Object Representation (CBOR)." IETF, Dec. 2020. Available: https://datatracker.ietf.org/doc/html/rfc8949

[3] "Concise Data Definition Language (CDDL): A Notational Convention to Express Concise Binary Object Representation (CBOR) and JSON Data Structures." IETF, Jun. 2019. Available: https://datatracker.ietf.org/doc/html/rfc8610

[4] "Common Vulnerability Scoring System Version 3.1: Specification Document." FIRST, Jun. 2019. Available: https://www.first.org/cvss/v3.1/specification-document

[5] "Common Weakness Enumeration (CWE)." MITRE Corporation. Available: https://cwe.mitre.org/

[6] "Common Vulnerabilities and Exposures (CVE)." MITRE Corporation. Available: https://cve.mitre.org/

[7] "OCP Security Assurance Framework for Enterprises (S.A.F.E.)." Open Compute Project Foundation. Available: https://www.opencompute.org/projects/safe

[8] "Remote ATtestation procedureS (RATS) Architecture." IETF, Oct. 2021. Available: https://datatracker.ietf.org/doc/html/rfc9334

[9] "OCP Profile for IETF Entity Attestation Token (EAT)." Open Compute Project Foundation. Available: https://www.opencompute.org/projects/safe
