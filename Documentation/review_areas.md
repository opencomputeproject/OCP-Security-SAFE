# Assessment Scope

This section provides guidance for the areas expected to be assessed by an SRP. The list is purposefully vague because
the OCP Workgroup believes that high quality, timely assessments are best achieved by letting the SRPs focus on the
architectural and implementation areas that are commonly known to have gaps or deficiencies in the scenario under
review.

### Documentation

#### Build Standards (Based on CC v3.1)

1. Version identification
2. Vulnerability management and publication
3. Configuration management and protection
4. Build repeatability and consistency
5. Behavior and implementation align with design
6. Tool chain security features
7. HW security features
8. Development standards

#### SDL

1. Threat model
2. Static analysis configuration and practices
3. Fuzzing tools, configuration and coverage
4. Management of third party dependencies
5. Build configuration

#### Security Implementation Details (HDL and LDL)

1. Secure boot design and specific configuration
2. Update process design and specific configuration
3. Recovery design and specific configuration
4. Telemetry design and specific configuration
5. Cryptographic design and specific configuration
6. Attestation design and specific configuration
7. Debugging design and specific configuration
8. Debugging protection design
9. Authorisation/Authentication design and specific configuration/management

#### Security Compliance and Compliance

1. Security Certifications for DUT
2. Security Certifications for third parties libraries
3. Full memory map for volatile and non-volatile memory
4. Life cycle management for memory including secure erasure and update

#### Evidence

1. Cryptographic test vector evidence
2. Entropy source(s) analysis and evidence
3. Certifications and methods linking to dependencies (e.g. ACME Crypto library v1.2 is certified on public register to
   FIPS 140-3)
4. Fuzzing results

#### Security Information Details (both documented and DV internal)

1. Debugging implementation
2. Logical and physical interfaces
3. Services running on DUT
4. All API's implemented on DUT

###     

### Code Review

#### Booting and general

1. Secure Boot
2. Immutable Hardware Root of Trust (Integrity, revocation, anti-rollback, key manifests)
3. Firmware secret sanitization
4. Firmware test/debug functionality sanitization
5. Secure updates
6. Firmware development best practice
    1. Input validation
    2. Backdoors
    3. Typical development errors
    4. Use of deprecated or insecure functions
    5. Memory safe programming
    6. Dependencies
7. Secure erasure
8. Exploit mitigation
9. Configuration hardening
10. Secure boot must be attack resistant

#### Attestation

1. Attestation support for persistent storage
2. Attestation enforcement for security configuration
3. Cryptographic tamper detectable logs
4. Securely implemented runtime attestation mechanism
5. HW ROT support/enforce quoting attestation claims at boot
6. HW ROT support/enforce quoting attestation claims at runtime
7. Enforcement of measurements for firmware/software loaded into DUT
8. Enforcement of measurements for security configuration loaded into DUT
9. Support for attestation challenges

#### Update

1. Support only secure firmware update
2. Attestation claims must use asymmetric cryptographic mechanisms
3. Updates in progress must be validated prior to committing to persistent storage
4. Attack and exploit resistant

#### End of Life / De-provisioning / Ability to securely re-provision

1. Secrets and storage must support secure erasure and reset
2. HW ROT key store must support secure erasure
3. Debug interfaces can only be re-enabled on entire secure erasure of DUT or with appropriate cryptographic
   challenge/response mechanism

#### Cryptography

1. Cryptographic algorithms must be industry standards or appropriate technical justification
2. Implemented Cryptography certification (e.g. FIPS 140-3)
3. Implemented Cryptography configuration (CNSA)
4. Unsecured persistent event/log storage sanitization
5. Unique or replaceable symmetric keys per device
6. Assets at rest must be appropriately cryptographically protected
7. Assets in memory must be appropriately protected/isolated
8. Keys and other critical security parameters are zeroed when no longer in use
9. Secure support for re-provisioning of all cryptographic material

#### Auditing & Telemetry

1. Secure logging and telemetry
2. Configurable logging to support security events
3. Cryptographic tamper detectable logs

#### Debug

1. Debugging mode must be disabled by default
2. Debug and test code should not be present in production DUT
3. Debug interfaces can only be re-enabled on entire secure erasure of DUT or with appropriate cryptographic
   challenge/response mechanism
4. If debugging functionality can be re-enabled, it must not provide any sensitive information
5. If enabled, debug should be disabled automatically on idle timeout or reboot
6. If re-enabled, debug interfaces and functionality must not compromise DUT security posture, secrets or claims

#### Secure management

1. Cryptographically appropriate authentication required for management functions
2. Management functions must operate under the principle of least privilege
3. Cryptographically appropriate transport layer for management functions, e.g. TLS

#### Dependencies

1. Third party software/firmware components including version specifics recorded in SBOM
2. Configuration specifics for third party dependencies recorded in SBOM
3. Third party dependencies up to date
4. Third party dependencies version pinned and in change control

#### Hardening

1. Interfaces must enforce authentication and authorization specific to the interface
2. Security sensitive operations restricted to trusted interfaces
3. Ability to disable all functionality, API’s, services not required for deployment

#### Trusted Execution Environment

1. DV implemented TEE's must generally conform to standards evolving in the Confidential Computing Consortium.
2. Trusted execution environment has physical and logical safeguards to provide isolation from other processing entities
3. IO from the TEE follows industry standards such as IDE or TDISP. If a proprietary protocol is used, e.g. XGMI,
   NVLINK, it must provide similar authentication, integrity, and isolation guarantees

#### Root of Trust

1. HW ROT shall be both through design and implementation appropriately isolated and protected from application and
   control processes.
2. The HW ROT shall measure and endorse boot and runtime code
3. If the HW ROT supports bulk cryptographic engines, the HW ROT must support secure key transport to and from the bulk
   cryptographic engine
4. The HW ROT shall be appropriately attack and tamper resistant
5. The HW ROT shall implement cryptographically secure tamper resistant logs
6. The HW ROT shall be appropriately cryptographically bound to DUT

#### Identity

1. DUT shall implement TCG DICE
2. DUT Identity must be non-repudiable
3. DUT identity must include DUT version
4. DUT version must be reproducible from SBOM

#### Volatile and non-volatile storage

1. Encrypted memory or storage uses industry standard crypto e.g., AES-XTS
2. Encryption keys must be generated to appropriate length and entropy to comply with FIPS/CNSA standards
3. Encryption keys must not be stored/cache in associated volatile or non-volatile storage
4. Wrapped keys, typically used for storage or transport, must have a mechanism to detect modification or replay
5. Encryption mechanisms are resistant to side channel attacks

 
