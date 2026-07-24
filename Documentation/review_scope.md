# Review Scope

The review scope is guided by to important aspects:

1.   What security characteristics should the product fulfill?
2.   What are important areas to look at as part of a review?

The first point is provided by [OCP S.O.L.I.D.](https://github.com/opencomputeproject/OCP-Security-SOLID), which defines requirements per product type. S.A.F.E. reviews must check if S.O.L.I.D. requirements are met. It is mandatory for these gaps to be listed in long-form reports starting from 2026-10-01. At some point in the future it will also become mandatory to list them in short-form reports as issues.

The second point is the definition of review areas below. Note that the review areas are purposefully vague because the OCP believes that high quality, timely assessments are best achieved by letting the review providers focus on the architectural and implementation areas that are commonly known to have gaps or deficiencies in the scenario under review.

Lastly, all source code that is reviewed must, in addition to a manual review, be reviewed using a suitable AI tool. The detailed requirements for this can be found on the [AI scanning page](./ai_scanning.md).

## High-level review areas

This section describes at a high level the areas that should be in scope for any security audit performed under this framework.
It is intended as starting point for vendors and review providers when undertaking a device or firmware security assessment. Under
the framework, it is required for every production version of device firmware to have undergone the assessment.

* **Threat Model** \
  The review provider should assess the vendor's documented threat models and perform a gap analysis, ensuring they are adequately
  covered by the observed hardware and firmware implementation. If the vendor cannot provide a threat model, then the review provider
  should create one as part of the assessment scope. The threat model document should include the following details, and
  be aligned with the in-scope and out-of-scope threats described by
  the [Common Security Threats](https://www.opencompute.org/documents/common-security-threats-notes-1-pdf)
  document:
    * **Security Objectives**: The high-level security objectives or key
      risks exposed by the firmware. Examples of such objectives may include the strict requirement that the secure boot
      or firmware anti-rollback features must not be subverted or bypassed by an attacker.
    * **Adversarial Model**: A listing of all threat actors along with their
      motivation and capabilities. Examples may include a simple opportunistic hardware adversary, or advanced
      persistent threats that are able to keep the device under antagonistic conditions for an extended duration.
    * **Attack Surface Enumeration**: A listing of all remote, local and
      physical attack surfaces exposed by the device. Examples may include mailbox or IPC interfaces exposed via MMIO, a
      command shell exposed via a serial interface, inter-chip buses which transmit sensitive data, or external
      non-volatile storage media.
    * **Critical Assets**: A listing of all security-impacting assets within
      the firmware, and the corresponding Confidentiality, Integrity and Availability requirements for each. Examples of
      critical assets may include secret keys, the fuse configuration, or any configuration data residing in external flash.

The SAFE program defines 3 security review scopes. These scopes increase with complexity of attacks in the threat model.
It is expected that devices will have reviews done with different review scopes. For example, a CPU may have a scope 3
review of the root of trust due to the need for glitch protection when using a persistent secret. This CPU
may use a scope 2 review for the application cores.

* **Scope 1 Code and Architecture Assessment**
    * **Source Code Review** \
      The review provider should perform a whitebox security review of the device’s ROM and mutable firmware source code for
      identification of vulnerabilities and lapses in industry best practices. Issues uncovered during the review should
      be fixed by the vendor and subsequently verified as fixed by the review provider. The review scope should include:
        * Analysis of the firmware loading and verification procedures to ensure that a secure boot implementation is
          present and cannot be circumvented. All critical assets that impact the device’s security must be
          cryptographically signed. The
          OCP [Secure Boot](https://www.opencompute.org/documents/secure-boot-2-pdf)
          document should be used for guidance.
        * Discovery of hard-coded credentials, seeds, private keys, or symmetric secrets.
        * Identifying temporal and spatial memory safety issues that arise due to improper input validation or race
          conditions that may occur along the attack surfaces that were identified in the threat model.
        * Discovery of remnant debug handlers on production builds
        * Analysis of the cryptographic constructions employed by the firmware when protecting the confidentiality or
          integrity of any critical assets.
        * Improper handling of cryptographic material, e.g. keys, counters, nonces, seeds.
        * Trust-boundary violations between privilege levels or across components, such as confused deputy problems or
          insufficient privilege separation between a firmware’s user and supervisor modes.
        * Identify outdated third-party libraries which are associated with publicly known CVEs.
        * Evaluation of exploit mitigation technologies such as: Address space randomization, stack canaries, data
          execution prevention, NULL page mapping, guard pages, and so on.
    * **Sensitive Functionality Review** \
      The review provider should review the firmware source code and should describe the presence and scope of all
      security-sensitive or commonly “restricted” functionality. This review can be used by consumers to measure risk
      and to configure deployment or isolation controls. The review scope should include:
        * TCG DICE implementation.
        * SPDM implementation.
        * Remote firmware update, manageability, or command and control functionality.
        * Manufacturing, debug, diagnostics, testing and logging capabilities.
        * Unauthenticated APIs.
        * Safe generation and handling of all cryptographic material.
        * Encryption capability controls (disk encryption, erase, rotation).
        * Secure boot key rotation capabilities.
* **Scope 2 - Focusing on Trust boundaries:** Includes all of the areas of Scope 1 above, with deeper review focus of the following areas:
    * Trusted execution environment assessment
    * Handling of trust boundaries
    * Attestation and non-repudiation across boundaries
    * Authenticated and encrypted IO, e.g., PCIe-IDE, TDISP, or vendor proprietary
* **Scope 3 - Resilience to physical attacks:** Scope 3 focuses on physical attacks against persistent secrets and the
  controls that protect or use them. Persistent secrets are secret values that remain available across power cycles or
  from which such values can be derived. Shared class secrets require particular attention because their compromise may
  affect every device that uses them.
    * **Threat model:** The SRP should identify each persistent secret, its security purpose, how it is generated or
      provisioned, and the lifecycle phases in which a physical attacker can access it. The physical attack window for a
      secret begins when that secret is generated or provisioned.
    * **Manufacturing and supply chain:** After secret generation or provisioning and before entry into a trusted data
      center, the threat model should allow for prolonged physical possession and access to laboratory equipment. Relevant
      attacks may include exposed debug interfaces, PCB probing or modification, interposers, bus sniffing or injection,
      voltage or clock fault injection, and power or electromagnetic side-channel analysis.
    * **Data center:** The threat model should allow for repeated physical-access windows of up to 30 minutes. Reviews
      should focus on attacks that can be performed or installed during those windows, such as exposed debug interfaces,
      PCB or bus access, interposers, and modchips. Attacks that require prolonged use of laboratory equipment in the data
      center are out of scope.
    * **RMA:** A device outside the trusted data center for repair should be treated as being under unrestricted physical
      control. The manufacturing and supply-chain threats apply, together with an assessment of sanitization before
      release and whether a tampered device can return to service while still being treated as trusted.
    * **Class secrets:** A secret shared across devices should not directly protect critical assets when compromise of one
      device would compromise other devices. A shared value may be used for obfuscation or defense in depth if its
      disclosure does not by itself compromise a protected asset.
    * **Invasive attacks on class secrets:** Invasive and in-package attacks are out of scope by default for device-unique
      secrets. When a class secret directly protects critical assets across multiple devices, its extraction through an
      invasive or in-package attack is in scope for threat modeling and design review because a single compromise may
      affect the entire device class. This does not require invasive physical testing unless it is included in the agreed
      review scope.
    * **Finding rating:** Scope 3 physical-attack findings must be rated using
      [JIL Application of Attack Potential to Smartcards and Similar Devices, version 3.2.1](https://sogis.eu/documents/cc/domains/sc/JIL-Application-of-Attack-Potential-to-Smartcards-v3.2.1.pdf).
      CVSS is not the primary rating for these findings.
    * **Review activities:** The review should examine the threat model, persistent-secret hierarchy, provisioning and
      lifecycle design, hardware design and RTL, relevant firmware and software, debug controls, sanitization, and
      physical-attack countermeasures. The SRP must test fault-injection and side-channel-analysis countermeasures in
      simulation and document the methods, coverage, assumptions, and results. Scope 3 does not require physical testing
      unless it is included in the review scope agreed by the device vendor and SRP.

## Concrete review areas

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

#### Security Information Details (both documented and vendor-internal)

1. Debugging implementation
2. Logical and physical interfaces
3. Services running on DUT
4. All API's implemented on DUT

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

1. Vendor implemented TEE's must generally conform to standards evolving in the Confidential Computing Consortium.
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
6. The separate [storage sanitization requirements](storage_sanitization.md) must be met.
 
