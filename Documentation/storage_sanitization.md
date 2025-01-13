# Storage Sanitization Requirements

This document outlines requirements for sanitization of storage devices. When a storage device is reviewed it must be verified that these requirements are met.

## Requirements

### Media Encryption Key (MEK)

The MEK is the key used to ultimately encrypt and decrypt all data on the drive. Is is generated within the device based on IK and EK and must never leave the device. The following requirements apply:
* The MEK must be generated with a cryptographically-strong amount of entropy.
* An attacker without knowledge of either IK or EK, but with knowledge of all other secrets stored at rest within the drive, as well as any external secrets, must be unable to recover the MEK.

### Internal Key (IK)

The IK is one of the two keys required to derive or access the MEK. It is generated within the device and never leaves it. It is not a fixed key, but can be erased and regenerated to effectively clear the drive. The following requirements apply:
* If the IK is a key used to encrypt the MEK, it must be generated with a cryptographically-strong amount of entropy, at least 128 bits.
* The IK must never be disclosed outside the drive.
  * Debug and manufacturing-related interfaces must be unable to access the IK.
  * Debug dumps must not contain the IK.
  * The IK must be protected against exfiltration via Differential Power Analysis side-channel attacks.
    * Rate limiting may be used to mitigate attacks.
  * The IK should be encrypted at rest with a unique key derived from secrets burned into fuses, in order to protect against physical exfiltration.
* The IK must be erasable.
  * An erase command may only report success after all old copies of the IK have been destroyed irreversibly. Status must be reported, so that failures can be addressed externally.
  * Advanced attackers with physical access to the drive must be unable to recover the IK.
    * As a subjective guideline: The IK should be unrecoverable with a budget of up to $10M.
  * It should be possible to destroy the IK even when other parts of the drive are faulty, such as motors, magnetic platters, heads or flash chips that have reached the maximum number of write-cycles.

### External Key (EK)

The EK is one of the two keys required to derive or access the MEK. It is not permanently stored within the device, but rather must be provided by the user to access their data. In TCG Opal this may be the user's C_PIN. The following requirements apply:
* The EK must be generated with a cryptographically-strong amount of entropy, at least 256 bits.
* The EK may not be stored at rest within the drive.
* The EK must be resistant to timing attacks.
  * An invalid EK must take the same amount of time to be processed as a valid EK.
    * Jitter may be used.
  * The IK may not be processed until the correct EK has been provided.
* The user may change the EK.
  * It must be ensured that old EKs cannot be used to recover the MEK.
* As long as all other requirements are met, the EK may be the user's C_PIN in TCG Opal Single User Mode.
  * If TCG Opal Single User Mode is enabled, it must not be possible to use the secrets on the drive, in conjuction with an admin C_PIN, to recover the MEK.

## Known errors

This is an incomplete list of implementation mistakes observed in the past that should not be repeated.
* Rather than using the EK to decrypt a secret, some implementations calculate the hash of the EK and compare it to a stored value. This produces seemingly correct behavior from the user's perspective, but makes it significantly easier to recover the data without knowledge of the EK.
* For durability, some implementations store multiple copies of the IK, but then neglect to erase all of them during sanitization operations, leaving the potential for an attacker to exfiltrate an old backup copy to access the data.
* When security is not enabled for an ATA drive, copies of the MEK that are decryptable without an EK are stored within the drive. Some implementations neglect to erase these when turning security on and rather just mark them as disabled, leaving the drive vulnerable to attackers attempting to extract these old copies.
* Similarly, when switching from multi-user to single user mode, an implementation might neglect to erase the MEKs that are decryptable by users that should no longer have access.
 
## Other

* A single drive might support several different mechanisms for IK and EK. Reviews should look at each mechanism, as well as host-side interfaces for exercising them, and interactions (including unintentional) between the various mechanisms.
