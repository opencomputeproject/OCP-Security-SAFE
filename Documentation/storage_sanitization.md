# Storage Sanitization Requirements

This document outlines requirements for sanitization of storage devices. When a storage device is reviewed it must be verified that these requirements are met.

## Requirements

### Media Encryption Key (MEK)

The MEK is the key used to ultimately encrypt and decrypt all data on the drive. Is is generated within the device based on an Internal Key and External Key and must never leave the device. The following requirements apply:
* The MEK must be generated with a cryptographically-strong amount of entropy.
* An attacker without knowledge of either the Internal Key or External Key, but with knowledge of all other secrets stored at rest within the drive, as well as any external secrets, must be unable to recover the MEK.

### Internal Key

The Internal Key is one of the two keys required to derive or access the MEK. It is generated within the device and never leaves it. It is not a fixed key, but can be erased and regenerated to effectively clear the drive. The following requirements apply:
* If the Internal Key is a key used to encrypt the MEK, it must be generated with a cryptographically-strong amount of entropy, at least 256 bits.
* The Internal Key must never be disclosed outside the drive.
  * Debug and manufacturing-related interfaces must be unable to access the Internal Key.
  * Debug dumps must not contain the Internal Key.
  * The Internal Key must be protected against exfiltration via Differential Power Analysis side-channel attacks (Scope 3 only).
    * Rate limiting may be used to mitigate attacks.
  * The Internal Key should be encrypted at rest with a unique key derived from secrets burned into fuses, in order to protect against physical exfiltration.
* The Internal Key must be erasable.
  * An erase command may only report success after all old copies of the Internal Key have been destroyed irreversibly. Status must be reported, so that failures can be addressed externally.
  * Advanced attackers with physical access to the drive must be unable to recover the Internal Key (Scope 3 only).
    * As a subjective guideline: The Internal Key should be unrecoverable with a budget of up to $10M.
  * It should be possible to destroy the Internal Key even when other parts of the drive are faulty, such as motors, magnetic platters, heads or flash chips that have reached the maximum number of write-cycles.

### External Key

The External Key is required to derive or access the MEK. It is not permanently stored within the device, but rather must be provided by the user to access their data. In TCG Opal this may be the user's C_PIN. The following requirements apply:
* The External Key must be able to represent a cryptographically-strong amount of entropy, at least 256 bits.
* The External Key may not be stored at rest within the drive.
* The External Key must be resistant to timing attacks.
  * An invalid External Key must take the same amount of time to be processed as a valid External Key.
    * Jitter may be used.
  * The Internal Key may not be processed until the correct External Key has been provided.
* The user may change the External Key.
  * It must be ensured that old External Keys cannot be used to recover the MEK.
* As long as all other requirements are met, the External Key may be the user's C_PIN in TCG Opal Single User Mode.
  * If TCG Opal Single User Mode is enabled, it must not be possible to use the secrets on the drive, in conjuction with an admin C_PIN, to recover the MEK.

## Known errors

This is an incomplete list of implementation mistakes observed in the past that should not be repeated.
* Rather than using the External Key to decrypt a secret, some implementations calculate the hash of the External Key and compare it to a stored value. This produces seemingly correct behavior from the user's perspective, but makes it significantly easier to recover the data without knowledge of the External Key.
* For durability, some implementations store multiple copies of the Internal Key, but then neglect to erase all of them during sanitization operations, leaving the potential for an attacker to exfiltrate an old backup copy to access the data.
* When security is not enabled for an ATA drive, copies of the MEK that are decryptable without an External Key are stored within the drive. Some implementations neglect to erase these when turning security on and rather just mark them as disabled, leaving the drive vulnerable to attackers attempting to extract these old copies.
* Similarly, when switching from multi-user to single user mode, an implementation might neglect to erase the MEKs that are decryptable by users that should no longer have access.
 
## Other

* A single drive might support several different mechanisms for Internal Keys and External Keys. Reviews should look at each mechanism, as well as host-side interfaces for exercising them, and interactions (including unintentional) between the various mechanisms.
