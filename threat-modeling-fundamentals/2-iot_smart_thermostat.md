# Threat Modeling - IoT Smart Thermostat

## System Overview

### Features

- Connects to home Wi-Fi
- Controls heating and cooling systems
- Collects indoor temperature data
- Receives commands from a mobile application
- Updates firmware Over-The-Air (OTA)

### Architecture

```text
                 +----------------------+
                 | Mobile Application   |
                 +----------+-----------+
                            |
                         HTTPS/TLS
                            |
                 +----------v-----------+
                 | Cloud API            |
                 +----------+-----------+
                            |
                         TLS/MQTT
                            |
                 +----------v-----------+
                 | Smart Thermostat     |
                 +----------+-----------+
                            |
                 Heating / Cooling System
```

---

# 1. IoT-Specific Threats

Unlike traditional web applications, IoT devices face additional risks due to their physical presence and direct interaction with hardware.

| Threat | Description | Potential Impact | Suggested Mitigation |
|---------|-------------|------------------|----------------------|
| **Physical Tampering** | An attacker opens the device to access internal components. | Device compromise, credential theft, firmware extraction. | Tamper-resistant enclosure, tamper-evident seals, disable debug interfaces. |
| **Weak Default Credentials** | Factory default usernames and passwords remain unchanged. | Unauthorized remote access and device takeover. | Require unique credentials and force password changes during initial setup. |
| **Firmware Extraction and Reverse Engineering** | Attackers dump firmware through flash memory or debug ports. | Discovery of vulnerabilities, hardcoded secrets, malware development. | Encrypt firmware, enable secure boot, disable debugging interfaces. |
| **Unencrypted Device Communication** | Data is transmitted without encryption over Wi-Fi or local protocols. | Eavesdropping, command interception, privacy violations. | Use TLS for all communications and secure wireless protocols. |
| **Malicious Firmware Installation** | The device installs unauthorized firmware updates. | Persistent malware, remote control, botnet participation. | Digitally signed firmware, signature verification, secure OTA updates. |

---

# 2. Physical Access Attack Chain

Physical access significantly increases the attacker's capabilities.

## Step 1 – Obtain Physical Access

The attacker gains possession of the thermostat by removing it from the wall or accessing it inside the home.

---

## Step 2 – Open the Device

The attacker opens the enclosure to expose internal hardware components.

Possible targets include:

- UART interface
- JTAG interface
- SPI flash memory
- Debug pins

---

## Step 3 – Extract Firmware

Using debugging tools, the attacker reads the device's flash memory.

Possible information obtained:

- Firmware image
- Encryption keys
- Wi-Fi credentials
- API tokens
- Hardcoded passwords

---

## Step 4 – Analyze Firmware

The extracted firmware is reverse engineered to discover:

- Software vulnerabilities
- Hidden functionality
- Hardcoded secrets
- Weak authentication mechanisms

---

## Step 5 – Modify Firmware

The attacker modifies the firmware to include malicious functionality such as:

- Backdoors
- Remote access capabilities
- Data exfiltration
- Persistent malware

---

## Step 6 – Reinstall Modified Firmware

The compromised firmware is installed back onto the thermostat.

If secure boot or firmware signature verification is absent, the modified firmware executes normally.

---

## Potential Impacts

- Complete device takeover
- Unauthorized control of heating and cooling systems
- Theft of Wi-Fi credentials
- Access to the home network
- Device added to a botnet
- Persistent malware surviving reboots
- Privacy violations through collection of occupancy patterns

---

# 3. OTA (Over-The-Air) Security Controls

A secure OTA update process is critical because firmware updates modify the software running on the device.

## 1. Digital Code Signing

Every firmware image must be digitally signed by the manufacturer.

The thermostat verifies the signature before installation.

**Purpose**

Prevents installation of malicious firmware.

---

## 2. Secure Boot

The bootloader verifies firmware integrity every time the device starts.

Only trusted firmware is allowed to execute.

**Purpose**

Prevents execution of modified firmware.

---

## 3. Encrypted Communication

Firmware updates must be downloaded using encrypted channels (TLS).

**Purpose**

Protects against interception and man-in-the-middle attacks.

---

## 4. Firmware Integrity Verification

The device verifies a cryptographic hash (e.g., SHA-256) after download.

**Purpose**

Ensures the firmware has not been altered or corrupted.

---

## 5. Rollback Protection

The device prevents installation of older firmware versions with known vulnerabilities.

**Purpose**

Stops downgrade attacks.

---

## 6. Device Authentication

The thermostat authenticates the update server before downloading firmware.

Likewise, the update server authenticates the device.

**Purpose**

Prevents unauthorized update servers from distributing malicious firmware.

---

## 7. Secure Key Storage

Private cryptographic keys are never stored in firmware.

Public verification keys should be stored in secure hardware when available.

**Purpose**

Protects the update trust chain.

---

## 8. Fail-Safe Recovery

If an update fails, the device automatically restores the previous working firmware.

**Purpose**

Prevents devices from becoming unusable after failed updates.

---

# Conclusion

IoT devices face unique security challenges due to their exposure to physical attacks and embedded hardware. Secure firmware management, hardware protections, encrypted communications, and strong authentication are essential to maintaining the confidentiality, integrity, and availability of connected devices.

---

# References

- OWASP IoT Security Guidance
- NIST SP 800-183 – Networks of 'Things'
- NISTIR 8259 – IoT Device Cybersecurity Capability Core Baseline
- Microsoft Threat Modeling Documentation
- OWASP Threat Modeling Cheat Sheet
