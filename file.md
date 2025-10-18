#  Unified Diagnostic Service 0x27 — SecurityAccess Deep Dive

## 🎯 Why This Service Matters
Service 0x27 secures every sensitive action inside the ECU. Understanding its architecture is essential before you can safely extend it. This document walks through the entire implementation provided in this repository, highlighting every major component, how data flows between them, and what is still missing to achieve full ISO 14229‑1:2020 conformance.

---

## 🧭 High-Level Architecture
- **Entry point**: <font color="DodgerBlue"><strong>UdsService::handleSecurityAccess</strong></font> (src/lib/uds_server/src/services/uds_0x27_secur_access.cpp) receives the raw Diagnostic Message.
- **Dispatch**: Odd sub-function ➝ <font color="DodgerBlue"><strong>handleRequestSeed</strong></font>; even sub-function ➝ <font color="DodgerBlue"><strong>handleSendKey</strong></font>.
- **Cryptographic backend**: <font color="DodgerBlue"><strong>SecurityHandler</strong></font> (src/lib/uds_server/src/uds_security_handler.cpp) generates seeds and validates keys using HMAC-SHA256.
- **Policy layer**: <font color="DodgerBlue"><strong>CustomDataServices</strong></font> (src/uds_ecu_interface/custom_data_services.cpp) publishes which levels exist and which services each level unlocks.
- **Timers**: <font color="DodgerBlue"><strong>m_securityAccessBootTimer</strong></font> and <font color="DodgerBlue"><strong>m_SecurityAccessFailTimer</strong></font> guard boot delay and brute-force penalties (created in <font color="DodgerBlue"><strong>UdsService</strong></font> constructor).

---

## 🔁 Request Flow — Step by Step
1. **Message decode**  
   <font color="DodgerBlue"><strong>UdsMessage::decodePayload</strong></font> extracts SID + payload (src/lib/uds_server/src/uds_message.cpp).
2. **Service routing**  
   <font color="DodgerBlue"><strong>UdsService::handleRequest</strong></font> switches on SID and calls <font color="DodgerBlue"><strong>handleSecurityAccess</strong></font>.
3. **Boot timer guard**  
   <font color="DodgerBlue"><strong>handleSecurityAccess</strong></font> validates that the server power-up timer expired before proceeding.
4. **Odd sub-function (Request Seed)**  
   - <font color="DodgerBlue"><strong>handleRequestSeed</strong></font> validates support via <font color="DodgerBlue"><strong>CustomDataServices::IsSecurityAccessLeveLSupported</strong></font>.  
   - Calls <font color="DodgerBlue"><strong>SecurityHandler::generateSeed</strong></font> and stores the result in `m_seed`.  
   - Sends positive response `67 xx` plus 32 random bytes.
5. **Even sub-function (Send Key)**  
   - <font color="DodgerBlue"><strong>handleSendKey</strong></font> checks request sequence (must match last seed + 1).  
   - Validates anti brute-force timer (`m_SecurityAccessFailTimer`).  
   - Invokes <font color="DodgerBlue"><strong>SecurityHandler::validateKey</strong></font> to verify HMAC(seed).  
   - On success updates `m_securityLevel`, fetches allowed services (<font color="DodgerBlue"><strong>CustomDataServices::getSecurityLeveLSupportedServices</strong></font>), notifies observers, and responds `67 xx`.  
   - On failure increments `m_NbOfSecurityAccessFailed`; when threshold reached, starts failure timer and returns `7F 27 36`.

---

## 🔍 Core Function Details
| Role | Function |
| ---- | -------- |
| Entry point | <font color="DodgerBlue"><strong>UdsService::handleSecurityAccess</strong></font> |
| Seed response | <font color="DodgerBlue"><strong>UdsService::handleRequestSeed</strong></font> |
| Key processing | <font color="DodgerBlue"><strong>UdsService::handleSendKey</strong></font> |
| Reserved-level guard | <font color="DodgerBlue"><strong>UdsService::SecurityAccessLevelIsReserved</strong></font> |
| Security level management | <font color="DodgerBlue"><strong>UdsService::setSecurityAccessLevel</strong></font>, <font color="DodgerBlue"><strong>UdsService::isSecurityAccessGranted</strong></font> |
| Seed generation | <font color="DodgerBlue"><strong>SecurityHandler::generateSeed</strong></font> |
| HMAC verification | <font color="DodgerBlue"><strong>SecurityHandler::validateKey</strong></font> |
| Data record storage | <font color="DodgerBlue"><strong>SecurityHandler::StoreReceivedSecurityAccessDataRecord</strong></font> |
| Policy support | <font color="DodgerBlue"><strong>CustomDataServices::IsSecurityAccessLeveLSupported</strong></font>, <font color="DodgerBlue"><strong>CustomDataServices::getSecurityLeveLSupportedServices</strong></font> |
| Timer creation | <font color="DodgerBlue"><strong>UdsService::UdsService</strong></font> constructor |

---

## ⚙️ Seed Generation & Key Validation
- **Seed source**: <font color="DodgerBlue"><strong>SecurityHandler::generateSeed</strong></font> delegates to <font color="DodgerBlue"><strong>security::SecureWrapper::generateSeed</strong></font>, using mbedTLS CTR_DRBG seeded with `/dev/urandom` (src/lib/port/src/security_wrapper_mbedtls.cpp).
- **Secret key**: loaded from `UDS_SECURITY_ACCESS_SYM_KEY_PATH` (default `src/uds_ecu_interface/default_security/0x27_keys/symmetric/symmetric_key.txt`).
- **Validation**: <font color="DodgerBlue"><strong>SecurityHandler::validateKey</strong></font> recalculates HMAC-SHA256(seed, secret) and performs a constant-time comparison. Expected key length is 32 bytes.

---

## 🧠 State Management
- `m_securityAccessSequence`: remembers the latest odd sub-function to enforce `seed -> key` ordering.
- `m_securityLevel`: active granted level (0 = locked).
- `m_supportedServices`: cached list of service IDs unlocked at the current level.
- `m_NbOfSecurityAccessFailed`: counts wrong keys before the failure timer triggers.
- `m_isfirstStartFailTimer`: indicates whether the failure timer is active.
- <font color="DodgerBlue"><strong>UdsService::resetSecurityAccessParams</strong></font> resets all fields and stops timers; invoked on session changes (`UdsManager::resetSecurityAccessParams`).

---

## 🧾 Negative Response Summary
| NRC | Triggered in |
| --- | ------------ |
| 0x13 IncorrectMessageLengthOrInvalidFormat | Empty payload or malformed request |
| 0x12 SubFunctionNotSupported | Unsupported security level (delegated to `CustomDataServices`) |
| 0x24 RequestSequenceError | Key sent without prior seed |
| 0x35 InvalidKey | HMAC mismatch |
| 0x36 ExceededNumberOfAttempts | Failure counter reached threshold |
| 0x37 RequiredTimeDelayNotExpired | Boot timer still running |

> **Note**: The implementation currently returns 0x13 for reserved sub-functions and never issues 0x31 even when the data record is malformed—see “What’s Missing” below.

---

## ⏱️ Timer Life Cycle
1. **Boot delay** (`m_securityAccessBootTimer`): Created at service start; `handleSecurityAccess` calls <font color="DodgerBlue"><strong>interface::os::isTimerExpired</strong></font> and fails with 0x37 until the configured `UDS_SERVER_POWER_UP_TIMEOUT` (2 s by default) elapses.
2. **Brute-force delay** (`m_SecurityAccessFailTimer`): After `UDS_MAX_NUMBER_OF_SECURITY_ACCESS_FAILED` wrong keys (default 3), <font color="DodgerBlue"><strong>interface::os::timerStart</strong></font> is invoked with `UDS_SECURITY_ACCESS_FAILED_TIMEOUT` (5 s).
3. **Reset paths**: <font color="DodgerBlue"><strong>resetSecurityAccessParams</strong></font> and <font color="DodgerBlue"><strong>UdsManager::resetSecurityAccessParams</strong></font> stop timers and clear state on session transitions or tester disconnects.

---

## 🔐 Policy Integration
- **Level definitions**: `UDS_0x27_SECURITY_LEVEL_{1|2|3}` in `custom_data_services.hpp`.
- **Service mapping**: Each level maps to a static list, e.g., level 1 ➝ `0x34`, `0x35`, `0x24`.
- **Availability checks**: Protected services like RequestDownload (`exec_0x34_rq_dowlnoad.cpp`) call <font color="DodgerBlue"><strong>isSecurityAccessGranted</strong></font> before executing.

---

## 🧪 Testing Hooks
- Unit test scaffold in `test/unit_tests/src/uds_server/services/uds_security_access_test.cpp`.
- Timer behavior can be forced in tests by toggling `interface::os::setTimerExpiredForTest`.
- Configurable secret key path lets you inject deterministic values for repeatable scenarios.

---

## 🚨 What’s Missing / Known Gaps
- Reserved sub-functions (0x41, 0x43–0x5E, 0x7F) should return 0x12, but due to `0x3F` masking the code currently responds with a seed.
- A failed key (`0x35`) does not reset `m_securityAccessSequence`, allowing a tester to replay `27 02` without requesting a fresh seed.
- <font color="DodgerBlue"><strong>handleRequestSeed</strong></font> ignores the failure timer; even during the penalty window the ECU issues new seeds instead of NRC 0x37.
- `securityAccessDataRecord` is stored but never validated; malformed data should trigger NRC 0x31.
- `SuppressPosRspMsgIndicationBit` (bit 7) is not honored: positive responses always echo the raw sub-function.
- Seed/key length is hard-coded to 32 bytes, preventing compliance with legacy 2-byte examples (e.g., `0x3657`/`0xC9A9`) unless the entire handler is customized.
- Documentation of observer behavior (the broadcast triggered by <font color="DodgerBlue"><strong>observer->onSecurityAccess</strong></font>) is absent; consumers must inspect implementation to know what side effects to expect.

---

Need help fixing these items or extending the SecurityAccess flow? Open an issue or reach out to the maintainers. Happy hacking! 🚀
