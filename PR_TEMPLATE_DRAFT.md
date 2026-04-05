# PR Title: feat: Add Pure Python Nightlight control via TUTK Protocol (Drop C Library Dependency)

## Description
This PR introduces native control for the CuboAI Nightlight feature using a **pure Python** implementation of the TUTK (ThroughTek) IOTC protocol. This completely eliminates the previous `libIOTCAPIs_ALL.so` C library dependency, fully resolving the deployment failures and `glibc` library crashes experienced by Home Assistant OS users on Alpine Linux.

### Key Changes:
- **Pure Python TUTK Implementation (`api/tutk.py` & `api/crypto.py`)**: Reverse-engineered the TUTK UDP transport obfuscation (`TransCodePartial` bitwise manipulation) and IOTC session handshake to build a fully native Python protocol handler.
- **Removed C Dependencies**: Deleted all `.so` binaries (`libIOTCAPIs_ALL.so`, `libgcompat.so`, etc.) decreasing the repository distribution payload by over 10 MB and removing ABI incompatibilities.
- **Native Light Entity (`light.py`)**: Refactored the `CuboNightLight` class to consume the new pure Python `TutkClient`, optimizing it to maintain connections instead of rapidly opening/closing them, increasing toggling stability and speed.
- **Tests**: Re-wrote `test_light.py` to assert against the async execution behaviors of the pure Python component, achieving 100% test passing success cleanly without native binaries.

## Type of Change
- [x] New feature (non-breaking change which adds functionality)
- [x] Bug fix (non-breaking change which fixes an issue - resolves HAOS crash)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [x] Documentation update

## Testing Performed
- [x] Verified pure Python protocol bit-for-bit matches C library packet traces.
- [x] Verified P2P nightlight toggle commands function cleanly via UDP socket transmission.
- [x] Verified Pytest passes with `100%` success locally.
