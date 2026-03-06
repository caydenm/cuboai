# PR Title: feat: Add Nightlight control via TUTK P2P protocol

## Description
This PR introduces native control for the CuboAI Nightlight feature. The nightlight control operates on a local P2P connection rather than the standard cloud API endpoints, which required introducing the TUTK SDK.

### Key Changes:
- **P2P Communication (`tutk.py`)**: Added a Python wrapper around the `libIOTCAPIs_ALL.so` library to establish P2P sessions and send IO control commands directly to the camera to toggle the nightlight.
- **Native Light Entity (`light.py`)**: Created the `CuboNightLight` class extending Home Assistant's `LightEntity`. It operates statelessly, spinning up its own `TutkClient` on demand using securely stored device credentials.
- **Credential Persistence (`config_flow.py` & API)**: Updated the multi-camera device profiles mapping to extract and store the required P2P credentials (`license_id`, `dev_admin_id`, `dev_admin_pwd`) seamlessly during the config flow setup.
- **Tests**: Refactored existing data structure assertions in `test_config_flow.py`, `test_async_api.py`, and `test_multi_camera.py` to support the new credential pairs without breaking backwards compatibility. Added `test_light.py` to mock and verify the native entity.

All required secrets are now handled securely following Home Assistant's standard ConfigEntry patterns without exposing sensitive variable logs.

## Related Issues
*(Link any related issues here if applicable)*

## Type of Change
- [x] New feature (non-breaking change which adds functionality)
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing Performed
- [x] Verified P2P `avRecvIOCtrl` commands toggle the physical device state.
- [x] Verified Pytest passes with `100%` success locally across 76 unified test paths.
- [x] Verified back-compat login flow fallback behavior functions safely.
