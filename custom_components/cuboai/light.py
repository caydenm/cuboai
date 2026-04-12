import logging
import asyncio
import time

from homeassistant.components.light import LightEntity, ColorMode
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN
from .api.tutk import TutkClient, TutkError

_LOGGER = logging.getLogger(__name__)

# Minimum seconds between connection attempts after a failure
_RECONNECT_COOLDOWN = 60


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up the CuboAI light platform."""
    cameras = entry.data.get("cameras", [])

    entities = []
    for camera in cameras:
        uid = camera.get("device_id")
        user = camera.get("dev_admin_id")
        pwd = camera.get("dev_admin_pwd")
        license_id = camera.get("license_id")
        baby_name = camera.get("baby_name", "Unknown")

        # P2P requires the admin credentials extracted from the cloud API
        if uid and user and pwd and license_id:
            entities.append(CuboNightLight(hass, baby_name, uid, license_id, user, pwd, camera))
        else:
            _LOGGER.warning(
                "Skipping nightlight for %s because admin credentials or license_id are missing. "
                "Please re-authenticate the integration.", baby_name
            )

    if entities:
        async_add_entities(entities, update_before_add=False)


class CuboNightLight(LightEntity):
    """Representation of a CuboAI Night Light.

    This entity does NOT poll the camera. State is set optimistically
    on toggle and cached. Polling via P2P every 30 s would starve
    Home Assistant's executor thread pool because the TUTK handshake
    and auth can take 10-15 s per attempt.
    """

    _attr_has_entity_name = True
    _attr_name = "Night Light"
    _attr_color_mode = ColorMode.ONOFF
    _attr_supported_color_modes = {ColorMode.ONOFF}
    _attr_should_poll = False  # Do NOT poll — connect only on toggle

    def __init__(self, hass, baby_name, uid, license_id, dev_admin_id, dev_admin_pwd, camera_data):
        """Initialize the light."""
        self.hass = hass
        self._baby_name = baby_name
        self._uid = uid
        self._license_id = license_id
        self._dev_admin_id = dev_admin_id
        self._dev_admin_pwd = dev_admin_pwd
        self._ip_address = camera_data.get("ip_address") or camera_data.get("host")
        self._is_on: bool | None = None
        self._attr_unique_id = f"cuboai_nightlight_{uid}"
        self._client = TutkClient(self._uid, self._license_id, self._dev_admin_id, self._dev_admin_pwd)
        self._connected = False
        self._last_connect_failure: float = 0.0  # monotonic timestamp of last failure

        self._lock = asyncio.Lock()

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information about this entity."""
        return {
            "identifiers": {(DOMAIN, self._uid)},
            "name": f"CuboAI {self._baby_name}",
            "manufacturer": "CuboAI",
            "model": "Baby Monitor",
        }

    @property
    def is_on(self) -> bool | None:
        """Return true if light is on."""
        return self._is_on

    def _ensure_connected(self):
        """Connect to the camera if not already connected.

        Respects the reconnection cooldown to avoid hammering the
        network when the camera is unreachable.

        Raises TutkError on failure.
        """
        if self._connected:
            return

        # Enforce cooldown after a previous failure
        now = time.monotonic()
        if self._last_connect_failure and (now - self._last_connect_failure) < _RECONNECT_COOLDOWN:
            remaining = int(_RECONNECT_COOLDOWN - (now - self._last_connect_failure))
            raise TutkError(
                f"Connection cooldown active ({remaining}s remaining)"
            )

        try:
            if not self._client.connect(ip=self._ip_address):
                raise TutkError("connect() returned False")
            
            self._connected = True
            self._last_connect_failure = 0.0
            
            # IP PERSISTENCE: If we found a new IP via discovery, save it to persistent storage
            # so we can skip discovery on the next Home Assistant restart.
            new_ip = self._client.transport.device_ip
            if new_ip and new_ip != self._ip_address:
                _LOGGER.info("Updating last known IP for %s: %s", self._baby_name, new_ip)
                self._ip_address = new_ip
                
                # Update the ConfigEntry data so it survives HA restarts
                current_data = dict(self.platform.config_entry.data)
                cameras = list(current_data.get("cameras", []))
                for camera in cameras:
                    if camera.get("device_id") == self._uid:
                        camera["ip_address"] = new_ip
                        break
                
                self.hass.config_entries.async_update_entry(
                    self.platform.config_entry, data=current_data
                )
        except Exception:
            self._connected = False
            self._last_connect_failure = time.monotonic()
            # Tear down any partial state
            try:
                self._client.disconnect()
            except Exception:
                pass
            raise

    async def _async_run_tutk_cmd(self, func, *args):
        """Run a blocking TUTK command in the executor with a timeout."""
        async with self._lock:
            def _run():
                try:
                    self._ensure_connected()
                    return func(self._client, *args)
                except Exception as err:
                    _LOGGER.error("TUTK command failed: %s", err)
                    self._connected = False
                    # On failure, we disconnect to ensure a fresh session next time.
                    # This is safe because _async_run_tutk_cmd holds self._lock.
                    try:
                        self._client.disconnect()
                    except Exception:
                        pass
                    raise

            loop = asyncio.get_running_loop()
            # Hard cap at 30 s to accommodate discovery (10s) + handshake + auth
            try:
                return await asyncio.wait_for(
                    loop.run_in_executor(None, _run),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                # If we timeout, we must ensure we don't leave the client in an 
                # inconsistent state, but we don't disconnect() here because 
                # the executor thread is still running _run().
                # The next call to _async_run_tutk_cmd will wait on self._lock.
                _LOGGER.warning("TUTK command timed out after 30s")
                raise

    async def async_turn_on(self, **kwargs):
        """Instruct the light to turn on."""
        try:
            success = await self._async_run_tutk_cmd(lambda c: c.set_night_light_status(True))
            if success:
                self._is_on = True
                self.async_write_ha_state()
        except (asyncio.TimeoutError, TutkError) as err:
            _LOGGER.error("Failed to turn on CuboAI night light: %s", err)

    async def async_turn_off(self, **kwargs):
        """Instruct the light to turn off."""
        try:
            success = await self._async_run_tutk_cmd(lambda c: c.set_night_light_status(False))
            if success:
                self._is_on = False
                self.async_write_ha_state()
        except (asyncio.TimeoutError, TutkError) as err:
            _LOGGER.error("Failed to turn off CuboAI night light: %s", err)

    async def async_update(self):
        """Fetch new state data for this light.

        Since should_poll is False, this is only called on explicit
        homeassistant.update_entity service calls, not on the 30 s timer.
        We still implement it so users can manually refresh if needed.
        """
        try:
            self._is_on = await self._async_run_tutk_cmd(
                lambda c: c.get_night_light_status()
            )
        except (asyncio.TimeoutError, TutkError) as err:
            _LOGGER.warning("Could not fetch CuboAI night light state: %s", err)
        except Exception as e:
            _LOGGER.error("Unexpected error updating CuboAI night light state: %s", e)
