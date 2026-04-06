"""
Pure Python TUTK/IOTC client for CuboAI nightlight control.

Protocol layers:
  1. Transport: UDP with TUTK obfuscation (crypto.transcode_encode/decode)
  2. Session:   28-byte framed packets (8 framing + 20 session context)
  3. AV Channel: 570-byte auth handshake + 28-byte AV header for IOCtrl
  4. Application: Night light get/set via IOTypes 4352-4355

Reverse-engineered from captured LD_PRELOAD + strace data of the C SDK.
"""

import logging
import os
import random
import socket
import struct
import threading
import time
from typing import Optional, Tuple

# Try relative import for HA, fallback for standalone tests
try:
    from . import crypto
except (ImportError, ValueError):
    import crypto

_LOGGER = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────────────────────────

TUTK_LAN_SEARCH_PORT = 32761
TUTK_DEVICE_PORT = 32100          # Observed default device port
IOTC_MAX_PACKET_SIZE = 2048

# Night light IOType codes
IOTYPE_USER_GET_NIGHT_LIGHT_ON_OFF_REQ  = 4352   # 0x1100
IOTYPE_USER_GET_NIGHT_LIGHT_ON_OFF_RESP = 4353   # 0x1101
IOTYPE_USER_SET_NIGHT_LIGHT_ON_OFF_REQ  = 4354   # 0x1102
IOTYPE_USER_SET_NIGHT_LIGHT_ON_OFF_RESP = 4355   # 0x1103

# AV Auth payload layout (570 bytes):
#   [0:4]     magic 00 00 0b 00
#   [4:16]    reserved (12 zeros)
#   [16:20]   version 22 02 00 00
#   [20:24]   nonce (4 random bytes)
#   [24:280]  admin_id (256 bytes, null-padded)
#   [280:536] password (256 bytes, null-padded, leading \x00)
#   [536:570] trailer (34 bytes of flags)
AV_AUTH_TOTAL_SIZE = 570

# ── Exceptions ──────────────────────────────────────────────────────────────

class TutkError(Exception):
    """Base TUTK error."""

class TutkTimeoutError(TutkError):
    """Timeout waiting for TUTK response."""

class TutkConnectionError(TutkError):
    """Failure to establish connection."""


# ── Transport Layer ─────────────────────────────────────────────────────────

class TutkTransport:
    """
    Low-level TUTK UDP transport.

    Handles obfuscation, LAN discovery, session handshake, keepalive,
    and reliable session-framed send/recv.

    Session frame layout (28 bytes header + payload):
      [0:2]   0402 prefix
      [2:4]   message type (1a02=control, 1a0a=AV data, 1d02/1d0a=responses)
      [4:6]   length (LE uint16) = len(payload) + 20 (context size)
      [6:8]   sequence number (LE uint16)
      [8:28]  20-byte session context
      [28:]   payload data
    """

    def __init__(self):
        self.device_ip: str = ""
        self.device_port: int = TUTK_LAN_SEARCH_PORT
        self.sock: Optional[socket.socket] = None
        self._connected: bool = False
        # 20-byte session context, derived from handshake
        self._session_context: bytearray = bytearray(20)
        self._seq_send: int = 0
        self._lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._alive_thread: Optional[threading.Thread] = None
        # Random 8-byte token generated during connect
        self._random_token: bytes = b'\x00' * 8

    def _ensure_socket(self) -> socket.socket:
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.settimeout(2.0)
            self.sock.bind(('', 0))
            _LOGGER.info(f"Socket bound to local port {self.sock.getsockname()[1]}")
        return self.sock

    # ── Obfuscation ──

    def _obfuscate(self, data: bytes) -> bytes:
        return crypto.transcode_encode(data)

    def _deobfuscate(self, raw: bytes) -> bytes:
        return crypto.transcode_decode(raw)

    # ── LAN Discovery ──

    def discover_lan_device(self, uid: str, timeout: float = 5.0):
        """
        Broadcast a LAN search for the device.
        Returns (ip, port, punch_out_bytes) or None.

        Tries broadcast first, then falls back to unicast scanning
        of local subnets (needed for Docker/HAOS containers where
        broadcast packets don't reach the physical LAN).
        """
        _LOGGER.debug(f"LAN search for UID: {uid}")
        sock = self._ensure_socket()

        search_pkt = self._build_lan_search_packet(uid)

        # Gather broadcast + unicast targets
        targets = self._get_discovery_targets()

        try:
            # Send to all targets
            for addr in targets:
                try:
                    sock.sendto(search_pkt, addr)
                except Exception:
                    pass

            start = time.time()
            while time.time() - start < timeout:
                try:
                    sock.settimeout(max(0.5, timeout - (time.time() - start)))
                    data, addr = sock.recvfrom(2048)
                    res = self._parse_lan_search_response(data)
                    if res:
                        found_uid, punch_out = res
                        _LOGGER.info(f"Discovered device {found_uid} at {addr[0]}:{addr[1]}")
                        return (addr[0], addr[1], punch_out)
                except socket.timeout:
                    # Re-send to all targets
                    for tgt in targets:
                        try:
                            sock.sendto(search_pkt, tgt)
                        except Exception:
                            pass
                    continue
        except Exception as e:
            _LOGGER.error(f"LAN discovery error: {e}")
        return None

    def _get_discovery_targets(self):
        """
        Build a list of (ip, port) tuples to send discovery packets to.
        Detects local subnet via /proc/net/route or socket trick,
        then sends broadcast + unicast to every host on /24.
        """
        targets = [
            ('255.255.255.255', TUTK_LAN_SEARCH_PORT),
        ]
        scanned_prefixes = set()

        # Method 1: Read default gateway from /proc/net/route (Linux)
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] != '00000000':
                        continue
                    if len(fields) >= 3 and fields[1] == '00000000':
                        # Default route found — get gateway IP
                        gw_hex = fields[2]
                        gw_ip = '.'.join(str(int(gw_hex[i:i+2], 16))
                                         for i in range(0, 8, 2))
                        parts = gw_ip.split('.')
                        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
                        if prefix not in scanned_prefixes:
                            scanned_prefixes.add(prefix)
                            _LOGGER.debug(f"Discovery: gateway subnet {prefix}.0/24")
                        break
        except Exception:
            pass

        # Method 2: Connect to a public IP to find our local address
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.settimeout(0)
            try:
                probe.connect(('10.255.255.255', 1))
                local_ip = probe.getsockname()[0]
                parts = local_ip.split('.')
                prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
                if prefix not in scanned_prefixes:
                    scanned_prefixes.add(prefix)
                    _LOGGER.debug(f"Discovery: local subnet {prefix}.0/24")
            finally:
                probe.close()
        except Exception:
            pass

        # Fallback if nothing detected
        if not scanned_prefixes:
            for prefix in ['192.168.1', '192.168.0', '10.0.0']:
                scanned_prefixes.add(prefix)

        # Build target list: broadcast + unicast for each subnet
        for prefix in scanned_prefixes:
            targets.append((f"{prefix}.255", TUTK_LAN_SEARCH_PORT))
            for host in range(1, 255):
                targets.append((f"{prefix}.{host}", TUTK_LAN_SEARCH_PORT))

        _LOGGER.info(f"Discovery: scanning {len(scanned_prefixes)} subnet(s), "
                     f"{len(targets)} targets")
        return targets

    def _build_lan_search_packet(self, uid: str) -> bytes:
        """
        Cubo AI does NOT use standard 0902 TUTK LAN discovery.
        It locally broadcasts an 88-byte 1a02 P2P Connect packet!
        """
        raw88 = bytearray(88)
        raw88[0:4] = b'\x04\x02\x1a\x02'
        raw88[4:8] = struct.pack("<I", 72)
        raw88[8:12] = b'\x01\x06\x21\x00'
        raw88[16:36] = uid.encode('ascii')[:20].ljust(20, b'\x00')
        raw88[52:56] = b'\x01\x01\x02\x04'
        # Random token to match response
        self._search_token = os.urandom(8)
        raw88[56:64] = self._search_token
        raw88[64:68] = b'\x01\x00\x00\x00'
        raw88[80:88] = b'\x45\x1f\x1b\x06\x06\x00\x1b\x63'
        return self._obfuscate(bytes(raw88))

    def _parse_lan_search_response(self, data: bytes):
        """Parse LAN search response → (uid, punch_out_bytes) or None."""
        decoded = self._deobfuscate(data)
        if len(decoded) >= 200 and decoded[0:4] == b'\x04\x02\x1d\x02':
            uid = decoded[16:36].decode('ascii', errors='ignore').strip('\x00')
            punch_out = decoded[36:44]
            return uid, punch_out
        # Sometimes it might reply with a shorter punch packet
        if len(decoded) >= 44 and decoded[0:4] == b'\x04\x02\x1d\x02':
            uid = decoded[16:36].decode('ascii', errors='ignore').strip('\x00')
            punch_out = decoded[36:44]
            return uid, punch_out
        return None

    # ── Session Handshake ──

    def connect_lan(self, device_ip: str, device_port: int, uid: str,
                    punch_out: bytes = b'\x00' * 8, timeout: float = 5.0) -> bool:
        """
        Perform the IOTC session handshake with the device.
        """
        _LOGGER.info(f"Connecting to {device_ip}:{device_port}")

        # 1) Handshake 1
        raw88 = bytearray(88)
        raw88[0:4] = b'\x04\x02\x1d\x01'
        raw88[4:8] = struct.pack("<I", 72)
        raw88[8:12] = b'\x02\x04\x33\x00'
        # ... 12:16 zeros ...
        raw88[16:36] = uid.encode('ascii')[:20].ljust(20, b'\x00')
        self._random_token = os.urandom(8)
        raw88[36:44] = self._random_token
        # ... 44:48 zeros ...
        raw88[48:56] = punch_out
        
        self._ensure_socket().sendto(self._obfuscate(bytes(raw88)), (device_ip, device_port))
        
        start = time.time()
        while time.time() - start < timeout:
            res = self.recv_session_data(timeout=1.0)
            if res:
                msg_type, full_decoded = res
                if msg_type == b'\x1d\x02':
                    if len(full_decoded) >= 28:
                        self._session_context = full_decoded[8:28]
                    break     
        self.device_ip = device_ip
        self.device_port = device_port

        self._random_token = os.urandom(8)

        # Build the 88-byte connect auth packet (from golden trace line 7)
        raw88 = bytearray(88)
        raw88[0:4] = b'\x04\x02\x1a\x02'
        raw88[4:8] = struct.pack("<I", 72)
        raw88[8:12] = b'\x01\x06\x21\x00'
        raw88[16:36] = uid.encode('ascii')[:20].ljust(20, b'\x00')
        raw88[52:56] = b'\x01\x01\x02\x04'
        raw88[56:64] = self._random_token
        raw88[64:68] = b'\x01\x00\x00\x00'
        raw88[80:88] = b'\x45\x1f\x1b\x06\x06\x00\x1b\x63'

        obf88 = self._obfuscate(bytes(raw88))
        sock = self._ensure_socket()

        try:
            for attempt in range(5):
                _LOGGER.info(f"Handshake attempt {attempt + 1}")
                sock.sendto(obf88, (device_ip, device_port))

                end = time.time() + 2.0
                sock.settimeout(1.0)
                while time.time() < end:
                    try:
                        data, addr = sock.recvfrom(2048)
                        dec = self._deobfuscate(data)

                        # Look for the 200-byte session confirmation:
                        # 04 02 1d 02 ... with 02 06 12 00 marker
                        if (len(dec) >= 20
                                and dec[0:4] == b'\x04\x02\x1d\x02'
                                and b'\x02\x06\x12\x00' in dec):
                            _LOGGER.info("HANDSHAKE SUCCESS!")

                            # Update device port to the port the response came from
                            if addr[1] != device_port:
                                _LOGGER.info(
                                    f"Device responded from port {addr[1]} "
                                    f"(was {device_port}), switching"
                                )
                                self.device_port = addr[1]

                            # Build session context (20 bytes) from our random token
                            self._session_context = bytearray(20)
                            self._session_context[0:4] = b'\x07\x04\x21\x00'
                            self._session_context[4:6] = self._random_token[0:2]
                            self._session_context[6:8] = b'\x00\x00'
                            self._session_context[8:12] = b'\x0c\x00\x00\x00'
                            self._session_context[12:20] = self._random_token

                            self._connected = True
                            self._start_keepalive()
                            return True
                    except socket.timeout:
                        continue
        except Exception as e:
            _LOGGER.error(f"Handshake error: {e}")
        return False

    # ── Keepalive ──

    def _start_keepalive(self):
        self._stop_event.clear()
        self._alive_thread = threading.Thread(
            target=self._keepalive_loop, daemon=True
        )
        self._alive_thread.start()

    def _keepalive_loop(self):
        while not self._stop_event.wait(10.0):
            if not self._connected or not self.sock:
                break
            try:
                keep = bytearray(24)
                keep[0:4] = b'\x04\x02\x1a\x02'
                keep[4:8] = struct.pack("<I", 8)
                keep[8:12] = b'\x03\x80\x3f\x00'
                keep[16:24] = b'\x45\x86\x1b\x06\x06\x00\xcf\x60'
                self.sock.sendto(self._obfuscate(bytes(keep)),
                                 (self.device_ip, self.device_port))
            except Exception:
                break

    # ── Session-framed Send/Recv ──

    def _build_session_frame(self, payload: bytes,
                             magic: bytes = b'\x1a\x0a') -> bytes:
        """
        Wrap payload in a 28-byte session header and obfuscate.

        Layout:
          [0:2]   0402 prefix
          [2:4]   magic type
          [4:6]   length = len(payload) + 20
          [6:8]   sequence number
          [8:28]  20-byte session context
          [28:]   payload
        """
        total_len = len(payload) + 28
        pkt = bytearray(total_len)
        pkt[0:4] = b'\x04\x02' + magic
        length = len(payload) + 12
        pkt[4:6] = struct.pack("<H", length)
        pkt[6:8] = struct.pack("<H", self._seq_send)
        
        if hasattr(self, '_session_context') and len(self._session_context) == 20:
            pkt[8:28] = self._session_context
        
        pkt[28:total_len] = payload
        
        self._seq_send += 1
        return bytes(pkt)

    def send_session_data(self, payload: bytes,
                          magic: bytes = b'\x1a\x0a') -> int:
        """Build a session frame around payload, obfuscate, and send it."""
        if not self._connected or not self.sock:
            raise TutkError("Not connected")
        frame = self._build_session_frame(payload, magic)
        return self.send_raw(self._obfuscate(frame))

    def send_raw(self, frame: bytes) -> int:
        """Send already-obfuscated frame bytes."""
        if not self.sock:
            return -1
        with self._lock:
            self.sock.sendto(frame, (self.device_ip, self.device_port))
        return 0
    def drain(self):
        """
        Drain all pending packets from the UDP socket receive buffer.
        Useful before sending a command to ensure we don't read stale
        status updates that the camera was streaming.
        """
        if not self.sock:
            return
        
        try:
            with self._recv_lock:
                orig_timeout = self.sock.gettimeout()
                self.sock.settimeout(0.0)
                try:
                    count = 0
                    while count < 5000:
                        self.sock.recvfrom(2048)
                        count += 1
                except (BlockingIOError, socket.error):
                    # Buffer is empty
                    pass
                finally:
                    self.sock.settimeout(orig_timeout)
        except Exception as e:
            _LOGGER.debug(f"Drain error: {e}")
    def recv_session_data(self, timeout: float = 5.0):
        """
        Receive and deobfuscate a session packet.

        Returns (magic_bytes, payload_after_context) or None on timeout.
        The magic_bytes are pkt[2:4] which identify packet type.
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                if not self.sock:
                    break
                with self._recv_lock:
                    remaining = timeout - (time.time() - start)
                    if remaining <= 0:
                        break
                    self.sock.settimeout(min(1.0, remaining))
                    data, addr = self.sock.recvfrom(2048)

                if len(data) == 0:
                    continue

                decoded = self._deobfuscate(data)
                msg_type = decoded[2:4]

                # Auto-ACK received 1d0a data packets to maintain
                # reliable delivery (camera won't process SET commands
                # without session-level acknowledgments)
                if msg_type == b'\x1d\x0a' and len(decoded) >= 8:
                    recv_seq = struct.unpack('<H', decoded[6:8])[0]
                    self._send_session_ack(recv_seq)

                return msg_type, decoded
            except socket.timeout:
                continue
            except Exception as e:
                _LOGGER.error(f"recv_session_data error: {e}")
                break
        return None

    def _send_session_ack(self, acked_seq: int):
        """
        Send a session-level ACK (0x0900) for the given received sequence.
        Required by the TUTK reliable delivery layer — the camera won't
        process write commands (SET) until it knows its data is being received.
        """
        ack_data = bytearray(24)
        ack_data[0:2] = b'\x09\x00'       # ACK magic
        ack_data[2:4] = b'\x0b\x00'       # channel
        struct.pack_into('<I', ack_data, 4, acked_seq)
        ack_data[8:12] = b'\xff\xff\xff\xff'
        # [12:24] = zeros (recv count, channel data, trailer)
        try:
            self.send_session_data(bytes(ack_data), magic=b'\x1a\x0a')
        except Exception:
            pass  # Best-effort ACK

    def close(self):
        self._connected = False
        self._stop_event.set()
        if self._alive_thread:
            self._alive_thread.join(timeout=1)
        if self.sock:
            self.sock.close()
            self.sock = None


# ── AV Channel ──────────────────────────────────────────────────────────────

class AVChannel:
    """
    AV channel for authentication and IOCtrl commands.

    Auth: Sends a 570-byte avClientStart payload inside a session frame.
    IOCtrl: Sends commands with a 28-byte AV header + io_type + payload.
    """

    def __init__(self, transport: TutkTransport, uid: str = ""):
        self.transport = transport
        self.uid = uid
        self._auth_ok = False
        self._av_seq = 0
        # Write counter from golden trace (increments per-command-type cycle)
        self._write_counter = 0

    def authenticate(self, admin_id: str, admin_pwd: str,
                     timeout: float = 15.0) -> bool:
        """
        Send the 570-byte AV auth handshake and wait for confirmation.

        Payload layout (570 bytes):
          [0:4]     00 00 0b 00  (magic)
          [4:16]    zeros        (reserved)
          [16:20]   22 02 00 00  (version)
          [20:24]   nonce        (4 random bytes)
          [24:280]  admin_id     (256 bytes, null-padded)
          [280:536] password     (256 bytes, 1 leading null + null-padded)
          [536:570] trailer      (34 bytes of flags)
        """
        _LOGGER.info(f"Authenticating AV channel ({admin_id})...")

        payload = bytearray(AV_AUTH_TOTAL_SIZE)

        # Magic
        payload[0:4] = b'\x00\x00\x0b\x00'
        # Reserved [4:16] = zeros (already zero)
        # Version
        payload[16:20] = b'\x22\x02\x00\x00'
        # Random nonce
        nonce = struct.pack("<I", random.randint(0, 0xFFFFFFFF))
        payload[20:24] = nonce

        # Admin ID at offset 24 (256 bytes, null-padded)
        admin_bytes = admin_id.encode('ascii')[:255]
        payload[24:24 + len(admin_bytes)] = admin_bytes

        # Password at offset 281 (1 leading null + null-padded, from angr memory layout)
        pwd_bytes = admin_pwd.encode('ascii')[:255]
        payload[281:281 + len(pwd_bytes)] = pwd_bytes

        # Trailer (verified byte-by-byte from full golden trace)
        # [542:546] = 04000000, [546:550] = fb071f00
        # [550:560] = 10 byte zeroes, [560:564] = 03000000
        # [564:568] = 261b0815, [568:570] = 020c
        payload[542:546] = b'\x04\x00\x00\x00'
        payload[546:550] = b'\xfb\x07\x1f\x00'
        payload[560:564] = b'\x03\x00\x00\x00'
        payload[564:568] = b'\x26\x1b\x08\x15'
        payload[568:570] = b'\x02\x0c'

        # Send auth payload via session frame (single obfuscation via
        # send_session_data → _build_session_frame → _obfuscate)
        self.transport.send_session_data(bytes(payload), magic=b'\x1a\x0a')

        # Also send the 52-byte session confirm packet (line 18 of golden trace)
        self._send_session_confirm()

        # Wait for auth response
        start = time.time()
        handshake_seen = False
        while time.time() - start < timeout:
            res = self.transport.recv_session_data(timeout=2.0)
            if not res:
                # Retry auth send
                if not handshake_seen:
                    self.transport.send_session_data(
                        bytes(payload), magic=b'\x1a\x0a'
                    )
                    self._send_session_confirm()
                continue
                
            msg_type, full_decoded = res
            
            # 1d0a = AV session data (auth response expected here)
            if msg_type == b'\x1d\x0a' and len(full_decoded) >= 68:
                data = full_decoded[28:]
                if data[0:4] == b'\x00\x70\x0b\x00':
                    _LOGGER.info(f"AV auth response received (len {len(data)})")
                    self._auth_ok = True
                    return True
            
            # 1d02 = handshake confirmation
            if msg_type == b'\x1d\x02' and len(full_decoded) >= 28:
                _LOGGER.info(f"Handshake response received (len {len(full_decoded)})")
                handshake_seen = True

        if handshake_seen:
            _LOGGER.warning("Handshake seen but no AV auth response; "
                            "treating as authenticated")
            self._auth_ok = True
            return True

        return False

    def _send_session_confirm(self):
        """
        Send the 52-byte session-confirm packet (golden trace line 18).

        This is a 1a02-typed control packet containing the UID and token.
        """
        raw24 = bytearray(24)
        raw24[0:4] = b'\x04\x02\x1d\x03'
        raw24[4:8] = struct.pack("<I", 8)
        if hasattr(self.transport, '_session_context') and len(self.transport._session_context) == 20:
            raw24[8:24] = b'\x02\x04\x33\x00' + self.transport._session_context[4:16]
        else:
            raw24[8:12] = b'\x02\x04\x33\x00'
        
        self.transport.send_raw(self.transport._obfuscate(bytes(raw24)))
        
        # Wait for Handshake 2 Response
        start = time.time()
        while time.time() - start < 2.0:
            res = self.transport.recv_session_data(timeout=0.5)
            if res:
                if res[0] == b'\x1d\x04' or res[0] == b'\x1d\x02':
                    pass
                if len(res[1]) <= 52 and res[0] == b'\x1d\x02':
                    break
        raw = bytearray(52)
        raw[0:4] = b'\x04\x02\x1a\x02'
        raw[4:8] = struct.pack("<I", 36)
        raw[8:12] = b'\x02\x04\x33\x00'
        # [12:16] = zeros
        raw[16:36] = self.uid.encode('ascii')[:20].ljust(20, b'\x00')
        raw[36:44] = self.transport._random_token
        # [44:48] = zeros
        raw[48:52] = b'\x06\x05\x2b\x0e'

        obf = self.transport._obfuscate(bytes(raw))
        self.transport.send_raw(obf)

    def send_ioctrl(self, io_type: int, user_payload: bytes = b"") -> int:
        """
        Send an IOCtrl command.
        Builds a 28-byte AV header + 4-byte io_type + user_payload.
        """
        if not self._auth_ok:
            raise TutkError("Not authenticated")

        inner_len = 4 + len(user_payload)  # io_type + user data

        av_header = bytearray(28)
        av_header[0:4] = b'\x00\x70\x0b\x00'
        struct.pack_into("<H", av_header, 4, self._av_seq)
        av_header[6:8] = b'\x59\x46'
        # Channel flags: 00 70 XX 00 where XX tracks write phase
        av_header[8:12] = struct.pack("<I", 0x00007000 | ((self._write_counter & 0xFF) << 16))
        struct.pack_into("<I", av_header, 12, 1)   # action = 1
        struct.pack_into("<I", av_header, 16, inner_len)
        struct.pack_into("<I", av_header, 20, self._write_counter)
        # [24:28] = zeros (reserved)

        # IO type + user payload
        io_data = struct.pack("<I", io_type) + user_payload

        full_payload = bytes(av_header) + io_data

        _LOGGER.debug(f"send_ioctrl type=0x{io_type:04x} seq={self._av_seq}")

        self.transport.send_session_data(full_payload, magic=b'\x1a\x0a')

        self._av_seq += 1
        self._write_counter += 1
        return 0

    def recv_ioctrl(self, expected_type: int = 0,
                    timeout: float = 5.0) -> Tuple[int, bytes]:
        """
        Receive an IOCtrl response.

        Parses the AV header to extract io_type at offset [28:32]
        and user payload at [32:].

        Returns (io_type, user_payload_bytes).
        """
        start = time.time()
        pkt_idx = 0
        while time.time() - start < timeout:
            res = self.transport.recv_session_data(timeout=1.0)
            if not res:
                continue

            msg_type, full_decoded = res
            pkt_idx += 1
            _LOGGER.debug(
                f"recv_ioctrl [{pkt_idx}] type={msg_type.hex()} "
                f"len={len(full_decoded)} expecting=0x{expected_type:04x}"
            )

            if msg_type != b'\x1d\x0a' or len(full_decoded) < 56:
                continue

            data = full_decoded[28:]
            if len(data) < 32:
                continue

            io_type = struct.unpack("<I", data[28:32])[0]
            user_payload = data[32:]

            if expected_type == 0 or io_type == expected_type:
                _LOGGER.debug(f"recv_ioctrl type=0x{io_type:04x}")
                return io_type, user_payload

        raise TutkTimeoutError(
            f"IOCtrl response timeout (expected 0x{expected_type:04x})"
        )


# ── High-Level Client ───────────────────────────────────────────────────────

class TutkClient:
    """Pure Python TUTK client for CuboAI cameras."""

    def __init__(self, uid: str, license_id: str,
                 admin_id: str, admin_pwd: str, region: int = 0):
        self.uid = uid
        self.license_id = license_id
        self.admin_id = admin_id
        self.admin_pwd = admin_pwd
        self.transport: TutkTransport = TutkTransport()
        self.av_channel: Optional[AVChannel] = None

    def connect(self, timeout: float = 10.0) -> bool:
        """Discover device on LAN, establish session, authenticate."""
        _LOGGER.info(f"Connecting to {self.uid}...")

        res = self.transport.discover_lan_device(
            self.license_id, timeout=min(5.0, timeout)
        )
        if not res:
            _LOGGER.error("Device not found on LAN")
            return False

        ip, port, punch_out = res
        if not self.transport.connect_lan(ip, port, self.license_id, punch_out):
            _LOGGER.error("Handshake failed")
            return False

        self.av_channel = AVChannel(self.transport, uid=self.license_id)
        if not self.av_channel.authenticate(
                self.admin_id, self.admin_pwd, timeout=10.0):
            _LOGGER.error("AV auth failed")
            return False

        _LOGGER.info("Connected successfully")
        return True

    def connect_direct(self, ip: str, port: int = TUTK_DEVICE_PORT,
                       timeout: float = 30.0):
        """Connect directly to a known IP (skip LAN discovery)."""
        _LOGGER.info(f"Direct connect to {ip}:{port}")
        if not self.transport.connect_lan(
                ip, port, self.license_id, b'\x00' * 8):
            raise TutkConnectionError("Handshake failed")

        self.av_channel = AVChannel(self.transport, uid=self.license_id)
        if not self.av_channel.authenticate(
                self.admin_id, self.admin_pwd, timeout=10.0):
            raise TutkConnectionError("AV auth failed")

    def get_night_light_status(self) -> bool:
        """
        Get the current night light status.

        Sends IOType 0x1100 (GET_NIGHT_LIGHT_ON_OFF_REQ) with 8-byte
        payload (timestamp + reserved).
        Response IOType 0x1101 has 16 bytes: msg_id(4) + result(4) + on_off(4) + reserved(4).
        """
        if not self.av_channel:
            return False
        try:
            # Drain the network buffer of old status streams before sending a request
            self.transport.drain()

            msg_id = int(time.time())
            payload = struct.pack("<ii", msg_id, 0)
            self.av_channel.send_ioctrl(
                IOTYPE_USER_GET_NIGHT_LIGHT_ON_OFF_REQ, payload
            )
            io_type, resp = self.av_channel.recv_ioctrl(
                IOTYPE_USER_GET_NIGHT_LIGHT_ON_OFF_RESP, 
                timeout=5.0
            )
            _LOGGER.debug(f"GET resp ({len(resp)} bytes): {resp.hex()}")
            if len(resp) >= 12:
                resp_msg_id, result, on_off = struct.unpack("<iii", resp[:12])
                _LOGGER.info(
                    f"Night light: msg_id={resp_msg_id} result={result} "
                    f"on_off={on_off}"
                )
                return on_off == 1
        except Exception as e:
            _LOGGER.error(f"Error getting nightlight: {e}")
        return False

    def set_night_light_status(self, state: bool) -> bool:
        """
        Set the night light on or off.

        Sends IOType 0x1102 (SET_NIGHT_LIGHT_ON_OFF_REQ) with 12-byte
        payload (msg_id + on_off + reserved).
        """
        if not self.av_channel:
            return False
        try:
            # Drain the network buffer of old status streams before sending a request
            self.transport.drain()

            on_off = 1 if state else 0
            msg_id = int(time.time())
            payload = struct.pack("<iii", msg_id, on_off, 0)
            self.av_channel.send_ioctrl(
                IOTYPE_USER_SET_NIGHT_LIGHT_ON_OFF_REQ, payload
            )
            # Wait for 0x1103 SET response (confirmation)
            try:
                io_type, resp = self.av_channel.recv_ioctrl(
                    IOTYPE_USER_SET_NIGHT_LIGHT_ON_OFF_RESP,
                    timeout=15.0
                )
                _LOGGER.info(f"SET response received: {resp.hex()}")
                return True
            except TutkTimeoutError:
                _LOGGER.warning("No SET response received, command may still have worked")
                return True  # SET was sent, assume it worked
        except Exception as e:
            _LOGGER.error(f"Error setting nightlight: {e}")
        return False

    def disconnect(self):
        _LOGGER.info("Disconnecting")
        if self.av_channel:
            self.av_channel = None
        self.transport.close()
