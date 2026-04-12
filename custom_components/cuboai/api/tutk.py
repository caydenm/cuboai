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
# import boto3
import jwt
import requests
# from pycognito.aws_srp import AWSSRP
from typing import Optional, Tuple, Dict
from collections import defaultdict

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
        self._seq_send = defaultdict(int)
        self._lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._alive_thread: Optional[threading.Thread] = None
        # Random 8-byte token generated during connect
        self._random_token: bytes = b'\x00' * 8
        self._keepalive_paused: bool = False
        self._last_set_time: float = 0
        self._last_set_state: bool = False

    def _ensure_socket(self) -> socket.socket:
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Help with discovery in containerized environments (HAOS/Docker)
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.settimeout(2.0)
            self.sock.bind(('', 0))
            _LOGGER.debug(f"Socket bound to local port {self.sock.getsockname()[1]}")
        return self.sock

    # ── Obfuscation ──

    def _obfuscate(self, data: bytes) -> bytes:
        return crypto.transcode_encode(data)

    def _deobfuscate(self, raw: bytes) -> bytes:
        return crypto.transcode_decode(raw)

    # ── LAN Discovery ──

    def discover_lan_device(self, uid: str, timeout: float = 10.0):
        """
        Broadcast a LAN search for the device.
        Returns (ip, port, punch_out_bytes) or None.

        Sends to broadcast addresses and unicast-scans all detected
        subnets. Includes extensive logging for HAOS debugging.
        """
        _LOGGER.info(f"LAN search for UID: {uid} (timeout={timeout}s)")
        sock = self._ensure_socket()

        search_pkt = self._build_lan_search_packet(uid)

        # Gather broadcast + unicast targets
        targets = self._get_discovery_targets()

        recv_count = 0
        try:
            # Send to all targets
            sent = 0
            for addr in targets:
                try:
                    sock.sendto(search_pkt, addr)
                    sent += 1
                except Exception:
                    pass
            _LOGGER.info(f"Discovery: sent search packet to {sent}/{len(targets)} targets")

            start = time.time()
            while time.time() - start < timeout:
                if not self.sock:
                    break
                try:
                    sock.settimeout(max(0.1, min(1.0, timeout - (time.time() - start))))
                    data, addr = sock.recvfrom(2048)
                    recv_count += 1
                    res = self._parse_lan_search_response(data)
                    if res:
                        found_uid, punch_out = res
                        _LOGGER.info(f"Discovered device {found_uid} at {addr[0]}:{addr[1]}")
                        return (addr[0], addr[1], punch_out)
                    else:
                        # Log non-matching packets to help debug
                        decoded = self._deobfuscate(data)
                        _LOGGER.debug(
                            f"Discovery: got {len(data)}B from {addr[0]}:{addr[1]} "
                            f"(decoded magic={decoded[0:4].hex()}, not a match)"
                        )
                except (socket.timeout, BlockingIOError):
                    if not self.sock:
                        break
                    # Re-send to all targets to keep poking
                    for tgt in targets:
                        try:
                            sock.sendto(search_pkt, tgt)
                        except (socket.error, socket.timeout):
                            pass
                    continue
                except socket.error as se:
                    # Catch Errno 9 (Bad file descriptor) which happens if 
                    # another thread calls close() while we are in recvfrom.
                    if se.errno == 9:
                        _LOGGER.debug("Discovery socket closed concurrently")
                    else:
                        _LOGGER.error(f"Discovery socket error: {se}")
                    break
        except Exception as e:
            _LOGGER.error(f"LAN discovery error: {e}")

        _LOGGER.warning(
            f"Discovery: device not found after {timeout}s "
            f"(received {recv_count} packets, none matched)"
        )
        return None

    def _get_discovery_targets(self):
        """
        Build a list of (ip, port) tuples to send discovery packets to.
        Enumerates ALL connected subnets from multiple sources.
        """
        targets = [
            ('255.255.255.255', TUTK_LAN_SEARCH_PORT),
        ]
        scanned_prefixes = set()

        # Method 1: Read ALL subnets from /proc/net/route (not just default gw)
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) < 8:
                        continue
                    iface = fields[0]
                    dest_hex = fields[1]
                    gw_hex = fields[2]
                    mask_hex = fields[7]

                    # Parse the destination network (Little-Endian hex)
                    dest_ip = '.'.join(str(int(dest_hex[i:i+2], 16))
                                       for i in range(6, -1, -2))

                    # For default route (dest=0.0.0.0), use the gateway IP
                    if dest_hex == '00000000' and gw_hex != '00000000':
                        gw_ip = '.'.join(str(int(gw_hex[i:i+2], 16))
                                         for i in range(6, -1, -2))
                        parts = gw_ip.split('.')
                        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
                        if prefix not in scanned_prefixes:
                            scanned_prefixes.add(prefix)
                            _LOGGER.info(f"Discovery: default gw subnet {prefix}.0/24 ({iface})")

                    # For connected subnets (non-zero dest), use the destination
                    elif dest_hex != '00000000':
                        parts = dest_ip.split('.')
                        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
                        # Skip loopback and link-local
                        if parts[0] in ('127', '169'):
                            continue
                        if prefix not in scanned_prefixes:
                            scanned_prefixes.add(prefix)
                            _LOGGER.info(f"Discovery: connected subnet {prefix}.0/24 ({iface})")

        except Exception as e:
            _LOGGER.warning(f"Discovery: failed to read /proc/net/route: {e}")

        # Method 2: Enumerate all interface IPs
        try:
            # Try using netifaces if available
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                for addr_info in addrs.get(netifaces.AF_INET, []):
                    ip = addr_info.get('addr', '')
                    parts = ip.split('.')
                    if len(parts) == 4 and parts[0] not in ('127', '169'):
                        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
                        if prefix not in scanned_prefixes:
                            scanned_prefixes.add(prefix)
                            _LOGGER.info(f"Discovery: interface {iface} subnet {prefix}.0/24")
        except ImportError:
            pass
        except Exception as e:
            _LOGGER.debug(f"Discovery: netifaces scan failed: {e}")

        # Method 3: Socket probe to find default outbound IP
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
                    _LOGGER.info(f"Discovery: outbound IP subnet {prefix}.0/24")
            finally:
                probe.close()
        except Exception:
            pass

        # Method 4: Parse 'ip addr' output as last resort
        try:
            import subprocess
            result = subprocess.run(
                ['ip', '-4', '-o', 'addr', 'show'],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                # Format: "2: eth0    inet 192.168.1.100/24 ..."
                parts_line = line.split()
                for i, token in enumerate(parts_line):
                    if token == 'inet' and i + 1 < len(parts_line):
                        ip_cidr = parts_line[i + 1]
                        ip = ip_cidr.split('/')[0]
                        parts = ip.split('.')
                        if len(parts) == 4 and parts[0] not in ('127', '169'):
                            prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
                            if prefix not in scanned_prefixes:
                                scanned_prefixes.add(prefix)
                                _LOGGER.info(f"Discovery: ip-addr subnet {prefix}.0/24")
        except Exception as e:
            _LOGGER.debug(f"Discovery: 'ip addr' fallback failed: {e}")

        # Always include common home subnets as fallback
        for prefix in ['192.168.1', '192.168.0', '192.168.2', '10.0.0', '10.0.1']:
            if prefix not in scanned_prefixes:
                scanned_prefixes.add(prefix)
                _LOGGER.debug(f"Discovery: adding common subnet {prefix}.0/24")

        # Build target list: broadcast + unicast for each subnet
        for prefix in scanned_prefixes:
            targets.append((f"{prefix}.255", TUTK_LAN_SEARCH_PORT))
            for host in range(1, 255):
                targets.append((f"{prefix}.{host}", TUTK_LAN_SEARCH_PORT))

        _LOGGER.info(
            f"Discovery: scanning {len(scanned_prefixes)} subnet(s): "
            f"{', '.join(sorted(scanned_prefixes))} "
            f"({len(targets)} targets)"
        )
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
            if self._keepalive_paused:
                continue
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
        pkt[6:8] = struct.pack("<H", self._seq_send[magic])
        
        if hasattr(self, '_session_context') and len(self._session_context) == 20:
            pkt[8:28] = self._session_context
        
        pkt[28:total_len] = payload
        
        self._seq_send[magic] += 1
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
    def drain(self, max_duration: float = 1.0, silence_timeout: float = 0.2):
        """
        Drain pending packets until silence is detected or max_duration reached.
        """
        if not self.sock:
            return
        
        start = time.time()
        count = 0
        try:
            with self._recv_lock:
                orig_timeout = self.sock.gettimeout()
                while time.time() - start < max_duration:
                    try:
                        # Wait for a short burst of silence
                        self.sock.settimeout(silence_timeout)
                        self.sock.recvfrom(4096)
                        count += 1
                        # If we got a packet, we reduce the silence window for the next one
                        # to keep things moving fast.
                        silence_timeout = min(silence_timeout, 0.05)
                    except (BlockingIOError, socket.timeout):
                        # Silence detected!
                        break
                self.sock.settimeout(orig_timeout)
        except Exception as e:
            _LOGGER.debug(f"Drain error after {count} pkts: {e}")
    def recv_session_data(self, timeout: float = 5.0, suppress_ack: bool = False):
        """
        Receive and deobfuscate a session packet.
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                if not self.sock:
                    break
                with self._recv_lock:
                    # SLURP FIX: If timeout is 0, we must attempt a non-blocking read.
                    if timeout == 0:
                        self.sock.settimeout(0.0)
                    else:
                        remaining = timeout - (time.time() - start)
                        if remaining <= 0:
                            break
                        self.sock.settimeout(min(1.0, remaining))
                    
                    try:
                        data, addr = self.sock.recvfrom(2048)
                    except (BlockingIOError, socket.timeout):
                        if remaining <= 0:
                            break
                        continue

                if len(data) == 0:
                    continue

                decoded = self._deobfuscate(data)
                msg_type = decoded[2:4]

                # Auto-ACK received 1d0a data packets to maintain
                # reliable delivery. During floods, we can suppress this
                # to prioritize receiving over sending.
                if not suppress_ack and msg_type == b'\x1d\x0a' and len(decoded) >= 8:
                    recv_seq = struct.unpack('<H', decoded[6:8])[0]
                    # Direct ACK sending to avoid framing overhead
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
        Required by the TUTK reliable delivery layer.
        """
        if not self.sock:
            return
        
        # Audio-style ACK (Magic 09 00 0b 00)
        ack_data = bytearray(24)
        ack_data[0:2] = b'\x09\x00'       # ACK magic
        ack_data[2:4] = b'\x0b\x00'       # channel
        struct.pack_into("<H", ack_data, 4, acked_seq)  # 16-bit seq
        ack_data[6:12] = b'\x00\x00\xff\xff\xff\xff'
        
        # Send wrapped in a session frame (1a 0a)
        try:
            self.send_session_data(bytes(ack_data), magic=b'\x1a\x0a')
        except Exception:
            pass

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
        self._auth_token = b'\x00' * 28
        self._av_seq = 0
        self._av_seq_lock = threading.Lock()
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

        # Trailer (34 bytes at offset 536 - exactly matched from golden trace)
        # These flags indicate client capabilities and are required for state modification.
        trailer = bytes.fromhex("00000000000004000000fb071f000000000000000000000003000000000000000000")
        payload[536:570] = trailer

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
                _LOGGER.debug("recv_session_data timeout during auth loop")
                # Retry auth send
                if not handshake_seen:
                    _LOGGER.debug("Retrying auth send...")
                    self.transport.send_session_data(
                        bytes(payload), magic=b'\x1a\x0a'
                    )
                    self._send_session_confirm()
                continue
                
            msg_type, full_decoded = res
            _LOGGER.debug(f"AUTH LOOP RECV: type={msg_type.hex()} len={len(full_decoded)} data[0:8]={full_decoded[28:36].hex() if len(full_decoded)>=36 else 'N/A'}")
            
            # 1d0a = AV session data (auth response expected here)
            if msg_type == b'\x1d\x0a' and len(full_decoded) >= 60:
                data = full_decoded[28:]
                if data[0:4] == b'\x00\x21\x0b\x00':  # 0x000b2100 = AV_AUTH_RESP
                    _LOGGER.info(f"AV auth response received (len {len(data)})")
                    # Capture the 28-byte session token following the 4-byte magic
                    self._auth_token = data[4:32]
                    self._auth_ok = True
                    self._start_keepalive()
                    return True
            
            # 1d02 = handshake confirmation
            if msg_type == b'\x1d\x02' and len(full_decoded) >= 28:
                _LOGGER.info(f"Handshake response received (len {len(full_decoded)})")
                handshake_seen = True

        if handshake_seen:
            _LOGGER.warning("Handshake seen but no AV auth response; "
                            "treating as authenticated")
            self._auth_ok = True
            self._start_keepalive()
            return True

        return False

    def _send_session_confirm(self):
        """
        Send the 52-byte session-confirm (Handshake 2) packet.
        Magic: 0x1a 0x02, Payload Magic: 0x02043300
        """
        payload = bytearray(24)
        # Payload magic 0x00330402 as seen in golden trace (little endian of trace bytes 02 04 33 00)
        payload[0:4] = b'\x02\x04\x33\x00'
        # The trace shows 20 bytes of zeros following it
        self.transport.send_session_data(bytes(payload), magic=b'\x1a\x02')

    def _start_keepalive(self):
        """Start background thread pumping fake A/V dummy frames."""
        if getattr(self, "_keepalive_running", False):
            return

        self._keepalive_running = True
        self._keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self._keepalive_thread.start()

    def _stop_keepalive(self):
        """Stop the keepalive background thread."""
        self._keepalive_running = False
        if hasattr(self, "_keepalive_thread") and self._keepalive_thread:
            self._keepalive_thread.join(timeout=2)
            self._keepalive_thread = None

    def _keepalive_loop(self):
        """Send dummy A/V frames to keep the control tunnel alive."""
        # 500ms interval is sufficient to keep the session alive
        # without flooding the network (was 50ms = 20 pkt/s)
        while getattr(self, "_keepalive_running", False):
            try:
                d1 = bytearray(bytes.fromhex("09000b0000000500ffffffff0000000000000000221afd76"))
                d2 = bytearray(bytes.fromhex("0a080b0000000500df6c320000000000"))

                with self._av_seq_lock:
                    struct.pack_into("<H", d1, 4, self._av_seq)
                    self._av_seq += 1
                    self.transport.send_session_data(d1)

                    struct.pack_into("<H", d2, 4, self._av_seq)
                    self._av_seq += 1
                    self.transport.send_session_data(d2)
            except Exception:
                break  # Transport closed, exit gracefully

            time.sleep(0.5)
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

        # Inner Length (Total payload after 28-byte AV_HDR)
        # Includes io_type(4) + user_payload + session_token(28)
        inner_len = 4 + len(user_payload) + len(self._auth_token)

        av_header = bytearray(28)
        av_header[0:4] = b'\x00\x70\x0b\x00'
        
        with self._av_seq_lock:
            seq_to_use = self._av_seq
            self._av_seq += 1
            
        struct.pack_into("<H", av_header, 4, seq_to_use)
        # magic2 - verified as 00 00 in working trace responses
        av_header[6:8] = b'\x00\x00'
        # Channel flags: 00 70 XX 00 where XX tracks write phase
        av_header[8:12] = struct.pack("<I", 0x00007000 | ((self._write_counter & 0xFF) << 16))
        struct.pack_into("<I", av_header, 12, 1)   # action = 1
        struct.pack_into("<I", av_header, 16, inner_len)
        struct.pack_into("<I", av_header, 20, self._write_counter)
        # [24:28] = zeros (reserved)

        # IO_TYPE (4) + USER_PAYLOAD + SESSION_TOKEN (28)
        full_io_payload = struct.pack("<I", io_type) + user_payload + self._auth_token
        full_payload = bytes(av_header) + full_io_payload

        if io_type == 4354: # IOTYPE_USER_SET_NIGHT_LIGHT_ON_OFF_REQ
            # Simulation of AV stream for command acceptance
            # Pack dummies with contiguous seqs
            ts = int(time.time() * 1000) & 0xFFFFFFFF
            
            # Audio Dummy (Magic 09 00 0b 00)
            d1 = bytearray(24)
            d1[0:4] = b'\x09\x00\x0b\x00'
            struct.pack_into("<H", d1, 4, seq_to_use)
            d1[6:12] = b'\x00\x00\xff\xff\xff\xff'
            struct.pack_into("<I", d1, 12, ts)
            d1[20:24] = b'\x22\x1a\x00\x00'
            self.transport.send_session_data(bytes(d1))
            
            # Double Audio Dummy as seen in trace
            d2 = bytearray(d1)
            struct.pack_into("<H", d2, 4, seq_to_use + 1)
            self.transport.send_session_data(bytes(d2))
            
            # The actual SET command
            struct.pack_into("<H", av_header, 4, seq_to_use + 2)
            full_payload = bytes(av_header) + full_io_payload
            _LOGGER.debug(f"send_ioctrl (SET) type=0x{io_type:04x} seq={seq_to_use + 2}")
            self.transport.send_session_data(full_payload, magic=b'\x1a\x0a')
            
            # Video Dummy (Magic 0a 08 0b 00)
            d3 = bytearray(16)
            d3[0:4] = b'\x0a\x08\x0b\x00'
            struct.pack_into("<H", d3, 4, seq_to_use + 3)
            struct.pack_into("<I", d3, 8, ts + 50)
            self.transport.send_session_data(bytes(d3))
            
            with self._av_seq_lock:
                self._av_seq = seq_to_use + 4
        else:
            _LOGGER.debug(f"send_ioctrl type=0x{io_type:04x} seq={seq_to_use}")
            self.transport.send_session_data(full_payload, magic=b'\x1a\x0a')

        self._write_counter += 1
        return 0

    def recv_ioctrl(self, expected_type: int = 0,
                    timeout: float = 5.0,
                    expected_msg_id: int = None) -> Tuple[int, bytes]:
        """
        Receive an IOCtrl response.
        Optimized with batch-receive to withstand camera floods.
        If expected_msg_id is provided, verifies it matches the first 4 bytes of payload.
        """
        start = time.time()
        pkt_idx = 0
        while time.time() - start < timeout:
            # Check for data with a tiny wait if the buffer is empty
            res = self.transport.recv_session_data(timeout=0.01, suppress_ack=True)
            if not res:
                continue

            # SLURP MODE: Once we find data, process ALL available packets 
            # currently waiting in the OS kernel buffer in a single transaction.
            batch_pkts = [res]
            slurp_start = time.time()
            try:
                # Limit slurp to 100ms per batch to prevent death loops
                while time.time() - slurp_start < 0.1 and len(batch_pkts) < 500:
                    nxt = self.transport.recv_session_data(timeout=0.0, suppress_ack=True)
                    if not nxt:
                        break
                    batch_pkts.append(nxt)
            except Exception:
                pass

            for msg_type, decoded in batch_pkts:
                pkt_idx += 1
                if msg_type != b'\x1d\x0a' or len(decoded) < 60:
                    continue

                # Skip the 28-byte session header to get to the AV payload
                data = decoded[28:]
                if data[0:4] != b'\x00\x70\x0b\x00':
                    continue

                # io_type is at offset 28 into the AV payload
                io_type = struct.unpack("<I", data[28:32])[0]
                user_payload = data[32:]

                if expected_type == 0 or io_type == expected_type:
                    # If msg_id verification is requested, check first 4 bytes of payload
                    if expected_msg_id is not None and len(user_payload) >= 4:
                        recv_msg_id = struct.unpack("<I", user_payload[:4])[0]
                        if recv_msg_id != expected_msg_id:
                            # Stale packet from a previous command flood
                            # THROTTLED LOGGING: Only log every 50th stale packet during floods
                            if pkt_idx % 50 == 0:
                                _LOGGER.debug(
                                    f"recv_ioctrl [{pkt_idx}] SKIP stale type=0x{io_type:04x} "
                                    f"id={recv_msg_id} (want {expected_msg_id})"
                                )
                            continue

                    _LOGGER.debug(f"recv_ioctrl type=0x{io_type:04x} FOUND at idx {pkt_idx}")
                    # Send a single ACK for the packet we actually wanted
                    recv_seq = struct.unpack('<H', decoded[6:8])[0]
                    self.transport._send_session_ack(recv_seq)
                    return io_type, user_payload
                else:
                    # Log unusual packets occasionally
                    if pkt_idx % 100 == 0 or (io_type != 0x1101 and pkt_idx % 50 == 0):
                        _LOGGER.debug(
                            f"recv_ioctrl [{pkt_idx}] SKIP io=0x{io_type:04x} "
                            f"(want 0x{expected_type:04x})"
                        )

        raise TutkTimeoutError(
            f"IOCtrl response timeout after {pkt_idx} pkts (expected 0x{expected_type:04x})"
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

    def connect(self, timeout: float = 10.0, ip: Optional[str] = None) -> bool:
        """Discover device on LAN (or use direct IP), establish session, authenticate."""
        if self.transport and self.transport._connected:
            return True

        if ip:
            _LOGGER.info(f"Connecting to {self.uid} at {ip} (direct)...")
            punch_out = b"" # No punch_out needed for direct LAN
            port = TUTK_DEVICE_PORT
        else:
            _LOGGER.info(f"Connecting to {self.uid} (discovery)...")
            res = self.transport.discover_lan_device(
                self.license_id, timeout=min(10.0, timeout)
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

    def _get_msg_id(self) -> int:
        now = int(time.time())
        if not hasattr(self, "_last_msg_id"):
            self._last_msg_id = now
        elif now <= self._last_msg_id:
            self._last_msg_id += 1
        else:
            self._last_msg_id = now
        return self._last_msg_id

    def get_night_light_status(self) -> bool:
        """
        Fetch the current status of the night light.
        """
        if not self.av_channel:
            return False
            
        # OPTIMISTIC CACHING: If we just set the state recently, rely on that cache
        # during the 'Long-Tail Flood' window (approx 15 seconds).
        now = time.time()
        if now - self.transport._last_set_time < 15.0:
            _LOGGER.debug("Using optimistic nightlight state during flood window")
            return self.transport._last_set_state

        try:
            # Suppress background traffic during GET exchange
            self.transport._keepalive_paused = True
            
            # Clear any stale status flood packets
            self.transport.drain(max_duration=1.0)
            
            msg_id = int(time.time())
            payload = struct.pack("<ii", msg_id, 0x1a221a22)
            
            self.av_channel.send_ioctrl(
                IOTYPE_USER_GET_NIGHT_LIGHT_ON_OFF_REQ, payload
            )
            
            io_type, resp = self.av_channel.recv_ioctrl(
                IOTYPE_USER_GET_NIGHT_LIGHT_ON_OFF_RESP,
                timeout=5.0,
                expected_msg_id=msg_id
            )
            
            if len(resp) >= 12:
                resp_msg_id, result, on_off = struct.unpack("<iii", resp[:12])
                _LOGGER.info(
                    f"Night light: msg_id={resp_msg_id} result={result} on_off={on_off}"
                )
                self.transport._last_set_state = (on_off == 1)
                return self.transport._last_set_state
        except Exception as e:
            _LOGGER.error(f"Error getting nightlight: {e}")
        finally:
            self.transport._keepalive_paused = False
            
        # Return last known good state if we failed to fetch it
        return self.transport._last_set_state

    def set_night_light_status(self, state: bool) -> bool:
        """
        Set the night light on or off.
        """
        if not self.av_channel:
            return False
        
        # Every command needs a unique message ID (epoch timestamp)
        msg_id = int(time.time())
        on_off = 1 if state else 0
        payload = struct.pack("<iii", msg_id, on_off, 0)
        
        try:
            # Silence background keepalives during SET attempt
            self.transport._keepalive_paused = True
            
            for attempt in range(1, 4):
                _LOGGER.info(f"Setting night light to {'ON' if state else 'OFF'} (attempt {attempt})...")
                
                # Clear stale status packets before sending
                self.transport.drain()
                
                self.av_channel.send_ioctrl(
                    IOTYPE_USER_SET_NIGHT_LIGHT_ON_OFF_REQ, payload
                )
                
                try:
                    # Wait for 0x1103 confirmation from THIS SPECIFIC message ID
                    self.av_channel.recv_ioctrl(
                        IOTYPE_USER_SET_NIGHT_LIGHT_ON_OFF_RESP, 
                        timeout=5.0,
                        expected_msg_id=msg_id
                    )
                    _LOGGER.info(f"SET confirmation (0x1103) received on attempt {attempt}")
                    
                    # Store optimistic state
                    self.transport._last_set_time = time.time()
                    self.transport._last_set_state = state
                    
                    # If we got the 0x1103, we are OPTIMISTIC. 
                    # We briefly try a GET to update state, but don't fail if GET floods out.
                    try:
                        # Settling delay followed by simple draining
                        time.sleep(1.0)
                        self.transport.drain()
                        
                        # Generate a fresh msg_id for the verification GET
                        v_msg_id = int(time.time())
                        v_payload = struct.pack("<ii", v_msg_id, 0x1a221a22)
                        
                        self.av_channel.send_ioctrl(
                            IOTYPE_USER_GET_NIGHT_LIGHT_ON_OFF_REQ, v_payload
                        )
                        # Use a standard timeout for verification GET
                        self.av_channel.recv_ioctrl(
                            IOTYPE_USER_GET_NIGHT_LIGHT_ON_OFF_RESP, 
                            timeout=5.0,
                            expected_msg_id=v_msg_id
                        )
                    except Exception:
                        _LOGGER.debug("SET confirmed, but verification flood is still settling. Trusting cache.")
                    
                    return True
                except TutkTimeoutError:
                    if attempt < 3:
                        _LOGGER.warning(f"No SET response on attempt {attempt}, retrying...")
                        time.sleep(1.0)
                        continue
                    else:
                        _LOGGER.error("No SET response received after 3 attempts")
                        return False
        except Exception as e:
            _LOGGER.error(f"Error setting nightlight: {e}")
        finally:
            self.transport._keepalive_paused = False
        return False

    def disconnect(self):
        """Disconnect and clean up all threads."""
        _LOGGER.info("Disconnecting")
        if self.av_channel:
            self.av_channel._stop_keepalive()
            self.av_channel = None
        self.transport.close()
