"""
Dynamic Network-Field Manipulation System
All packet fields vary independently on each evaluation
Crafts real packets with randomized fields (except destination IP/port)
Supports both Layer 2 (Ethernet) and Layer 3 (IP-only) sending
Option to use real IP for receiving responses
"""

import random
import time
import struct
import uuid
import string
import socket
import os
import subprocess
import re
import select
import threading
from typing import Any, Dict, List, Optional, Tuple, Union, TypeVar, Generic, Set, Callable

# ============================================================================
# Core Volatile Infrastructure
# ============================================================================

T = TypeVar('T')

class VolatileValue(Generic[T]):
    """Base class for values that change on each evaluation"""
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"
    
    def _fix(self) -> T:
        raise NotImplementedError
    
    def __str__(self) -> str:
        return str(self._fix())
    
    def __bytes__(self) -> bytes:
        return bytes(str(self._fix()), 'utf-8')
    
    def __eq__(self, other: Any) -> bool:
        return self._fix() == other
    
    def __getattr__(self, attr: str) -> Any:
        return getattr(self._fix(), attr)


# ============================================================================
# Random Generators (The Volatile Fields)
# ============================================================================

class RandNum(VolatileValue[int]):
    """Random integer in range [min, max]"""
    
    def __init__(self, min_val: int = 0, max_val: int = 100):
        self.min = min_val
        self.max = max_val
    
    def _fix(self) -> int:
        return random.randint(self.min, self.max)
    
    def __int__(self) -> int:
        return self._fix()
    
    def __and__(self, other: int) -> int:
        return self._fix() & other
    
    def __or__(self, other: int) -> int:
        return self._fix() | other
    
    def __xor__(self, other: int) -> int:
        return self._fix() ^ other


class RandFloat(VolatileValue[float]):
    """Random float in range [min, max]"""
    
    def __init__(self, min_val: float = 0.0, max_val: float = 1.0):
        self.min = min_val
        self.max = max_val
    
    def _fix(self) -> float:
        return random.uniform(self.min, self.max)
    
    def __float__(self) -> float:
        return self._fix()


class RandByte(VolatileValue[int]):
    """Random byte (0-255)"""
    
    def _fix(self) -> int:
        return random.randint(0, 255)
    
    def __int__(self) -> int:
        return self._fix()


class RandShort(VolatileValue[int]):
    """Random unsigned short (0-65535)"""
    
    def _fix(self) -> int:
        return random.randint(0, 65535)
    
    def __int__(self) -> int:
        return self._fix()


class RandInt(VolatileValue[int]):
    """Random unsigned int (0-4294967295)"""
    
    def _fix(self) -> int:
        return random.randint(0, 4294967295)
    
    def __int__(self) -> int:
        return self._fix()


class RandLong(VolatileValue[int]):
    """Random unsigned long (0-18446744073709551615)"""
    
    def _fix(self) -> int:
        return random.randint(0, 18446744073709551615)
    
    def __int__(self) -> int:
        return self._fix()


class RandChoice(VolatileValue[Any]):
    """Random choice from a list of values"""
    
    def __init__(self, *choices: Any):
        if not choices:
            raise ValueError("RandChoice needs at least one choice")
        self._choices = list(choices)
    
    def _fix(self) -> Any:
        return random.choice(self._choices)
    
    def __int__(self) -> int:
        return int(self._fix())
    
    def __str__(self) -> str:
        return str(self._fix())


class RandIP(VolatileValue[str]):
    """Random IP address from a network range"""
    
    def __init__(self, network: str = "0.0.0.0/0"):
        self.network = network
        self._parse_network()
    
    def _parse_network(self):
        if '/' in self.network:
            ip_str, mask_str = self.network.split('/')
            mask = int(mask_str)
        else:
            ip_str = self.network
            mask = 32
        
        parts = ip_str.split('.')
        ip_int = 0
        for i, part in enumerate(parts):
            ip_int |= int(part) << (24 - 8 * i)
        
        if mask == 0:
            self._start = 0
            self._end = 4294967295
        else:
            mask_int = (0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF
            self._start = ip_int & mask_int
            self._end = ip_int | (~mask_int & 0xFFFFFFFF)
    
    def _fix(self) -> str:
        ip_int = random.randint(self._start, self._end)
        return ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in range(3, -1, -1))


class RandIP6(VolatileValue[str]):
    """Random IPv6 address"""
    
    def __init__(self):
        pass
    
    def _fix(self) -> str:
        parts = []
        for _ in range(8):
            parts.append(f"{random.randint(0, 65535):04x}")
        return ":".join(parts)


class RandMAC(VolatileValue[str]):
    """Random MAC address"""
    
    def __init__(self):
        pass
    
    def _fix(self) -> str:
        return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


class RandUUID(VolatileValue[uuid.UUID]):
    """Random UUID"""
    
    def __init__(self, version: int = 4):
        self.version = version
    
    def _fix(self) -> uuid.UUID:
        if self.version == 4:
            return uuid.uuid4()
        else:
            return uuid.uuid4()


class RandString(VolatileValue[str]):
    """Random string of specified length"""
    
    DEFAULT_CHARS = string.ascii_letters + string.digits + string.punctuation
    
    def __init__(self, size: Optional[int] = None, chars: str = DEFAULT_CHARS):
        if size is None:
            size = random.randint(1, 100)
        self.size = size
        self.chars = chars
    
    def _fix(self) -> str:
        size = self.size if not isinstance(self.size, VolatileValue) else self.size._fix()
        return ''.join(random.choice(self.chars) for _ in range(int(size)))


class RandBin(VolatileValue[bytes]):
    """Random binary data of specified length"""
    
    def __init__(self, size: Optional[int] = None):
        if size is None:
            size = random.randint(1, 100)
        self.size = size
    
    def _fix(self) -> bytes:
        size = self.size if not isinstance(self.size, VolatileValue) else self.size._fix()
        return bytes(random.randint(0, 255) for _ in range(int(size)))


class RandEnumKeys(VolatileValue[Any]):
    """Random key from a dictionary"""
    
    def __init__(self, enum: Dict[Any, Any]):
        self._keys = list(enum.keys())
    
    def _fix(self) -> Any:
        return random.choice(self._keys)


# ============================================================================
# Protocol Mapping
# ============================================================================

PROTOCOL_NAMES = {
    1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP',
    41: 'IPv6', 50: 'ESP', 51: 'AH', 89: 'OSPF'
}


def get_protocol_name(proto_num: int) -> str:
    return PROTOCOL_NAMES.get(proto_num, 'Unknown')


# ============================================================================
# Network Utilities
# ============================================================================

def ip_checksum(data: bytes) -> int:
    """Calculate IP checksum"""
    if len(data) % 2 != 0:
        data += b'\x00'
    
    words = struct.unpack('!' + 'H' * (len(data) // 2), data)
    checksum = sum(words)
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF


def get_local_ip() -> str:
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def get_public_ip() -> str:
    """Try to get public IP address"""
    try:
        import urllib.request
        response = urllib.request.urlopen('https://api.ipify.org', timeout=2)
        return response.read().decode('utf-8')
    except:
        return get_local_ip()


def get_interface_info() -> Dict[str, Any]:
    """Get network interface information"""
    info = {
        'interface': None,
        'mac': None,
        'local_ip': None,
        'public_ip': None
    }
    
    try:
        # Get default interface
        with open('/proc/net/route', 'r') as f:
            for line in f:
                fields = line.strip().split()
                if fields[1] == '00000000':
                    info['interface'] = fields[0]
                    break
        
        # Get MAC address
        if info['interface']:
            result = subprocess.check_output(['ip', 'link', 'show', info['interface']],
                                           stderr=subprocess.DEVNULL,
                                           text=True)
            mac_match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', 
                                result, re.I)
            if mac_match:
                info['mac'] = mac_match.group(1)
    except:
        pass
    
    info['local_ip'] = get_local_ip()
    info['public_ip'] = get_public_ip()
    
    return info


def get_dst_mac(ip: str) -> Optional[str]:
    """Get MAC address for destination IP via ARP"""
    try:
        result = subprocess.check_output(['arp', '-n', ip], 
                                       stderr=subprocess.DEVNULL,
                                       text=True)
        for line in result.split('\n'):
            if ip in line and 'ether' in line:
                mac = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', 
                              line, re.I)
                if mac:
                    return mac.group(1)
    except:
        pass
    return None


# ============================================================================
# ICMP Response Listener
# ============================================================================

class ICMPListener:
    """Listen for ICMP responses"""
    
    def __init__(self):
        self.responses = []
        self.running = False
        self.sock = None
    
    def start(self, interface: str = None):
        """Start listening for ICMP responses"""
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            if interface:
                self.sock.bind((interface, 0))
            self.running = True
            self.thread = threading.Thread(target=self._listen, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            print(f"❌ Failed to start listener: {e}")
            return False
    
    def _listen(self):
        """Listen for incoming packets"""
        while self.running:
            try:
                self.sock.settimeout(0.5)
                packet = self.sock.recv(65536)
                
                # Parse Ethernet header
                eth_type = struct.unpack('!H', packet[12:14])[0]
                
                if eth_type == 0x0800:  # IPv4
                    ip_header = packet[14:34]
                    ip_proto = ip_header[9]
                    
                    if ip_proto == 1:  # ICMP
                        icmp_offset = 14 + ((ip_header[0] & 0x0F) * 4)
                        icmp_data = packet[icmp_offset:]
                        
                        if len(icmp_data) >= 8:
                            icmp_type = icmp_data[0]
                            
                            if icmp_type == 0:  # Echo Reply
                                icmp_id = struct.unpack('!H', icmp_data[4:6])[0]
                                icmp_seq = struct.unpack('!H', icmp_data[6:8])[0]
                                src_ip = '.'.join(str(b) for b in ip_header[12:16])
                                dst_ip = '.'.join(str(b) for b in ip_header[16:20])
                                
                                self.responses.append({
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'icmp_id': icmp_id,
                                    'icmp_seq': icmp_seq,
                                    'time': time.time(),
                                    'size': len(packet)
                                })
            except socket.timeout:
                continue
            except:
                continue
    
    def get_responses(self, timeout: float = 2.0) -> List[Dict]:
        """Get responses within timeout"""
        time.sleep(timeout)
        responses = self.responses.copy()
        self.responses.clear()
        return responses
    
    def stop(self):
        """Stop listening"""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass


# ============================================================================
# Fixed Packet (Non-Randomized) - Uses real IPs
# ============================================================================

class FixedPacket:
    """
    A packet with FIXED (non-random) fields
    Uses real IP, real MAC, fixed ports, etc.
    Used when user selects 'N' for randomized fields
    """
    
    def __init__(self, dest_ip: str, dest_port: int, use_layer2: bool = True):
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.use_layer2 = use_layer2
        
        # Get network info
        self.net_info = get_interface_info()
        self.local_ip = self.net_info.get('local_ip', '127.0.0.1')
        self.local_mac = self.net_info.get('mac', '00:00:00:00:00:00')
        
        # Fixed fields (non-random)
        self.src_ip = self.local_ip
        self.src_mac = self.local_mac
        self.protocol = 1  # ICMP (fixed)
        self.ttl = 64
        self.tos = 0
        self.src_port = 0  # Not used for ICMP
        self.seq_num = 0
        self.ack_num = 0
        self.tcp_flags = 0
        self.payload_size = 32
        self.payload = "PING" * 8
        self.identifier = 0x1234
        self.session_id = "FIXED"
        self.timestamp = int(time.time())
        self.sequence = 0
    
    def build_icmp_packet(self) -> bytes:
        """Build ICMP echo request"""
        icmp_type = 8  # Echo Request
        icmp_code = 0
        icmp_id = 0x1234
        icmp_seq = 0
        
        payload = self.payload.encode('utf-8')
        
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
        icmp_data = icmp_header + payload
        checksum = ip_checksum(icmp_data)
        icmp_header = struct.pack('!BBH', icmp_type, icmp_code, checksum)
        icmp_header += struct.pack('!HH', icmp_id, icmp_seq)
        
        return icmp_header + payload
    
    def build_ip_packet(self) -> bytes:
        """Build IP packet with fixed fields"""
        src_ip = struct.pack('!4B', *map(int, self.src_ip.split('.')))
        dst_ip = struct.pack('!4B', *map(int, self.dest_ip.split('.')))
        
        transport_data = self.build_icmp_packet()
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, self.tos, 0,
            self.identifier, 0x4000,
            self.ttl, self.protocol, 0,
            src_ip, dst_ip
        )
        
        total_length = 20 + len(transport_data)
        ip_header = ip_header[:2] + struct.pack('!H', total_length) + ip_header[4:]
        
        checksum = ip_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]
        
        return ip_header + transport_data
    
    def get_current_fields(self) -> Dict[str, Any]:
        """Get fixed field values"""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dest_ip,
            'protocol': self.protocol,
            'protocol_name': 'ICMP',
            'ttl': self.ttl,
            'tos': self.tos,
            'src_port': 'N/A',
            'dst_port': self.dest_port,
            'seq_num': 'N/A',
            'ack_num': 'N/A',
            'tcp_flags': 'N/A',
            'payload_size': len(self.payload),
            'payload_preview': self.payload[:30],
            'identifier': self.identifier,
            'session_id': self.session_id,
            'timestamp': self.timestamp,
            'sequence': self.sequence,
            'app_id': 'PING',
            'version': '1.0',
            'option_value': 'default',
            'priority': 0,
        }
    
    def send_with_response_check(self, count: int = 3, timeout: float = 2.0) -> bool:
        """Send fixed packets and check for responses"""
        if self.use_layer2:
            return self._send_layer2_with_response(count, timeout)
        else:
            return self._send_layer3_with_response(count, timeout)
    
    def _send_layer3_with_response(self, count: int, timeout: float) -> bool:
        """Send Layer 3 fixed packets and listen for responses"""
        if os.geteuid() != 0:
            print("❌ Need root for raw sockets: sudo python3 script.py")
            return False
        
        interface = self.net_info.get('interface')
        if not interface:
            print("❌ Could not find network interface")
            return False
        
        # Start ICMP listener
        listener = ICMPListener()
        listener.start(interface)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except Exception as e:
            print(f"❌ Socket error: {e}")
            listener.stop()
            return False
        
        print(f"\n📤 Sending {count} FIXED (non-randomized) packets:")
        print(f"   Target: {self.dest_ip}")
        print(f"   Mode: Layer 3 (IP-only)")
        print(f"   Source IP: {self.src_ip} (REAL IP)")
        print("   Fields are FIXED - no randomization")
        print("-" * 70)
        
        for i in range(count):
            fields = self.get_current_fields()
            ip_packet = self.build_ip_packet()
            
            print(f"\n  Packet #{i+1}:")
            print(f"    IP:       {fields['src_ip']} -> {fields['dst_ip']}")
            print(f"    Proto:    ICMP (Echo Request)")
            print(f"    TTL:      {fields['ttl']}")
            print(f"    ID:       {fields['identifier']}")
            print(f"    Payload:  {fields['payload_size']} bytes")
            
            try:
                sock.sendto(ip_packet, (self.dest_ip, 0))
                print(f"    ✅ Sent")
            except Exception as e:
                print(f"    ❌ Send failed: {e}")
            
            if i < count - 1:
                time.sleep(0.1)
        
        sock.close()
        
        # Wait for responses
        print(f"\n⏳ Waiting {timeout}s for responses...")
        responses = listener.get_responses(timeout)
        listener.stop()
        
        # Show responses
        print("\n" + "-" * 70)
        print("📥 RESPONSES RECEIVED:")
        print("-" * 70)
        
        if responses:
            for resp in responses:
                print(f"\n  ✓ Response received:")
                print(f"    From:      {resp['src_ip']}")
                print(f"    To:        {resp['dst_ip']}")
                print(f"    ICMP ID:   {resp['icmp_id']}")
                print(f"    ICMP Seq:  {resp['icmp_seq']}")
                print(f"    Size:      {resp['size']} bytes")
                print(f"    ✅ PACKET REACHED DESTINATION!")
            
            print(f"\n  ✅ Successfully received {len(responses)} responses!")
            print(f"  Packets successfully reached the destination!")
        else:
            print("\n  ❌ No responses received!")
            print("  Possible reasons:")
            print("    • Target is not reachable")
            print("    • Firewall is blocking ICMP")
            print("    • Target doesn't respond to ICMP")
        
        return len(responses) > 0
    
    def _send_layer2_with_response(self, count: int, timeout: float) -> bool:
        """Send Layer 2 fixed packets and listen for responses"""
        if os.geteuid() != 0:
            print("❌ Need root for raw sockets: sudo python3 script.py")
            return False
        
        interface = self.net_info.get('interface')
        if not interface:
            print("❌ Could not find network interface")
            return False
        
        dst_mac = get_dst_mac(self.dest_ip)
        if not dst_mac:
            print(f"⚠️  Could not find MAC for {self.dest_ip}")
            dst_mac = "ff:ff:ff:ff:ff:ff"
        
        # Start ICMP listener
        listener = ICMPListener()
        listener.start(interface)
        
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((interface, 0))
        except Exception as e:
            print(f"❌ Socket error: {e}")
            listener.stop()
            return False
        
        print(f"\n📤 Sending {count} FIXED (non-randomized) packets:")
        print(f"   Target: {self.dest_ip}")
        print(f"   Mode: Layer 2 (Ethernet)")
        print(f"   Source IP: {self.src_ip} (REAL IP)")
        print("   Fields are FIXED - no randomization")
        print("-" * 70)
        
        for i in range(count):
            fields = self.get_current_fields()
            ip_packet = self.build_ip_packet()
            
            src_bytes = bytes.fromhex(self.src_mac.replace(':', ''))
            dst_bytes = bytes.fromhex(dst_mac.replace(':', ''))
            eth_header = dst_bytes + src_bytes + struct.pack('!H', 0x0800)
            packet = eth_header + ip_packet
            
            print(f"\n  Packet #{i+1}:")
            print(f"    MAC:      {self.src_mac} -> {dst_mac}")
            print(f"    IP:       {fields['src_ip']} -> {fields['dst_ip']}")
            print(f"    Proto:    ICMP (Echo Request)")
            print(f"    TTL:      {fields['ttl']}")
            print(f"    ID:       {fields['identifier']}")
            print(f"    Payload:  {fields['payload_size']} bytes")
            
            try:
                sock.send(packet)
                print(f"    ✅ Sent")
            except Exception as e:
                print(f"    ❌ Send failed: {e}")
            
            if i < count - 1:
                time.sleep(0.1)
        
        sock.close()
        
        # Wait for responses
        print(f"\n⏳ Waiting {timeout}s for responses...")
        responses = listener.get_responses(timeout)
        listener.stop()
        
        # Show responses
        print("\n" + "-" * 70)
        print("📥 RESPONSES RECEIVED:")
        print("-" * 70)
        
        if responses:
            for resp in responses:
                print(f"\n  ✓ Response received:")
                print(f"    From:      {resp['src_ip']}")
                print(f"    To:        {resp['dst_ip']}")
                print(f"    ICMP ID:   {resp['icmp_id']}")
                print(f"    ICMP Seq:  {resp['icmp_seq']}")
                print(f"    Size:      {resp['size']} bytes")
                print(f"    ✅ PACKET REACHED DESTINATION!")
            
            print(f"\n  ✅ Successfully received {len(responses)} responses!")
            print(f"  Packets successfully reached the destination!")
        else:
            print("\n  ❌ No responses received!")
            print("  Possible reasons:")
            print("    • Target is not reachable")
            print("    • Firewall is blocking ICMP")
            print("    • Target doesn't respond to ICMP")
        
        return len(responses) > 0


# ============================================================================
# Volatile Packet - ALL fields randomize on each evaluation
# ============================================================================

class VolatilePacket:
    """
    A packet where ALL fields change on every evaluation
    Only destination IP and port are fixed (user provided)
    Supports both Layer 2 and Layer 3 sending modes
    """
    
    def __init__(self, dest_ip: str, dest_port: int, use_layer2: bool = True, use_real_ip: bool = False):
        # Store fixed destination
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.use_layer2 = use_layer2
        self.use_real_ip = use_real_ip
        
        # Get network info for source MAC
        self.net_info = get_interface_info()
        self.local_ip = self.net_info.get('local_ip', '127.0.0.1')
        
        # ============================================================
        # VOLATILE FIELDS - These change on EVERY evaluation!
        # Each field uses a random generator for independent variation
        # ============================================================
        
        # Layer 2 - Ethernet
        self.src_mac = RandMAC()
        
        # Layer 3 - IP
        if use_real_ip:
            self.src_ip = RandIP(f"{self.local_ip}/32")
        else:
            self.src_ip = RandIP("192.168.0.0/16")
        
        self.protocol = RandChoice(6, 17, 1)
        self.ttl = RandNum(64, 128)
        self.tos = RandNum(0, 255)
        
        # Layer 4 - Transport
        self.src_port = RandShort()
        
        # TCP specific
        self.seq_num = RandInt()
        self.ack_num = RandInt()
        self.tcp_flags = RandChoice(0x02, 0x10, 0x18, 0x04, 0x01)
        
        # Payload
        self.payload_size = RandNum(10, 500)
        self.payload = RandString(self.payload_size)
        self.binary_payload = RandBin(RandNum(0, 200))
        
        # Options and identifiers
        self.identifier = RandInt()
        self.session_id = RandUUID()
        self.timestamp = RandInt()
        self.sequence = RandLong()
        
        # Application identifiers
        self.app_id = RandChoice('HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS', 'SMTP', 'RDP')
        self.version = RandChoice('1.0', '1.1', '2.0', '3.0', '4.0')
        
        # Option values
        self.option_value = RandChoice('enabled', 'disabled', 'none', 'default')
        self.priority = RandNum(0, 7)
    
    def _fix_field(self, field: Any) -> Any:
        """Evaluate a volatile field to its current value"""
        if isinstance(field, VolatileValue):
            return field._fix()
        return field
    
    def build_icmp_packet(self) -> bytes:
        """Build ICMP packet"""
        icmp_type = RandChoice(8, 0, 3, 11)._fix()
        icmp_code = RandNum(0, 15)._fix()
        icmp_id = RandShort()._fix()
        icmp_seq = RandShort()._fix()
        
        payload = self.build_payload()
        
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
        icmp_data = icmp_header + payload
        checksum = ip_checksum(icmp_data)
        icmp_header = struct.pack('!BBH', icmp_type, icmp_code, checksum)
        icmp_header += struct.pack('!HH', icmp_id, icmp_seq)
        
        return icmp_header + payload
    
    def build_tcp_segment(self) -> bytes:
        """Build TCP segment"""
        src_port = self._fix_field(self.src_port)
        dst_port = self.dest_port
        seq = self._fix_field(self.seq_num)
        ack = self._fix_field(self.ack_num)
        flags = self._fix_field(self.tcp_flags)
        payload = self.build_payload()
        
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, ack,
            0x50, flags, 65535, 0, 0
        )
        
        src_ip_str = self._fix_field(self.src_ip)
        dst_ip_str = self.dest_ip
        src_ip = struct.pack('!4B', *map(int, src_ip_str.split('.')))
        dst_ip = struct.pack('!4B', *map(int, dst_ip_str.split('.')))
        
        pseudo_header = struct.pack('!4s4sBBH',
            src_ip, dst_ip, 0, 6,
            len(tcp_header) + len(payload)
        )
        
        checksum_data = pseudo_header + tcp_header + payload
        if len(checksum_data) % 2 != 0:
            checksum_data += b'\x00'
        
        checksum = ip_checksum(checksum_data)
        tcp_header = tcp_header[:16] + struct.pack('!H', checksum) + tcp_header[18:]
        
        return tcp_header + payload
    
    def build_udp_segment(self) -> bytes:
        """Build UDP segment"""
        src_port = self._fix_field(self.src_port)
        dst_port = self.dest_port
        payload = self.build_payload()
        length = 8 + len(payload)
        
        udp_header = struct.pack('!HHHH', src_port, dst_port, length, 0)
        
        src_ip_str = self._fix_field(self.src_ip)
        dst_ip_str = self.dest_ip
        src_ip = struct.pack('!4B', *map(int, src_ip_str.split('.')))
        dst_ip = struct.pack('!4B', *map(int, dst_ip_str.split('.')))
        
        pseudo_header = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, 17, length)
        checksum_data = pseudo_header + udp_header + payload
        if len(checksum_data) % 2 != 0:
            checksum_data += b'\x00'
        
        checksum = ip_checksum(checksum_data)
        udp_header = udp_header[:6] + struct.pack('!H', checksum)
        
        return udp_header + payload
    
    def build_payload(self) -> bytes:
        """Build packet payload"""
        payload_type = RandChoice('text', 'binary', 'mixed')._fix()
        
        if payload_type == 'text':
            data = self._fix_field(self.payload).encode('utf-8', errors='ignore')
        elif payload_type == 'binary':
            data = self._fix_field(self.binary_payload)
        else:
            text = self._fix_field(self.payload).encode('utf-8', errors='ignore')
            binary = self._fix_field(self.binary_payload)
            data = text + binary
        
        return data[:500]
    
    def build_ip_packet(self) -> bytes:
        """Build IP packet with CURRENT volatile values"""
        src_ip_str = self._fix_field(self.src_ip)
        dst_ip_str = self.dest_ip
        protocol = self._fix_field(self.protocol)
        ttl = self._fix_field(self.ttl)
        tos = self._fix_field(self.tos)
        identifier = self._fix_field(self.identifier) & 0xFFFF
        
        if protocol == 1:
            transport_data = self.build_icmp_packet()
        elif protocol == 6:
            transport_data = self.build_tcp_segment()
        elif protocol == 17:
            transport_data = self.build_udp_segment()
        else:
            transport_data = self.build_payload()
        
        src_ip = struct.pack('!4B', *map(int, src_ip_str.split('.')))
        dst_ip = struct.pack('!4B', *map(int, dst_ip_str.split('.')))
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, tos, 0,
            identifier, 0x4000,
            ttl, protocol, 0,
            src_ip, dst_ip
        )
        
        total_length = 20 + len(transport_data)
        ip_header = ip_header[:2] + struct.pack('!H', total_length) + ip_header[4:]
        
        checksum = ip_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]
        
        return ip_header + transport_data
    
    def get_current_fields(self) -> Dict[str, Any]:
        """Get ALL current field values"""
        proto = self._fix_field(self.protocol)
        
        return {
            'src_ip': self._fix_field(self.src_ip),
            'dst_ip': self.dest_ip,
            'protocol': proto,
            'protocol_name': get_protocol_name(proto),
            'ttl': self._fix_field(self.ttl),
            'tos': self._fix_field(self.tos),
            'src_port': self._fix_field(self.src_port),
            'dst_port': self.dest_port,
            'seq_num': self._fix_field(self.seq_num),
            'ack_num': self._fix_field(self.ack_num),
            'tcp_flags': self._fix_field(self.tcp_flags),
            'payload_size': self._fix_field(self.payload_size),
            'payload_preview': str(self._fix_field(self.payload))[:30],
            'identifier': self._fix_field(self.identifier),
            'session_id': str(self._fix_field(self.session_id))[:8],
            'timestamp': self._fix_field(self.timestamp),
            'sequence': self._fix_field(self.sequence),
            'app_id': self._fix_field(self.app_id),
            'version': self._fix_field(self.version),
            'option_value': self._fix_field(self.option_value),
            'priority': self._fix_field(self.priority),
        }
    
    def send_with_response_check(self, count: int = 3, timeout: float = 2.0) -> bool:
        """Send packets and check for responses"""
        if self.use_layer2:
            return self._send_layer2_with_response(count, timeout)
        else:
            return self._send_layer3_with_response(count, timeout)
    
    def _send_layer3_with_response(self, count: int, timeout: float) -> bool:
        """Send Layer 3 packets and listen for responses"""
        if os.geteuid() != 0:
            print("❌ Need root for raw sockets: sudo python3 script.py")
            return False
        
        interface = self.net_info.get('interface')
        if not interface:
            print("❌ Could not find network interface")
            return False
        
        # Start ICMP listener
        listener = ICMPListener()
        listener.start(interface)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except Exception as e:
            print(f"❌ Socket error: {e}")
            listener.stop()
            return False
        
        print(f"\n📤 Sending {count} RANDOMIZED packets:")
        print(f"   Target: {self.dest_ip}")
        print(f"   Mode: Layer 3 (IP-only)")
        print(f"   Source IP: {'REAL IP (will get responses)' if self.use_real_ip else 'RANDOM IP (no responses)'}")
        print("   Fields change on EVERY packet!")
        print("-" * 70)
        
        for i in range(count):
            fields = self.get_current_fields()
            ip_packet = self.build_ip_packet()
            
            print(f"\n  Packet #{i+1}:")
            print(f"    IP:       {fields['src_ip']} -> {fields['dst_ip']}")
            print(f"    Proto:    {fields['protocol_name']} ({fields['protocol']})")
            if fields['protocol'] == 1:
                print(f"    ICMP:     Echo Request")
            elif fields['protocol'] in [6, 17]:
                print(f"    Ports:    {fields['src_port']} -> {fields['dst_port']}")
            print(f"    TTL:      {fields['ttl']}")
            print(f"    ID:       {fields['identifier']}")
            print(f"    Payload:  {fields['payload_size']} bytes")
            print(f"    App:      {fields['app_id']} v{fields['version']}")
            
            try:
                sock.sendto(ip_packet, (self.dest_ip, 0))
                print(f"    ✅ Sent")
            except Exception as e:
                print(f"    ❌ Send failed: {e}")
            
            if i < count - 1:
                time.sleep(0.1)
        
        sock.close()
        
        # Wait for responses
        print(f"\n⏳ Waiting {timeout}s for responses...")
        responses = listener.get_responses(timeout)
        listener.stop()
        
        # Show responses
        print("\n" + "-" * 70)
        print("📥 RESPONSES RECEIVED:")
        print("-" * 70)
        
        if responses:
            for resp in responses:
                print(f"\n  ✓ Response received:")
                print(f"    From:      {resp['src_ip']}")
                print(f"    To:        {resp['dst_ip']}")
                print(f"    ICMP ID:   {resp['icmp_id']}")
                print(f"    ICMP Seq:  {resp['icmp_seq']}")
                print(f"    Size:      {resp['size']} bytes")
                print(f"    ✅ PACKET REACHED DESTINATION!")
            
            print(f"\n  ✅ Successfully received {len(responses)} responses!")
            print(f"  Packets successfully reached the destination!")
        else:
            print("\n  ❌ No responses received!")
            print("  Possible reasons:")
            print("    • Target is not reachable")
            print("    • Firewall is blocking packets")
            print("    • Target doesn't respond to this protocol")
            if not self.use_real_ip:
                print("    • Using random IP (try 'y' for real IP)")
        
        return len(responses) > 0
    
    def _send_layer2_with_response(self, count: int, timeout: float) -> bool:
        """Send Layer 2 packets and listen for responses"""
        if os.geteuid() != 0:
            print("❌ Need root for raw sockets: sudo python3 script.py")
            return False
        
        interface = self.net_info.get('interface')
        if not interface:
            print("❌ Could not find network interface")
            return False
        
        dst_mac = get_dst_mac(self.dest_ip)
        if not dst_mac:
            print(f"⚠️  Could not find MAC for {self.dest_ip}")
            dst_mac = "ff:ff:ff:ff:ff:ff"
        
        # Start ICMP listener
        listener = ICMPListener()
        listener.start(interface)
        
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((interface, 0))
        except Exception as e:
            print(f"❌ Socket error: {e}")
            listener.stop()
            return False
        
        print(f"\n📤 Sending {count} RANDOMIZED packets:")
        print(f"   Target: {self.dest_ip}")
        print(f"   Mode: Layer 2 (Ethernet)")
        print(f"   Source IP: {'REAL IP (will get responses)' if self.use_real_ip else 'RANDOM IP (no responses)'}")
        print("   Fields change on EVERY packet!")
        print("-" * 70)
        
        for i in range(count):
            fields = self.get_current_fields()
            ip_packet = self.build_ip_packet()
            
            src_mac = self._fix_field(self.src_mac)
            src_bytes = bytes.fromhex(src_mac.replace(':', ''))
            dst_bytes = bytes.fromhex(dst_mac.replace(':', ''))
            eth_header = dst_bytes + src_bytes + struct.pack('!H', 0x0800)
            packet = eth_header + ip_packet
            
            print(f"\n  Packet #{i+1}:")
            print(f"    MAC:      {src_mac} -> {dst_mac}")
            print(f"    IP:       {fields['src_ip']} -> {fields['dst_ip']}")
            print(f"    Proto:    {fields['protocol_name']} ({fields['protocol']})")
            if fields['protocol'] == 1:
                print(f"    ICMP:     Echo Request")
            elif fields['protocol'] in [6, 17]:
                print(f"    Ports:    {fields['src_port']} -> {fields['dst_port']}")
            print(f"    TTL:      {fields['ttl']}")
            print(f"    ID:       {fields['identifier']}")
            print(f"    Payload:  {fields['payload_size']} bytes")
            print(f"    App:      {fields['app_id']} v{fields['version']}")
            
            try:
                sock.send(packet)
                print(f"    ✅ Sent")
            except Exception as e:
                print(f"    ❌ Send failed: {e}")
            
            if i < count - 1:
                time.sleep(0.1)
        
        sock.close()
        
        # Wait for responses
        print(f"\n⏳ Waiting {timeout}s for responses...")
        responses = listener.get_responses(timeout)
        listener.stop()
        
        # Show responses
        print("\n" + "-" * 70)
        print("📥 RESPONSES RECEIVED:")
        print("-" * 70)
        
        if responses:
            for resp in responses:
                print(f"\n  ✓ Response received:")
                print(f"    From:      {resp['src_ip']}")
                print(f"    To:        {resp['dst_ip']}")
                print(f"    ICMP ID:   {resp['icmp_id']}")
                print(f"    ICMP Seq:  {resp['icmp_seq']}")
                print(f"    Size:      {resp['size']} bytes")
                print(f"    ✅ PACKET REACHED DESTINATION!")
            
            print(f"\n  ✅ Successfully received {len(responses)} responses!")
            print(f"  Packets successfully reached the destination!")
        else:
            print("\n  ❌ No responses received!")
            print("  Possible reasons:")
            print("    • Target is not reachable")
            print("    • Firewall is blocking packets")
            print("    • Target doesn't respond to this protocol")
            if not self.use_real_ip:
                print("    • Using random IP (try 'y' for real IP)")
        
        return len(responses) > 0


# ============================================================================
# DEMONSTRATION - Shows randomization in action
# ============================================================================

def demo_randomization():
    """Show how fields CHANGE on every evaluation"""
    
    print("=" * 70)
    print("DYNAMIC NETWORK-FIELD MANIPULATION")
    print("All fields vary independently on each evaluation")
    print("=" * 70)
    
    packet = VolatilePacket(dest_ip="8.8.8.8", dest_port=80, use_layer2=True, use_real_ip=False)
    
    print("\n📊 Generating 5 packets - ALL fields change on each evaluation:")
    print("-" * 70)
    
    print("\n  Field types used:")
    print("    • RandNum        - Random numbers")
    print("    • RandByte       - Random bytes")
    print("    • RandShort      - Random shorts")
    print("    • RandInt        - Random integers")
    print("    • RandLong       - Random longs")
    print("    • RandIP         - Random IP addresses")
    print("    • RandIP6        - Random IPv6 addresses")
    print("    • RandMAC        - Random MAC addresses")
    print("    • RandUUID       - Random UUIDs")
    print("    • RandString     - Random strings")
    print("    • RandBin        - Random binary data")
    print("    • RandChoice     - Random choices")
    print("    • RandEnumKeys   - Random enum keys")
    print("-" * 70)
    
    for i in range(5):
        fields = packet.get_current_fields()
        print(f"\n  Packet #{i+1}:" if i == 0 else f"\n  Packet #{i+1}:")
        print(f"    SRC IP:   {fields['src_ip']}:{fields['src_port']}")
        print(f"    DST IP:   {fields['dst_ip']}:{fields['dst_port']} (FIXED)")
        print(f"    PROTO:    {fields['protocol_name']} (ID: {fields['protocol']})")
        if fields['protocol'] == 6:
            print(f"    TCP:      Seq={fields['seq_num']}, Flags=0x{fields['tcp_flags']:02x}")
        print(f"    TTL:      {fields['ttl']}")
        print(f"    ID:       {fields['identifier']}")
        print(f"    SESSION:  {fields['session_id']}")
        print(f"    APP:      {fields['app_id']} v{fields['version']}")
        print(f"    PAYLOAD:  {fields['payload_size']} bytes")
    
    print("\n" + "=" * 70)
    print("✓ Every evaluation produces DIFFERENT values")
    print("✓ All fields are independent and volatile")
    print("✓ Destination IP and port remain FIXED (user provided)")
    print("=" * 70)


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("🌐 DYNAMIC NETWORK-FIELD MANIPULATION SYSTEM")
    print("Independent field randomization on every packet")
    print("=" * 70)
    
    # Check root
    if os.geteuid() != 0:
        print("\n⚠️  WARNING: Not running as root")
        print("   Root required for raw packet sending (sudo)")
        print("   Demo mode will show randomization without sending\n")
    
    # Show demo
    demo_randomization()
    
    # Get user input for Layer 2 mode
    print("\n" + "=" * 70)
    print("🔧 LAYER 2 (Ethernet) MODE SELECTION")
    print("=" * 70)
    print("\n  Layer 2 Mode (YES):")
    print("    • Adds Ethernet header with MAC addresses")
    print("    • Requires destination MAC (uses ARP)")
    print("    • Best for: Local network traffic")
    print("    • Example: 192.168.1.100, 10.0.0.1")
    print("\n  Layer 3 Mode (NO):")
    print("    • Sends IP packets only (no Ethernet header)")
    print("    • Kernel handles MAC address resolution")
    print("    • Best for: External/WAN traffic")
    print("    • Example: google.com, 8.8.8.8, any public IP")
    print("\n" + "-" * 70)
    
    use_layer2_input = input("\nUse Layer 2 (Ethernet) mode? (y/N): ").strip().lower()
    use_layer2 = use_layer2_input == 'y'
    
    if use_layer2:
        print("\n✅ Layer 2 mode selected - Ethernet headers will be added")
    else:
        print("\n✅ Layer 3 mode selected - IP-only packets")
        print("   Suitable for external/WAN traffic")
    
    # Get user input for destination
    print("\n" + "=" * 70)
    print("🎯 SET DESTINATION (Fixed fields)")
    print("These fields will NOT change - user provided")
    print("=" * 70)
    
    dest_ip = input("\nEnter destination IP: ").strip()
    if not dest_ip:
        dest_ip = "8.8.8.8"
    
    dest_port = input("Enter destination port (0 for ICMP): ").strip()
    if not dest_port:
        dest_port = "80"
    dest_port = int(dest_port)
    
    count = input("Number of packets to send (default: 3): ").strip()
    if not count:
        count = "3"
    count = int(count)
    
    # Ask about using real IP for responses
    print("\n" + "=" * 70)
    print("📡 RESPONSE RECEPTION MODE")
    print("=" * 70)
    print("\n  If you use REAL IP:")
    print("    • Packets will use your actual IP as source")
    print("    • Responses will come back to your machine")
    print("    • You can see if packets reached the destination")
    print("    • Best for: Testing packet delivery")
    print("\n  If you use RANDOM IP:")
    print("    • Packets will use random private IPs")
    print("    • Responses will go to the random IP (not your machine)")
    print("    • You won't see responses")
    print("    • Best for: Stealth/obfuscation")
    print("\n" + "-" * 70)
    
    use_real_ip_input = input("\nUse REAL IP to receive responses? (y/N): ").strip().lower()
    use_real_ip = use_real_ip_input == 'y'
    
    if use_real_ip:
        print(f"\n✅ Using REAL IP: {get_local_ip()}")
        print("   Responses will be received and displayed!")
    else:
        print("\n✅ Using RANDOM IP (private range)")
        print("   Responses will NOT be received")
    
    # NEW: Ask about randomization
    print("\n" + "=" * 70)
    print("🎲 RANDOMIZATION MODE")
    print("=" * 70)
    print("\n  RANDOMIZED fields (YES):")
    print("    • ALL fields change on every packet")
    print("    • Source IP, ports, TTL, payload, etc. all vary")
    print("    • Each packet is completely different")
    print("    • Best for: Testing, fuzzing, variety")
    print("\n  FIXED fields (NO):")
    print("    • Fields are fixed/non-random")
    print("    • Uses REAL IP, fixed TTL, fixed payload")
    print("    • ICMP ping with consistent values")
    print("    • Best for: Confirming packet delivery")
    print("\n" + "-" * 70)
    
    use_randomization_input = input("\nUse RANDOMIZED fields? (y/N): ").strip().lower()
    use_randomization = use_randomization_input == 'y'
    
    if use_randomization:
        print("\n✅ RANDOMIZED mode - All fields vary on each packet!")
    else:
        print("\n✅ FIXED mode - Fields are constant (ICMP ping)")
        print("   This is useful for confirming packet delivery")
    
    print(f"\n🎯 Target: {dest_ip}:{dest_port}")
    print(f"📦 Packets: {count}")
    print(f"🔧 Mode: {'Layer 2 (Ethernet)' if use_layer2 else 'Layer 3 (IP-only)'}")
    print(f"📡 Source IP: {'REAL (will get responses)' if use_real_ip else 'RANDOM (no responses)'}")
    print(f"🎲 Fields: {'RANDOMIZED' if use_randomization else 'FIXED (ICMP ping)'}")
    
    if os.geteuid() == 0:
        if use_randomization:
            packet = VolatilePacket(dest_ip=dest_ip, dest_port=dest_port, 
                                    use_layer2=use_layer2, use_real_ip=use_real_ip)
        else:
            packet = FixedPacket(dest_ip=dest_ip, dest_port=dest_port, 
                                 use_layer2=use_layer2)
        
        packet.send_with_response_check(count=count, timeout=3.0)
    else:
        print("\n❌ Need root privileges to send packets!")
        print("   Run with: sudo python3 script.py")
        print("\n📊 Demo mode - no packets sent")
    
    print("\n" + "=" * 70)
    print("✅ COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    random.seed(time.time())
    main()