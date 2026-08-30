"""
Dynamic Network-Field Manipulation System
All packet fields vary independently on each evaluation
Crafts real packets with randomized fields (except destination IP/port)
Supports both Layer 2 (Ethernet) and Layer 3 (IP-only) sending
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


def get_interface_info() -> Dict[str, Any]:
    """Get network interface information"""
    info = {
        'interface': None,
        'mac': None
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
# Volatile Packet - ALL fields randomize on each evaluation
# ============================================================================

class VolatilePacket:
    """
    A packet where ALL fields change on every evaluation
    Only destination IP and port are fixed (user provided)
    Source MAC is real (for proper sending)
    Supports both Layer 2 and Layer 3 sending modes
    """
    
    def __init__(self, dest_ip: str, dest_port: int, use_layer2: bool = True):
        # Store fixed destination
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.use_layer2 = use_layer2
        
        # Get network info for source MAC
        self.net_info = get_interface_info()
        self.local_ip = get_local_ip()
        
        # ============================================================
        # VOLATILE FIELDS - These change on EVERY evaluation!
        # Each field uses a random generator for independent variation
        # ============================================================
        
        # Layer 2 - Ethernet (Source MAC is real for sending)
        self.src_mac = RandMAC()  # Random source MAC
        # Destination MAC will be calculated via ARP when sending (Layer 2 mode)
        
        # Layer 3 - IP
        self.src_ip = RandIP("192.168.0.0/16")  # Random private IP
        # Dest IP is FIXED (user provided)
        self.protocol = RandChoice(6, 17, 1)  # Random: TCP, UDP, ICMP
        self.ttl = RandNum(128, 128)  # Random TTL
        self.tos = RandNum(0, 255)  # Random Type of Service
        
        # Layer 4 - Transport
        self.src_port = RandShort()  # Random source port
        # Dest port is FIXED (user provided)
        
        # TCP specific (only used when protocol is TCP)
        self.seq_num = RandInt()  # Random sequence number
        self.ack_num = RandInt()  # Random acknowledgment
        self.tcp_flags = RandChoice(0x02, 0x10, 0x18, 0x04, 0x01)  # Random flags
        
        # Payload
        self.payload_size = RandNum(10, 500)  # Random size
        self.payload = RandString(self.payload_size)  # Random text
        self.binary_payload = RandBin(RandNum(0, 200))  # Random binary
        
        # Options and identifiers
        self.identifier = RandInt()  # Random identifier
        self.session_id = RandUUID()  # Random UUID
        self.timestamp = RandInt()  # Random timestamp (can be overridden)
        self.sequence = RandLong()  # Random sequence-like field
        
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
        """Build ICMP packet (for when protocol is ICMP)"""
        icmp_type = RandChoice(8, 0, 3, 11)._fix()  # Random ICMP type
        icmp_code = RandNum(0, 15)._fix()
        icmp_id = RandShort()._fix()
        icmp_seq = RandShort()._fix()
        
        payload = self.build_payload()
        
        # ICMP header (without checksum)
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
        
        # TCP header
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, ack,
            0x50, flags, 65535, 0, 0
        )
        
        # Calculate checksum
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
        
        # Calculate checksum
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
        else:  # mixed
            text = self._fix_field(self.payload).encode('utf-8', errors='ignore')
            binary = self._fix_field(self.binary_payload)
            data = text + binary
        
        return data[:500]  # Limit size
    
    def build_ip_packet(self) -> bytes:
        """Build IP packet with CURRENT volatile values"""
        src_ip_str = self._fix_field(self.src_ip)
        dst_ip_str = self.dest_ip
        protocol = self._fix_field(self.protocol)
        ttl = self._fix_field(self.ttl)
        tos = self._fix_field(self.tos)
        identifier = self._fix_field(self.identifier) & 0xFFFF
        
        # Build transport based on protocol
        if protocol == 1:  # ICMP
            transport_data = self.build_icmp_packet()
        elif protocol == 6:  # TCP
            transport_data = self.build_tcp_segment()
        elif protocol == 17:  # UDP
            transport_data = self.build_udp_segment()
        else:
            transport_data = self.build_payload()
        
        src_ip = struct.pack('!4B', *map(int, src_ip_str.split('.')))
        dst_ip = struct.pack('!4B', *map(int, dst_ip_str.split('.')))
        
        # IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, tos, 0,  # version, tos, length placeholder
            identifier, 0x4000,  # ID, flags
            ttl, protocol, 0,  # TTL, protocol, checksum placeholder
            src_ip, dst_ip
        )
        
        total_length = 20 + len(transport_data)
        ip_header = ip_header[:2] + struct.pack('!H', total_length) + ip_header[4:]
        
        checksum = ip_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]
        
        return ip_header + transport_data
    
    def get_current_fields(self) -> Dict[str, Any]:
        """Get ALL current field values (each call gives new random values!)"""
        proto = self._fix_field(self.protocol)
        
        return {
            # Layer 2
            'src_mac': self._fix_field(self.src_mac),
            
            # Layer 3
            'src_ip': self._fix_field(self.src_ip),
            'dst_ip': self.dest_ip,
            'protocol': proto,
            'protocol_name': get_protocol_name(proto),
            'ttl': self._fix_field(self.ttl),
            'tos': self._fix_field(self.tos),
            
            # Layer 4
            'src_port': self._fix_field(self.src_port),
            'dst_port': self.dest_port,
            
            # TCP
            'seq_num': self._fix_field(self.seq_num),
            'ack_num': self._fix_field(self.ack_num),
            'tcp_flags': self._fix_field(self.tcp_flags),
            
            # Payload
            'payload_size': self._fix_field(self.payload_size),
            'payload_preview': str(self._fix_field(self.payload))[:30],
            
            # Identifiers
            'identifier': self._fix_field(self.identifier),
            'session_id': str(self._fix_field(self.session_id))[:8],
            'timestamp': self._fix_field(self.timestamp),
            'sequence': self._fix_field(self.sequence),
            
            # Application
            'app_id': self._fix_field(self.app_id),
            'version': self._fix_field(self.version),
            'option_value': self._fix_field(self.option_value),
            'priority': self._fix_field(self.priority),
        }
    
    def send_layer2(self, count: int = 1, delay: float = 0.1) -> bool:
        """Send packets using Layer 2 (Ethernet) - for local network"""
        if os.geteuid() != 0:
            print("❌ Need root for raw sockets: sudo python3 script.py")
            return False
        
        interface = self.net_info.get('interface')
        if not interface:
            print("❌ Could not find network interface")
            return False
        
        # Get destination MAC via ARP
        dst_mac = get_dst_mac(self.dest_ip)
        
        if not dst_mac:
            print(f"⚠️  Could not find MAC for {self.dest_ip}")
            print("   Using broadcast MAC (packets may not reach destination)")
            dst_mac = "ff:ff:ff:ff:ff:ff"
        else:
            print(f"✅ Found destination MAC: {dst_mac}")
        
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((interface, 0))
        except Exception as e:
            print(f"❌ Socket error: {e}")
            return False
        
        print(f"\n📤 Sending {count} packets via Layer 2 (Ethernet):")
        print(f"   Target: {self.dest_ip}:{self.dest_port}")
        print(f"   Interface: {interface}")
        print(f"   Dest MAC: {dst_mac}")
        print("-" * 70)
        
        for i in range(count):
            fields = self.get_current_fields()
            
            # Build packet
            ip_packet = self.build_ip_packet()
            
            # Build Ethernet frame
            src_mac = self._fix_field(self.src_mac)
            src_bytes = bytes.fromhex(src_mac.replace(':', ''))
            dst_bytes = bytes.fromhex(dst_mac.replace(':', ''))
            eth_header = dst_bytes + src_bytes + struct.pack('!H', 0x0800)
            
            packet = eth_header + ip_packet
            
            print(f"\n  Packet #{i+1}:")
            print(f"    MAC:      {src_mac} -> {dst_mac}")
            print(f"    IP:       {fields['src_ip']} -> {fields['dst_ip']}")
            print(f"    Proto:    {fields['protocol_name']} ({fields['protocol']})")
            if fields['protocol'] in [6, 17]:
                print(f"    Ports:    {fields['src_port']} -> {fields['dst_port']}")
            if fields['protocol'] == 6:
                print(f"    TCP:      Seq={fields['seq_num']}, Ack={fields['ack_num']}, Flags=0x{fields['tcp_flags']:02x}")
            elif fields['protocol'] == 1:
                print(f"    ICMP:     Type=8 (Echo Request)")
            print(f"    TTL:      {fields['ttl']}")
            print(f"    ID:       {fields['identifier']}")
            print(f"    Payload:  {fields['payload_size']} bytes")
            print(f"    App:      {fields['app_id']} v{fields['version']}")
            print(f"    Priority: {fields['priority']}")
            print(f"    Session:  {fields['session_id']}")
            
            try:
                sock.send(packet)
                print(f"    ✅ Sent successfully (Layer 2)")
            except Exception as e:
                print(f"    ❌ Send failed: {e}")
            
            if i < count - 1 and delay > 0:
                time.sleep(delay)
        
        sock.close()
        return True
    
    def send_layer3(self, count: int = 1, delay: float = 0.1) -> bool:
        """Send packets using Layer 3 (IP-only) - for external/WAN traffic"""
        if os.geteuid() != 0:
            print("❌ Need root for raw sockets: sudo python3 script.py")
            return False
        
        print(f"\n📤 Sending {count} packets via Layer 3 (IP-only):")
        print(f"   Target: {self.dest_ip}:{self.dest_port}")
        print(f"   Mode:   External/WAN traffic (no Ethernet header)")
        print("-" * 70)
        
        try:
            # Create raw IP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # IP_HDRINCL tells the kernel we're providing the IP header
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except Exception as e:
            print(f"❌ Socket error: {e}")
            return False
        
        for i in range(count):
            fields = self.get_current_fields()
            
            # Build IP packet (no Ethernet header)
            ip_packet = self.build_ip_packet()
            
            print(f"\n  Packet #{i+1}:")
            print(f"    IP:       {fields['src_ip']} -> {fields['dst_ip']}")
            print(f"    Proto:    {fields['protocol_name']} ({fields['protocol']})")
            if fields['protocol'] in [6, 17]:
                print(f"    Ports:    {fields['src_port']} -> {fields['dst_port']}")
            if fields['protocol'] == 6:
                print(f"    TCP:      Seq={fields['seq_num']}, Ack={fields['ack_num']}, Flags=0x{fields['tcp_flags']:02x}")
            elif fields['protocol'] == 1:
                print(f"    ICMP:     Type=8 (Echo Request)")
            print(f"    TTL:      {fields['ttl']}")
            print(f"    ID:       {fields['identifier']}")
            print(f"    Payload:  {fields['payload_size']} bytes")
            print(f"    App:      {fields['app_id']} v{fields['version']}")
            print(f"    Priority: {fields['priority']}")
            print(f"    Session:  {fields['session_id']}")
            
            try:
                # Send IP packet directly (kernel adds Ethernet header)
                sock.sendto(ip_packet, (self.dest_ip, 0))
                print(f"    ✅ Sent successfully (Layer 3 - IP-only)")
            except Exception as e:
                print(f"    ❌ Send failed: {e}")
            
            if i < count - 1 and delay > 0:
                time.sleep(delay)
        
        sock.close()
        return True
    
    def send(self, count: int = 1, delay: float = 0.1) -> bool:
        """Send packets based on selected mode (Layer 2 or Layer 3)"""
        if self.use_layer2:
            return self.send_layer2(count, delay)
        else:
            return self.send_layer3(count, delay)


# ============================================================================
# DEMONSTRATION - Shows randomization in action
# ============================================================================

def demo_randomization():
    """Show how fields CHANGE on every evaluation"""
    
    print("=" * 70)
    print("DYNAMIC NETWORK-FIELD MANIPULATION")
    print("All fields vary independently on each evaluation")
    print("=" * 70)
    
    # Create packet with fixed destination
    packet = VolatilePacket(dest_ip="8.8.8.8", dest_port=80, use_layer2=True)
    
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
        print("   Packets will have destination MAC via ARP")
    else:
        print("\n✅ Layer 3 mode selected - IP-only packets")
        print("   No Ethernet headers - kernel handles MAC resolution")
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
    
    print(f"\n🎯 Target: {dest_ip}:{dest_port}")
    print(f"📦 Packets: {count}")
    print(f"🔧 Mode: {'Layer 2 (Ethernet)' if use_layer2 else 'Layer 3 (IP-only)'}")
    print("\n📋 Fixed fields (user provided):")
    print(f"   • Destination IP:  {dest_ip}")
    print(f"   • Destination Port: {dest_port}")
    print("\n📋 Volatile fields (change on every packet):")
    print("   • Source IP, Source Port, MAC, Protocol, TTL, TOS")
    print("   • Sequence numbers, ACK numbers, TCP flags")
    print("   • Payload size, Payload content, Identifiers")
    print("   • Session IDs, Application IDs, Versions")
    print("   • Priority, Option values, Timestamps")
    
    if os.geteuid() == 0:
        choice = input("\nSend packets with RANDOMIZED fields? (y/N): ")
        if choice.lower() == 'y':
            packet = VolatilePacket(dest_ip=dest_ip, dest_port=dest_port, use_layer2=use_layer2)
            packet.send(count=count)
        else:
            print("\n📊 Demo mode - no packets sent")
    else:
        print("\n❌ Need root privileges to send packets!")
        print("   Run with: sudo python3 script.py")
        print("\n📊 Demo mode - randomization shown above")
    
    print("\n" + "=" * 70)
    print("✅ COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    random.seed(time.time())
    main()
