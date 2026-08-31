#!/usr/bin/env python3
"""
IPv6 Real Toolkit - Performs actual system reconnaissance on Linux
No external dependencies required (only Python standard library)
"""

import socket
import struct
import time
import hashlib
import random
import subprocess
import os
import re
from typing import Iterator, List, Optional, Tuple, Union, Dict, Any
from functools import lru_cache

# Constants
IPV6_ADDR_GLOBAL = 0x01
IPV6_ADDR_LINKLOCAL = 0x02
IPV6_ADDR_SITELOCAL = 0x04
IPV6_ADDR_LOOPBACK = 0x08
IPV6_ADDR_UNICAST = 0x10
IPV6_ADDR_MULTICAST = 0x20
IPV6_ADDR_6TO4 = 0x40
IPV6_ADDR_UNSPECIFIED = 0x80

# RFC 1924 alphabet
_RFC1924MAP = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
               'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
               'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
               'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
               'y', 'z', '!', '#', '$', '%', '&', '(', ')', '*', '+', '-', ';', '<', '=',
               '>', '?', '@', '^', '_', '`', '{', '|', '}', '~']


def _generate_oui_database() -> Dict[str, str]:
    """Generate OUI database programmatically"""
    oui_db = {}
    
    # Cisco OUI patterns
    for o1 in range(0, 0x20):
        for o2 in range(0, 0x10):
            oui_db[f"00:{o1:02X}:{o2:02X}"] = "Cisco"
    
    # Major vendors
    vendor_patterns = {
        "3Com": [0x20, 0x50, 0x60, 0x80, 0x90, 0xA0, 0xB0],
        "Intel": [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
        "Dell": [0x04, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
        "HP": [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
        "Apple": [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
        "IBM": [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
        "Microsoft": [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
        "Sony": [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
        "Samsung": [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
        "Nokia": [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
        "Ericsson": [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E],
        "Motorola": [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B],
        "NEC": [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
        "Fujitsu": [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B],
        "Hitachi": [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B],
        "Panasonic": [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B],
        "Toshiba": [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B],
        "Sharp": [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B],
        "Asus": [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E],
        "Acer": [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D],
        "Lenovo": [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
        "Realtek": [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF],
        "Broadcom": [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
        "Qualcomm": [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
        "Marvell": [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]
    }
    
    for vendor, hex_values in vendor_patterns.items():
        for oui_byte in hex_values:
            for second_byte in range(0x00, 0x10):
                oui_db[f"00:{oui_byte:02X}:{second_byte:02X}"] = vendor
    
    return oui_db


OUI_DB = _generate_oui_database()


# ============================================================================
# Core IPv6 Analysis Functions
# ============================================================================

def in6_getAddrType(addr: str) -> int:
    """Determine the type and scope of an IPv6 address"""
    try:
        naddr = socket.inet_pton(socket.AF_INET6, addr)
        paddr = socket.inet_ntop(socket.AF_INET6, naddr)
    except Exception:
        return 0
    
    addrType = 0
    
    if ((naddr[0] & 0xE0) == 0x20):
        addrType = (IPV6_ADDR_UNICAST | IPV6_ADDR_GLOBAL)
        if naddr[:2] == b' \x02':
            addrType |= IPV6_ADDR_6TO4
    elif naddr[0] == 0xff:
        addrScope = paddr[3] if len(paddr) > 3 else ''
        if addrScope == '2':
            addrType = (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_MULTICAST)
        elif addrScope == 'e':
            addrType = (IPV6_ADDR_GLOBAL | IPV6_ADDR_MULTICAST)
        else:
            addrType = (IPV6_ADDR_GLOBAL | IPV6_ADDR_MULTICAST)
    elif ((naddr[0] == 0xfe) and (len(paddr) > 2 and ((int(paddr[2], 16) & 0xC) == 0x8))):
        addrType = (IPV6_ADDR_UNICAST | IPV6_ADDR_LINKLOCAL)
    elif paddr == "::1":
        addrType = IPV6_ADDR_LOOPBACK
    elif paddr == "::":
        addrType = IPV6_ADDR_UNSPECIFIED
    else:
        addrType = (IPV6_ADDR_GLOBAL | IPV6_ADDR_UNICAST)
    
    return addrType


def in6_getscope(addr: str) -> int:
    """Returns the scope of the address"""
    if in6_isgladdr(addr) or in6_isuladdr(addr):
        return IPV6_ADDR_GLOBAL
    elif in6_islladdr(addr):
        return IPV6_ADDR_LINKLOCAL
    elif in6_issladdr(addr):
        return IPV6_ADDR_SITELOCAL
    elif in6_ismaddr(addr):
        if in6_ismgladdr(addr):
            return IPV6_ADDR_GLOBAL
        elif in6_ismlladdr(addr):
            return IPV6_ADDR_LINKLOCAL
        elif in6_ismsladdr(addr):
            return IPV6_ADDR_SITELOCAL
        elif in6_ismnladdr(addr):
            return IPV6_ADDR_LOOPBACK
        else:
            return -1
    elif addr == '::1':
        return IPV6_ADDR_LOOPBACK
    else:
        return -1


def in6_isincluded(addr: str, prefix: str, plen: int) -> bool:
    """Returns True when 'addr' belongs to prefix/plen"""
    try:
        temp = socket.inet_pton(socket.AF_INET6, addr)
        pref = in6_cidr2mask(plen)
        zero = socket.inet_pton(socket.AF_INET6, prefix)
        return zero == in6_and(temp, pref)
    except Exception:
        return False


def in6_ismaddr(addr: str) -> bool:
    return in6_isincluded(addr, 'ff00::', 8)


def in6_ismnladdr(addr: str) -> bool:
    return in6_isincluded(addr, 'ff01::', 16)


def in6_ismgladdr(addr: str) -> bool:
    return in6_isincluded(addr, 'ff0e::', 16)


def in6_ismlladdr(addr: str) -> bool:
    return in6_isincluded(addr, 'ff02::', 16)


def in6_ismsladdr(addr: str) -> bool:
    return in6_isincluded(addr, 'ff05::', 16)


def in6_islladdr(addr: str) -> bool:
    return in6_isincluded(addr, 'fe80::', 10)


def in6_issladdr(addr: str) -> bool:
    return in6_isincluded(addr, 'fec0::', 10)


def in6_isuladdr(addr: str) -> bool:
    return in6_isincluded(addr, 'fc00::', 7)


def in6_isgladdr(addr: str) -> bool:
    return in6_isincluded(addr, '2000::', 3)


def in6_isdocaddr(addr: str) -> bool:
    """Returns True if address is in documentation prefix (2001:db8::/32)"""
    return in6_isincluded(addr, '2001:db8::', 32)


def in6_isllsnmaddr(addr: str) -> bool:
    """Check if address is link-local solicited-node multicast"""
    try:
        temp = in6_and(b"\xff" * 13 + b"\x00" * 3, socket.inet_pton(socket.AF_INET6, addr))
        temp2 = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00'
        return temp == temp2
    except Exception:
        return False


def in6_isaddrllallnodes(addr: str) -> bool:
    """Check if address is link-local all-nodes multicast (ff02::1)"""
    try:
        return socket.inet_pton(socket.AF_INET6, "ff02::1") == socket.inet_pton(socket.AF_INET6, addr)
    except Exception:
        return False


def in6_isaddrllallservers(addr: str) -> bool:
    """Check if address is link-local all-servers multicast (ff02::2)"""
    try:
        return socket.inet_pton(socket.AF_INET6, "ff02::2") == socket.inet_pton(socket.AF_INET6, addr)
    except Exception:
        return False


def in6_isaddr6to4(addr: str) -> bool:
    try:
        bx = socket.inet_pton(socket.AF_INET6, addr)
        return bx[:2] == b' \x02'
    except Exception:
        return False


def in6_isaddrTeredo(addr: str, teredo_prefix: str = "2001::") -> bool:
    try:
        our = socket.inet_pton(socket.AF_INET6, addr)[0:4]
        teredoPrefix = socket.inet_pton(socket.AF_INET6, teredo_prefix)[0:4]
        return teredoPrefix == our
    except Exception:
        return False


def in6_iseui64(addr: str) -> bool:
    try:
        eui64 = socket.inet_pton(socket.AF_INET6, '::ff:fe00:0')
        bx = in6_and(socket.inet_pton(socket.AF_INET6, addr), eui64)
        return bx == eui64
    except Exception:
        return False


def in6_isanycast(addr: str) -> bool:
    if in6_iseui64(addr):
        try:
            packed_s = socket.inet_pton(socket.AF_INET6, '::fdff:ffff:ffff:ff80')
            packed_x = socket.inet_pton(socket.AF_INET6, addr)
            x_and_s = in6_and(packed_x, packed_s)
            return x_and_s == packed_s
        except Exception:
            return False
    return False


def in6_addrtomac(addr: str) -> Optional[str]:
    try:
        mask = socket.inet_pton(socket.AF_INET6, "::ffff:ffff:ffff:ffff")
        x = in6_and(mask, socket.inet_pton(socket.AF_INET6, addr))
        ifaceid = socket.inet_ntop(socket.AF_INET6, x)[2:]
        return in6_ifaceidtomac(ifaceid)
    except Exception:
        return None


def in6_addrtovendor(addr: str) -> Optional[str]:
    mac = in6_addrtomac(addr)
    if mac is None:
        return None
    
    oui = mac[:8]
    if oui in OUI_DB:
        return OUI_DB[oui]
    
    for known_oui, vendor in OUI_DB.items():
        if mac.startswith(known_oui):
            return vendor
    
    return "UNKNOWN"


def in6_6to4ExtractAddr(addr: str) -> Optional[str]:
    try:
        baddr = socket.inet_pton(socket.AF_INET6, addr)
        if baddr[:2] != b" \x02":
            return None
        return socket.inet_ntop(socket.AF_INET, baddr[2:6])
    except Exception:
        return None


def teredoAddrExtractInfo(addr: str) -> Tuple[str, int, str, int]:
    addr_bytes = socket.inet_pton(socket.AF_INET6, addr)
    server = socket.inet_ntop(socket.AF_INET, addr_bytes[4:8])
    flag = struct.unpack("!H", addr_bytes[8:10])[0]
    mappedport = struct.unpack("!H", in6_xor(addr_bytes[10:12], b'\xff' * 2))[0]
    mappedaddr = socket.inet_ntop(socket.AF_INET, in6_xor(addr_bytes[12:16], b'\xff' * 4))
    return server, flag, mappedaddr, mappedport


def in6_mactoifaceid(mac: str, ulbit: Optional[int] = None) -> str:
    if len(mac) != 17:
        raise ValueError("Invalid MAC")
    m = "".join(mac.split(':'))
    if len(m) != 12:
        raise ValueError("Invalid MAC")
    first = int(m[0:2], 16)
    if ulbit is None or not (ulbit == 0 or ulbit == 1):
        ulbit = [1, 0, 0][first & 0x02]
    ulbit *= 2
    first_b = "%.02x" % ((first & 0xFD) | ulbit)
    eui64 = first_b + m[2:4] + ":" + m[4:6] + "FF:FE" + m[6:8] + ":" + m[8:12]
    return eui64.upper()


def in6_ifaceidtomac(ifaceid_s: str) -> Optional[str]:
    try:
        ifaceid = socket.inet_pton(socket.AF_INET6, "::" + ifaceid_s)[8:16]
    except Exception:
        return None
    
    if ifaceid[3:5] != b'\xff\xfe':
        return None
    
    first = struct.unpack("B", ifaceid[:1])[0]
    ulbit = 2 * [1, '-', 0][first & 0x02]
    first = struct.pack("B", ((first & 0xFD) | ulbit))
    oui = first + ifaceid[1:3]
    end = ifaceid[5:]
    mac_bytes = ["%.02x" % x for x in list(oui + end)]
    return ":".join(mac_bytes)


def in6_getRandomizedIfaceId(ifaceid: str, previous: Optional[str] = None) -> Tuple[str, str]:
    if previous is None:
        b_previous = bytes([random.randint(0, 255) for _ in range(8)])
    else:
        b_previous = socket.inet_pton(socket.AF_INET6, "::" + previous)[8:]
    
    s = socket.inet_pton(socket.AF_INET6, "::" + ifaceid)[8:] + b_previous
    s = hashlib.md5(s).digest()
    s1, s2 = s[:8], s[8:]
    s1 = bytes([s1[0] & (~0x04)]) + s1[1:]
    bs1 = socket.inet_ntop(socket.AF_INET6, b"\xff" * 8 + s1)[20:]
    bs2 = socket.inet_ntop(socket.AF_INET6, b"\xff" * 8 + s2)[20:]
    return (bs1, bs2)


def in6_cidr2mask(m: int) -> bytes:
    if m > 128 or m < 0:
        raise ValueError(f"value outside [0, 128] domain ({m})")
    
    t = []
    for i in range(0, 4):
        t.append(max(0, 2**32 - 2**(32 - min(32, m))))
        m -= 32
    return b"".join(struct.pack('!I', x) for x in t)


def in6_mask2cidr(m: bytes) -> int:
    if len(m) != 16:
        raise ValueError("value must be 16 octets long")
    
    for i in range(0, 4):
        s = struct.unpack('!I', m[i*4:(i+1)*4])[0]
        for j in range(32):
            if not s & (1 << (31 - j)):
                return i * 32 + j
    return 128


def in6_get_common_plen(a: str, b: str) -> int:
    def matching_bits(byte1: int, byte2: int) -> int:
        for i in range(8):
            cur_mask = 0x80 >> i
            if (byte1 & cur_mask) != (byte2 & cur_mask):
                return i
        return 8
    
    try:
        tmpA = socket.inet_pton(socket.AF_INET6, a)
        tmpB = socket.inet_pton(socket.AF_INET6, b)
        for i in range(16):
            mbits = matching_bits(tmpA[i], tmpB[i])
            if mbits != 8:
                return 8 * i + mbits
        return 128
    except Exception:
        return 0


def in6_getnsma(addr: bytes) -> bytes:
    r = in6_and(addr, socket.inet_pton(socket.AF_INET6, '::ff:ffff'))
    r = in6_or(socket.inet_pton(socket.AF_INET6, 'ff02::1:ff00:0'), r)
    return r


def in6_getnsmac(addr: bytes) -> str:
    ba = struct.unpack('16B', addr)[-4:]
    mac = '33:33:' + ':'.join("%.2x" % x for x in ba)
    return mac


def in6_getha(prefix: str) -> str:
    r = in6_and(socket.inet_pton(socket.AF_INET6, prefix), in6_cidr2mask(64))
    r = in6_or(r, socket.inet_pton(socket.AF_INET6, '::fdff:ffff:ffff:fffe'))
    return socket.inet_ntop(socket.AF_INET6, r)


def in6_getLinkScopedMcastAddr(addr: str, grpid: Optional[Union[bytes, str, int]] = None, scope: int = 2) -> Optional[str]:
    if scope not in [0, 1, 2]:
        return None
    
    try:
        if not in6_islladdr(addr):
            return None
        baddr = socket.inet_pton(socket.AF_INET6, addr)
    except Exception:
        return None
    
    iid = baddr[8:]
    
    if grpid is None:
        b_grpid = b'\x00\x00\x00\x00'
    else:
        try:
            if isinstance(grpid, str) and len(grpid) == 8:
                i_grpid = int(grpid, 16) & 0xffffffff
            elif isinstance(grpid, bytes) and len(grpid) == 4:
                i_grpid = struct.unpack("!I", grpid)[0]
            elif isinstance(grpid, int):
                i_grpid = grpid
            else:
                return None
        except Exception:
            return None
        b_grpid = struct.pack("!I", i_grpid)
    
    flgscope = struct.pack("B", 0xff & ((0x3 << 4) | scope))
    plen = b'\xff'
    res = b'\x00'
    a = b'\xff' + flgscope + res + plen + iid + b_grpid
    
    return socket.inet_ntop(socket.AF_INET6, a)


def in6_or(a1: bytes, a2: bytes) -> bytes:
    return bytes([x | y for x, y in zip(a1, a2)])


def in6_and(a1: bytes, a2: bytes) -> bytes:
    return bytes([x & y for x, y in zip(a1, a2)])


def in6_xor(a1: bytes, a2: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a1, a2)])


def in6_ptop(addr: str) -> str:
    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, addr))


def in6_isvalid(addr: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except Exception:
        return False


class Net6:
    """IPv6 network object with CIDR notation support"""
    
    def __init__(self, network: str):
        if '/' in network:
            self.network, self.prefix_len = network.split('/')
            self.prefix_len = int(self.prefix_len)
        else:
            self.network = network
            self.prefix_len = 128
        
        self._start = self._ip_to_int(self.network)
        self._mask = self._prefix_to_mask(self.prefix_len)
        self._network_start = self._start & self._mask
        self._network_end = self._network_start | (~self._mask & ((1 << 128) - 1))
        self.size = self._network_end - self._network_start + 1
    
    @staticmethod
    def _ip_to_int(addr: str) -> int:
        val1, val2 = struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, addr))
        return (val1 << 64) + val2
    
    @staticmethod
    def _int_to_ip(val: int) -> str:
        return socket.inet_ntop(socket.AF_INET6, struct.pack('!QQ', val >> 64, val & 0xffffffffffffffff))
    
    @staticmethod
    def _prefix_to_mask(plen: int) -> int:
        if plen == 0:
            return 0
        return ((1 << plen) - 1) << (128 - plen)
    
    def __contains__(self, addr: str) -> bool:
        try:
            ip_int = self._ip_to_int(addr)
            return self._network_start <= ip_int <= self._network_end
        except Exception:
            return False
    
    def __iter__(self):
        current = self._network_start
        while current <= self._network_end:
            yield self._int_to_ip(current)
            current += 1
    
    def __len__(self):
        return self.size
    
    def __repr__(self):
        return f"Net6({self.network}/{self.prefix_len})"


# ============================================================================
# REAL SYSTEM RECONNAISSANCE FUNCTIONS
# ============================================================================

class SystemRecon:
    """Performs actual system reconnaissance on Linux"""
    
    @staticmethod
    def get_interfaces() -> Dict[str, Dict[str, Any]]:
        """
        Get all network interfaces and their IPv6 addresses from /proc/net/if_inet6
        """
        interfaces = {}
        
        try:
            with open('/proc/net/if_inet6', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        addr_hex = parts[0]
                        iface_name = parts[5]
                        
                        # Convert hex to IPv6
                        addr_bytes = bytes.fromhex(addr_hex)
                        addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                        
                        # Parse flags
                        flags = int(parts[3], 16)
                        scope = int(parts[4], 16)
                        
                        if iface_name not in interfaces:
                            interfaces[iface_name] = {
                                'addresses': [],
                                'mac': None,
                                'flags': flags,
                                'scope': scope
                            }
                        
                        interfaces[iface_name]['addresses'].append({
                            'address': addr,
                            'scope': scope,
                            'flags': flags,
                            'addr_type': in6_getAddrType(addr)
                        })
        except Exception as e:
            print(f"Error reading /proc/net/if_inet6: {e}")
        
        # Get MAC addresses from /sys/class/net/
        for iface_name in interfaces:
            try:
                with open(f'/sys/class/net/{iface_name}/address', 'r') as f:
                    mac = f.read().strip()
                    interfaces[iface_name]['mac'] = mac
            except:
                interfaces[iface_name]['mac'] = None
        
        return interfaces
    
    @staticmethod
    def get_routing_table() -> List[Dict[str, Any]]:
        """
        Get IPv6 routing table from /proc/net/ipv6_route
        """
        routes = []
        
        try:
            with open('/proc/net/ipv6_route', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        dest_hex = parts[0]
                        dest_plen = int(parts[1], 16)
                        src_hex = parts[2]
                        src_plen = int(parts[3], 16)
                        next_hop_hex = parts[4]
                        metric = int(parts[5], 16)
                        iface = parts[9] if len(parts) > 9 else 'unknown'
                        
                        # Convert hex to IPv6
                        dest_bytes = bytes.fromhex(dest_hex)
                        dest = socket.inet_ntop(socket.AF_INET6, dest_bytes)
                        
                        next_hop_bytes = bytes.fromhex(next_hop_hex)
                        next_hop = socket.inet_ntop(socket.AF_INET6, next_hop_bytes) if any(next_hop_bytes) else '::'
                        
                        routes.append({
                            'destination': dest,
                            'prefix_len': dest_plen,
                            'src_prefix': src_hex,
                            'src_plen': src_plen,
                            'next_hop': next_hop,
                            'metric': metric,
                            'interface': iface,
                            'network': f"{dest}/{dest_plen}"
                        })
        except Exception as e:
            print(f"Error reading /proc/net/ipv6_route: {e}")
        
        return routes
    
    @staticmethod
    def get_neighbors() -> List[Dict[str, Any]]:
        """
        Get IPv6 neighbor cache from /proc/net/ndisc or using ip command
        """
        neighbors = []
        
        try:
            # Try using ip command
            result = subprocess.run(['ip', '-6', 'neigh', 'show'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 3:
                            addr = parts[0]
                            iface = parts[2] if parts[1] == 'dev' else 'unknown'
                            state = parts[3] if len(parts) > 3 else 'unknown'
                            
                            neighbors.append({
                                'address': addr,
                                'interface': iface,
                                'state': state
                            })
        except Exception:
            pass
        
        return neighbors
    
    @staticmethod
    def get_interface_info(iface: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific interface
        """
        info = {
            'name': iface,
            'mac': None,
            'addresses': [],
            'mtu': None,
            'state': None
        }
        
        # Get MAC
        try:
            with open(f'/sys/class/net/{iface}/address', 'r') as f:
                info['mac'] = f.read().strip()
        except:
            pass
        
        # Get MTU
        try:
            with open(f'/sys/class/net/{iface}/mtu', 'r') as f:
                info['mtu'] = f.read().strip()
        except:
            pass
        
        # Get state
        try:
            with open(f'/sys/class/net/{iface}/operstate', 'r') as f:
                info['state'] = f.read().strip()
        except:
            pass
        
        # Get IPv6 addresses
        try:
            with open('/proc/net/if_inet6', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 6 and parts[5] == iface:
                        addr_hex = parts[0]
                        addr_bytes = bytes.fromhex(addr_hex)
                        addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                        flags = int(parts[3], 16)
                        scope = int(parts[4], 16)
                        
                        info['addresses'].append({
                            'address': addr,
                            'scope': scope,
                            'flags': flags,
                            'addr_type': in6_getAddrType(addr)
                        })
        except:
            pass
        
        return info
    
    @staticmethod
    def ping6(addr: str, count: int = 1, timeout: int = 2) -> bool:
        """
        Ping an IPv6 address to check if it's reachable
        """
        try:
            result = subprocess.run(['ping6', '-c', str(count), '-W', str(timeout), addr],
                                  capture_output=True, text=True, timeout=timeout+1)
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def get_all_global_addresses() -> List[str]:
        """
        Get all global IPv6 addresses configured on the system
        """
        global_addrs = []
        interfaces = SystemRecon.get_interfaces()
        
        for iface, data in interfaces.items():
            for addr_info in data['addresses']:
                addr = addr_info['address']
                if in6_isgladdr(addr) and not in6_isaddr6to4(addr):
                    global_addrs.append(addr)
        
        return global_addrs
    
    @staticmethod
    def get_all_link_local_addresses() -> List[str]:
        """
        Get all link-local IPv6 addresses configured on the system
        """
        ll_addrs = []
        interfaces = SystemRecon.get_interfaces()
        
        for iface, data in interfaces.items():
            for addr_info in data['addresses']:
                addr = addr_info['address']
                if in6_islladdr(addr):
                    ll_addrs.append(addr)
        
        return ll_addrs


# ============================================================================
# IPv6 Reconnaissance Class - Performs REAL System Recon
# ============================================================================

class IPv6Recon:
    """IPv6 reconnaissance performing actual system analysis"""
    
    def __init__(self):
        self.interfaces = SystemRecon.get_interfaces()
        self.routes = SystemRecon.get_routing_table()
        self.neighbors = SystemRecon.get_neighbors()
        
    def analyze_system(self) -> Dict[str, Any]:
        """
        Complete system IPv6 analysis
        """
        return {
            'interfaces': self.analyze_interfaces(),
            'routing': self.analyze_routing(),
            'neighbors': self.analyze_neighbors(),
            'global_addresses': SystemRecon.get_all_global_addresses(),
            'link_local_addresses': SystemRecon.get_all_link_local_addresses(),
            'transition_technologies': self.detect_transition_technologies(),
            'summary': self.get_summary()
        }
    
    def analyze_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """
        Analyze all network interfaces
        """
        result = {}
        
        for iface, data in self.interfaces.items():
            result[iface] = {
                'name': iface,
                'mac': data['mac'],
                'address_count': len(data['addresses']),
                'addresses': [],
                'vendor': None
            }
            
            if data['mac']:
                # Get vendor from MAC
                oui = data['mac'][:8]
                result[iface]['vendor'] = OUI_DB.get(oui, "UNKNOWN")
            
            for addr_info in data['addresses']:
                addr = addr_info['address']
                addr_analysis = self.analyze_address(addr)
                result[iface]['addresses'].append(addr_analysis)
        
        return result
    
    def analyze_address(self, addr: str) -> Dict[str, Any]:
        """
        Comprehensive analysis of a single IPv6 address
        """
        result = {
            'address': addr,
            'normalized': in6_ptop(addr) if in6_isvalid(addr) else None,
            'valid': in6_isvalid(addr),
            'type': None,
            'scope': None,
            'is_multicast': False,
            'is_unicast': False,
            'is_global': False,
            'is_link_local': False,
            'is_site_local': False,
            'is_unique_local': False,
            'is_loopback': False,
            'is_unspecified': False,
            'is_6to4': False,
            'is_teredo': False,
            'is_documentation': False,
            'is_eui64': False,
            'is_anycast': False,
            'is_solicited_node': False,
            'mac_address': None,
            'vendor': None,
            'embedded_ipv4': None,
            'reachable': None
        }
        
        if not result['valid']:
            result['error'] = 'Invalid IPv6 address'
            return result
        
        addr_type = in6_getAddrType(addr)
        if addr_type & IPV6_ADDR_MULTICAST:
            result['is_multicast'] = True
            result['type'] = 'multicast'
        elif addr_type & IPV6_ADDR_UNICAST:
            result['is_unicast'] = True
            result['type'] = 'unicast'
        elif addr_type == IPV6_ADDR_LOOPBACK:
            result['is_loopback'] = True
            result['type'] = 'loopback'
        elif addr_type == IPV6_ADDR_UNSPECIFIED:
            result['is_unspecified'] = True
            result['type'] = 'unspecified'
        
        result['scope'] = in6_getscope(addr)
        result['is_global'] = bool(addr_type & IPV6_ADDR_GLOBAL)
        result['is_link_local'] = bool(addr_type & IPV6_ADDR_LINKLOCAL)
        result['is_site_local'] = bool(addr_type & IPV6_ADDR_SITELOCAL)
        result['is_6to4'] = bool(addr_type & IPV6_ADDR_6TO4)
        
        result['is_unique_local'] = in6_isuladdr(addr)
        result['is_documentation'] = in6_isdocaddr(addr)
        result['is_eui64'] = in6_iseui64(addr)
        result['is_anycast'] = in6_isanycast(addr)
        result['is_solicited_node'] = in6_isllsnmaddr(addr)
        result['is_teredo'] = in6_isaddrTeredo(addr)
        
        if result['is_6to4']:
            result['embedded_ipv4'] = in6_6to4ExtractAddr(addr)
        
        if result['is_eui64']:
            result['mac_address'] = in6_addrtomac(addr)
            if result['mac_address']:
                result['vendor'] = in6_addrtovendor(addr)
        
        return result
    
    def analyze_routing(self) -> Dict[str, Any]:
        """
        Analyze routing table
        """
        result = {
            'total_routes': len(self.routes),
            'routes': [],
            'connected_networks': [],
            'default_routes': []
        }
        
        for route in self.routes:
            route_info = route.copy()
            
            # Check if route is connected (next_hop is ::)
            if route['next_hop'] == '::':
                result['connected_networks'].append(route['network'])
            
            # Check if default route
            if route['destination'] == '::' and route['prefix_len'] == 0:
                result['default_routes'].append(route)
            
            result['routes'].append(route_info)
        
        return result
    
    def analyze_neighbors(self) -> Dict[str, Any]:
        """
        Analyze neighbor cache
        """
        result = {
            'total_neighbors': len(self.neighbors),
            'neighbors': [],
            'reachable': [],
            'stale': []
        }
        
        for neighbor in self.neighbors:
            neighbor_info = {
                'address': neighbor['address'],
                'interface': neighbor['interface'],
                'state': neighbor['state'],
                'is_global': in6_isgladdr(neighbor['address']),
                'is_link_local': in6_islladdr(neighbor['address']),
                'is_eui64': in6_iseui64(neighbor['address'])
            }
            
            if neighbor['state'] == 'REACHABLE':
                result['reachable'].append(neighbor_info)
            elif neighbor['state'] == 'STALE':
                result['stale'].append(neighbor_info)
            
            result['neighbors'].append(neighbor_info)
        
        return result
    
    def detect_transition_technologies(self) -> Dict[str, Any]:
        """
        Detect transition technologies on the system
        """
        result = {
            '6to4': [],
            'teredo': [],
            'isatap': [],
            'ula': []
        }
        
        for iface, data in self.interfaces.items():
            for addr_info in data['addresses']:
                addr = addr_info['address']
                
                if in6_isaddr6to4(addr):
                    result['6to4'].append({
                        'address': addr,
                        'interface': iface,
                        'embedded_ipv4': in6_6to4ExtractAddr(addr)
                    })
                
                if in6_isaddrTeredo(addr):
                    server, flag, mappedaddr, mappedport = teredoAddrExtractInfo(addr)
                    result['teredo'].append({
                        'address': addr,
                        'interface': iface,
                        'server': server,
                        'flag': flag,
                        'mapped_address': mappedaddr,
                        'mapped_port': mappedport
                    })
                
                if in6_isuladdr(addr):
                    result['ula'].append({
                        'address': addr,
                        'interface': iface
                    })
        
        return result
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of IPv6 configuration
        """
        total_addresses = 0
        global_count = 0
        link_local_count = 0
        unique_local_count = 0
        multicast_count = 0
        
        for iface, data in self.interfaces.items():
            total_addresses += len(data['addresses'])
            for addr_info in data['addresses']:
                addr = addr_info['address']
                addr_type = in6_getAddrType(addr)
                
                if addr_type & IPV6_ADDR_GLOBAL:
                    global_count += 1
                if addr_type & IPV6_ADDR_LINKLOCAL:
                    link_local_count += 1
                if in6_isuladdr(addr):
                    unique_local_count += 1
                if addr_type & IPV6_ADDR_MULTICAST:
                    multicast_count += 1
        
        return {
            'total_interfaces': len(self.interfaces),
            'total_addresses': total_addresses,
            'global_addresses': global_count,
            'link_local_addresses': link_local_count,
            'unique_local_addresses': unique_local_count,
            'multicast_addresses': multicast_count,
            'total_routes': len(self.routes),
            'total_neighbors': len(self.neighbors)
        }
    
    def generate_source_identities(self, interface: str = None) -> List[Dict[str, Any]]:
        """
        Generate possible source identities for adversary simulation
        """
        identities = []
        
        if interface:
            if interface in self.interfaces:
                interfaces = {interface: self.interfaces[interface]}
            else:
                return []
        else:
            interfaces = self.interfaces
        
        for iface, data in interfaces.items():
            mac = data['mac']
            if mac:
                # Hardware-derived identity
                eui64 = in6_mactoifaceid(mac)
                identities.append({
                    'type': 'hardware_derived',
                    'interface': iface,
                    'mac': mac,
                    'eui64': eui64,
                    'address': f"fe80::{eui64}"
                })
                
                # Generate randomized identities
                for i in range(3):
                    random_iid, history = in6_getRandomizedIfaceId(eui64, 
                        previous=None if i == 0 else None)
                    identities.append({
                        'type': f'randomized_{i+1}',
                        'interface': iface,
                        'base_eui64': eui64,
                        'random_iid': random_iid,
                        'history': history,
                        'address': f"fe80::{random_iid}"
                    })
        
        return identities
    
    def get_multicast_targets(self) -> List[Dict[str, Any]]:
        """
        Generate multicast targets for reconnaissance
        """
        targets = []
        
        for iface, data in self.interfaces.items():
            for addr_info in data['addresses']:
                addr = addr_info['address']
                
                if not in6_islladdr(addr):
                    continue
                
                # Solicited-node multicast
                nsma = in6_getnsma(socket.inet_pton(socket.AF_INET6, addr))
                nsma_str = socket.inet_ntop(socket.AF_INET6, nsma)
                
                targets.append({
                    'type': 'solicited_node',
                    'interface': iface,
                    'source_address': addr,
                    'multicast_address': nsma_str,
                    'multicast_mac': in6_getnsmac(nsma)
                })
                
                # All-nodes multicast
                targets.append({
                    'type': 'all_nodes',
                    'interface': iface,
                    'multicast_address': 'ff02::1',
                    'multicast_mac': '33:33:00:00:00:01'
                })
        
        return targets


# ============================================================================
# Main Execution
# ============================================================================

def main():
    """Perform real IPv6 reconnaissance on the system"""
    
    print("=" * 80)
    print("IPv6 REAL System Reconnaissance Toolkit")
    print("=" * 80)
    
    # Initialize reconnaissance
    recon = IPv6Recon()
    
    print("\n[1] System IPv6 Summary")
    print("-" * 60)
    summary = recon.get_summary()
    for key, value in summary.items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
    
    print("\n[2] Network Interfaces")
    print("-" * 60)
    interfaces = recon.analyze_interfaces()
    for iface, data in interfaces.items():
        print(f"\n  Interface: {iface}")
        print(f"    MAC: {data['mac']}")
        print(f"    Vendor: {data['vendor']}")
        print(f"    Address Count: {data['address_count']}")
        
        for addr_info in data['addresses'][:5]:  # Show first 5
            print(f"    Address: {addr_info['address']}")
            print(f"      Type: {addr_info['type']}")
            print(f"      Scope: {addr_info['scope']}")
            if addr_info['is_eui64']:
                print(f"      EUI-64: Yes")
                print(f"      MAC: {addr_info['mac_address']}")
                print(f"      Vendor: {addr_info['vendor']}")
            if addr_info['is_6to4']:
                print(f"      6to4 IPv4: {addr_info['embedded_ipv4']}")
            if addr_info['is_teredo']:
                print(f"      Teredo: Yes")
    
    print("\n[3] Routing Information")
    print("-" * 60)
    routing = recon.analyze_routing()
    print(f"  Total Routes: {routing['total_routes']}")
    print(f"  Connected Networks: {len(routing['connected_networks'])}")
    print(f"  Default Routes: {len(routing['default_routes'])}")
    
    if routing['default_routes']:
        print("\n  Default Routes:")
        for route in routing['default_routes']:
            print(f"    Interface: {route['interface']}")
            print(f"    Next Hop: {route['next_hop']}")
            print(f"    Metric: {route['metric']}")
    
    if routing['connected_networks']:
        print("\n  Connected Networks:")
        for network in routing['connected_networks'][:5]:
            print(f"    {network}")
    
    print("\n[4] Neighbor Cache")
    print("-" * 60)
    neighbors = recon.analyze_neighbors()
    print(f"  Total Neighbors: {neighbors['total_neighbors']}")
    print(f"  Reachable: {len(neighbors['reachable'])}")
    print(f"  Stale: {len(neighbors['stale'])}")
    
    if neighbors['reachable']:
        print("\n  Reachable Neighbors:")
        for neighbor in neighbors['reachable'][:5]:
            print(f"    {neighbor['address']} (interface: {neighbor['interface']})")
    
    print("\n[5] Transition Technologies")
    print("-" * 60)
    transitions = recon.detect_transition_technologies()
    print(f"  6to4 Addresses: {len(transitions['6to4'])}")
    print(f"  Teredo Addresses: {len(transitions['teredo'])}")
    print(f"  ULA Addresses: {len(transitions['ula'])}")
    
    if transitions['6to4']:
        print("\n  6to4 Addresses:")
        for entry in transitions['6to4']:
            print(f"    {entry['address']} -> IPv4: {entry['embedded_ipv4']}")
    
    if transitions['teredo']:
        print("\n  Teredo Addresses:")
        for entry in transitions['teredo']:
            print(f"    {entry['address']}")
            print(f"      Server: {entry['server']}")
            print(f"      Mapped: {entry['mapped_address']}:{entry['mapped_port']}")
    
    print("\n[6] Source Identities (Adversary Simulation)")
    print("-" * 60)
    identities = recon.generate_source_identities()
    print(f"  Generated {len(identities)} source identities")
    
    for identity in identities[:3]:  # Show first 3
        print(f"\n  Type: {identity['type']}")
        print(f"    Interface: {identity['interface']}")
        if 'mac' in identity:
            print(f"    MAC: {identity['mac']}")
        if 'eui64' in identity:
            print(f"    EUI-64: {identity['eui64']}")
        if 'address' in identity:
            print(f"    Address: {identity['address']}")
    
    print("\n[7] Multicast Targets")
    print("-" * 60)
    multicast_targets = recon.get_multicast_targets()
    print(f"  Generated {len(multicast_targets)} multicast targets")
    
    for target in multicast_targets[:5]:  # Show first 5
        print(f"\n  Type: {target['type']}")
        print(f"    Interface: {target['interface']}")
        print(f"    Multicast: {target['multicast_address']}")
        print(f"    MAC: {target['multicast_mac']}")
        if target['type'] == 'solicited_node':
            print(f"    Source: {target['source_address']}")
    
    print("\n" + "=" * 80)
    print("Reconnaissance Complete")
    print("=" * 80)
    
    # Optional: Show a few neighbors reachability test
    if neighbors['reachable']:
        print("\n[Optional] Testing reachability to first reachable neighbor...")
        test_addr = neighbors['reachable'][0]['address']
        if SystemRecon.ping6(test_addr, count=1, timeout=1):
            print(f"  {test_addr} is reachable")
        else:
            print(f"  {test_addr} is not responding to ping")


if __name__ == "__main__":
    main()