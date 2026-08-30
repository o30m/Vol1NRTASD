<img width="690" height="685" alt="netimg" src="https://github.com/user-attachments/assets/6b048bb4-b7cb-41c6-acb5-fd327c486e41" />


# Research Specialization in Network Red Team Adversary Simulation Development

# =============================================================================

### Language : Python ( ref. https://www.python.org/ )
### Library : Scapy ( ref. https://github.com/secdev/scapy )
### File : Volatile.py ( ref. https://github.com/secdev/scapy/blob/master/scapy/volatile.py )

================================================================================

### General Capabilities :

RandomEnumeration Iterates through a numeric sequence in a random order without
repetition, optionally looping forever.

VolatileValue The base class for all volatile values; it can be fixed to a concrete value,
represented, and used in commands.

_RandNumeral Provides common arithmetic, comparison, and type-casting operations for
random numeric values.

RandNum Generates a random integer within a specified inclusive range.

RandFloat Generates a random floating-point number within a specified range.

RandBinFloat Generates a random floating-point number by interpreting random binary data
as a float.

RandNumGamma Generates a random integer following a Gamma distribution.

RandNumGauss Generates a random integer following a Gaussian (normal) distribution.

RandNumExpo Generates a random integer following an exponential distribution, with an
optional base offset.

RandEnum Generates random integers from a range without replacement (sampling without
replacement).

RandByte / RandSByte Generates a random unsigned or signed byte (8-bit integer).

RandShort / RandSShort Generates a random unsigned or signed short (16-bit integer).

RandInt / RandSInt Generates a random unsigned or signed integer (32-bit).

RandLong / RandSLong Generates a random unsigned or signed long (64-bit).

RandEnumByte to RandEnumSLong Generates random integers of various sizes without
replacement (enumeration versions).

RandEnumKeys Picks a random key from a given dictionary's key list.

RandChoice Selects a random element from a provided list of choices.

_RandString The base class for volatile string-like values, handling string/bytes conversion
and repetition.

RandString Generates a random string of a given size, using a customizable character set.

RandBin Generates a random byte string of a given size.

RandTermString Generates a random byte string that ends with a specified termination
sequence.

RandIP Generates a random IP address within a specified CIDR network range.

RandMAC Generates a random MAC address, with optional templating for fixed or range-limited
octets.

RandIP6 Generates a random IPv6 address, supporting templates with wildcards and
variable-length parts.

RandOID Generates a random Object Identifier (OID) string, with optional formatting templates.

RandRegExp Generates a random string that matches a given regular expression.

RandSingularity The base class for "singularity" values, which are special or edge-case
values.

RandSingNum Picks a special/edge-case number from a range (e.g., 0, min, max, powers of
two, +/-1).

RandSingByte to RandSingSLong Generates special/edge-case numbers for various integer
sizes (byte, short, int, long).

RandSingString Picks from a list of special/edge-case strings (e.g., format strings, path
traversals, null bytes).

RandPool Randomly selects and evaluates a volatile value from a weighted pool of options.

RandUUID Generates a random UUID, supporting versions 1, 3, 4, and 5 with optional fields.

_AutoTime The base class for values that automatically update to the current time, with an
optional offset.

AutoTime Evaluates to the current floating-point Unix timestamp, minus a fixed offset.

IntAutoTime Evaluates to the current integer Unix timestamp, minus a fixed offset.

ZuluTime Evaluates to a Zulu (UTC) time string in the format YYMMDDHHMMSSZ.

GeneralizedTime Evaluates to a generalized UTC time string in the format
YYYYMMDDHHMMSSZ.

DelayedEval Evaluates a Python expression string at the time of fixing, allowing dynamic
values.

IncrementalValue Returns an integer that increments by a step each time it is evaluated,
with optional restart.

CorruptedBytes Introduces random byte corruptions in a given string with a specified
probability.

CorruptedBits Introduces random bit corruptions (not just bytes) in a given string

=============================================================================================
