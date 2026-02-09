#!/usr/bin/env python3
"""
Binary Rule Storage Module

Provides efficient binary storage for routing rules using msgpack format.
This module is Phase 1 of the database performance optimization, moving
bulk routing rules from SQLCipher to msgpack binary files.

Binary Format:
    - MAGIC: b"RULE" (4 bytes)
    - VERSION: 1 (uint8)
    - DATA: msgpack-encoded payload
    - CHECKSUM: SHA256 of DATA (32 bytes, appended)

Data Structure:
{
    "magic": "RULE",
    "version": 1,
    "rule_type": "ip" | "domain" | "domain_suffix" | "domain_keyword",
    "outbound": str,
    "rules": List[str],
    "created_at": str  # ISO format timestamp
}

Usage:
    from rule_binary import write_rule_binary, read_rule_binary

    # Write rules
    checksum = write_rule_binary(
        "/path/to/rules.bin",
        rules=["example.com", "test.org"],
        rule_type="domain",
        outbound="proxy"
    )

    # Read rules
    data = read_rule_binary("/path/to/rules.bin", expected_checksum=checksum)
"""

import hashlib
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

try:
    import msgpack
except ImportError:
    raise ImportError(
        "msgpack is required for binary rule storage. "
        "Install it with: pip install msgpack"
    )

# Module logger
logger = logging.getLogger(__name__)

# Binary format constants
MAGIC = b"RULE"
VERSION = 1

# Valid rule types
VALID_RULE_TYPES = frozenset({
    "ip",
    "domain",
    "domain_suffix",
    "domain_keyword",
})


class RuleBinaryError(Exception):
    """Base exception for rule binary operations."""
    pass


class RuleBinaryCorruptionError(RuleBinaryError):
    """Raised when binary file is corrupted or invalid."""
    pass


class RuleBinaryChecksumError(RuleBinaryError):
    """Raised when checksum verification fails."""
    pass


def _compute_checksum(data: bytes) -> str:
    """Compute SHA256 checksum of data.

    Args:
        data: Raw bytes to hash

    Returns:
        Hexadecimal SHA256 digest string
    """
    return hashlib.sha256(data).hexdigest()


def _validate_rule_type(rule_type: str) -> None:
    """Validate rule type is one of the allowed values.

    Args:
        rule_type: The rule type to validate

    Raises:
        ValueError: If rule_type is not valid
    """
    if rule_type not in VALID_RULE_TYPES:
        raise ValueError(
            f"Invalid rule_type '{rule_type}'. "
            f"Must be one of: {', '.join(sorted(VALID_RULE_TYPES))}"
        )


def _validate_rules(rules: List[str]) -> None:
    """Validate rules list.

    Args:
        rules: List of rule strings to validate

    Raises:
        TypeError: If rules is not a list or contains non-strings
        ValueError: If rules list is empty
    """
    if not isinstance(rules, list):
        raise TypeError(f"rules must be a list, got {type(rules).__name__}")

    if not rules:
        raise ValueError("rules list cannot be empty")

    for i, rule in enumerate(rules):
        if not isinstance(rule, str):
            raise TypeError(
                f"rules[{i}] must be a string, got {type(rule).__name__}"
            )


def write_rule_binary(
    file_path: str,
    rules: List[str],
    rule_type: str,
    outbound: str,
    tag: Optional[str] = None
) -> str:
    """Write rules to a binary file using msgpack format.

    Uses atomic write pattern (temp file + rename) to prevent corruption.
    The file format includes a SHA256 checksum for integrity verification.

    Args:
        file_path: Destination file path (absolute or relative)
        rules: List of rule strings (domains, IPs, etc.)
        rule_type: One of "ip", "domain", "domain_suffix", "domain_keyword"
        outbound: Target outbound name for these rules
        tag: Optional tag for rule grouping (included in metadata)

    Returns:
        SHA256 checksum of the written data (hex string)

    Raises:
        ValueError: If rule_type is invalid or rules is empty
        TypeError: If rules contains non-string elements
        IOError: If file write fails
    """
    # Validate inputs
    _validate_rule_type(rule_type)
    _validate_rules(rules)

    if not isinstance(outbound, str) or not outbound:
        raise ValueError("outbound must be a non-empty string")

    # Build data structure
    data = {
        "magic": MAGIC.decode("ascii"),
        "version": VERSION,
        "rule_type": rule_type,
        "outbound": outbound,
        "rules": rules,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    if tag is not None:
        data["tag"] = tag

    # Serialize with msgpack
    try:
        packed_data = msgpack.packb(data, use_bin_type=True)
    except Exception as e:
        logger.error("Failed to serialize rules with msgpack: %s", e)
        raise RuleBinaryError(f"Failed to serialize rules: {e}") from e

    # Compute checksum
    checksum = _compute_checksum(packed_data)

    # Prepare final binary: MAGIC + VERSION + DATA + CHECKSUM
    final_binary = MAGIC + bytes([VERSION]) + packed_data + bytes.fromhex(checksum)

    # Atomic write: write to temp file, then rename
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    temp_fd = None
    temp_path = None

    try:
        # Create temp file in same directory for atomic rename
        temp_fd, temp_path = tempfile.mkstemp(
            suffix=".tmp",
            prefix=".rule_binary_",
            dir=file_path.parent
        )

        # Write binary data
        os.write(temp_fd, final_binary)
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None

        # Atomic rename
        os.replace(temp_path, file_path)

        logger.info(
            "Wrote rule binary: path=%s, type=%s, outbound=%s, "
            "rules=%d, size=%d bytes, checksum=%s",
            file_path, rule_type, outbound, len(rules),
            len(final_binary), checksum[:16] + "..."
        )

        return checksum

    except Exception as e:
        # Cleanup temp file on error
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        logger.error("Failed to write rule binary to %s: %s", file_path, e)
        raise IOError(f"Failed to write rule binary to {file_path}: {e}") from e


def read_rule_binary(
    file_path: str,
    expected_checksum: Optional[str] = None
) -> Dict[str, Any]:
    """Read and validate a binary rule file.

    Args:
        file_path: Path to the binary rule file
        expected_checksum: Optional SHA256 checksum to verify against

    Returns:
        Dictionary with rule data:
        {
            "magic": "RULE",
            "version": 1,
            "rule_type": str,
            "outbound": str,
            "rules": List[str],
            "created_at": str,
            "tag": Optional[str]
        }

    Raises:
        FileNotFoundError: If file does not exist
        RuleBinaryCorruptionError: If file format is invalid
        RuleBinaryChecksumError: If checksum verification fails
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Rule binary file not found: {file_path}")

    try:
        with open(file_path, "rb") as f:
            binary_data = f.read()
    except IOError as e:
        raise RuleBinaryError(f"Failed to read rule binary: {e}") from e

    # Minimum size: MAGIC(4) + VERSION(1) + minimal msgpack + CHECKSUM(32)
    MIN_SIZE = 4 + 1 + 1 + 32
    if len(binary_data) < MIN_SIZE:
        raise RuleBinaryCorruptionError(
            f"File too small ({len(binary_data)} bytes), minimum is {MIN_SIZE}"
        )

    # Verify magic bytes
    if binary_data[:4] != MAGIC:
        raise RuleBinaryCorruptionError(
            f"Invalid magic bytes: expected {MAGIC!r}, got {binary_data[:4]!r}"
        )

    # Check version
    file_version = binary_data[4]
    if file_version != VERSION:
        raise RuleBinaryCorruptionError(
            f"Unsupported version: expected {VERSION}, got {file_version}"
        )

    # Extract checksum (last 32 bytes)
    stored_checksum_bytes = binary_data[-32:]
    stored_checksum = stored_checksum_bytes.hex()

    # Extract packed data (between header and checksum)
    packed_data = binary_data[5:-32]

    # Verify checksum
    computed_checksum = _compute_checksum(packed_data)
    if computed_checksum != stored_checksum:
        logger.error(
            "Checksum mismatch for %s: expected=%s, actual=%s",
            file_path, stored_checksum, computed_checksum
        )
        raise RuleBinaryChecksumError(
            f"Checksum mismatch: stored={stored_checksum[:16]}..., "
            f"computed={computed_checksum[:16]}..."
        )

    # Verify against expected checksum if provided
    if expected_checksum is not None and computed_checksum != expected_checksum:
        logger.error(
            "Checksum mismatch for %s: expected=%s, actual=%s",
            file_path, expected_checksum, computed_checksum
        )
        raise RuleBinaryChecksumError(
            f"Expected checksum mismatch: expected={expected_checksum[:16]}..., "
            f"computed={computed_checksum[:16]}..."
        )

    # Deserialize msgpack data
    try:
        data = msgpack.unpackb(packed_data, raw=False)
    except Exception as e:
        raise RuleBinaryCorruptionError(
            f"Failed to deserialize msgpack data: {e}"
        ) from e

    # Validate data structure
    if not isinstance(data, dict):
        raise RuleBinaryCorruptionError(
            f"Expected dict, got {type(data).__name__}"
        )

    required_fields = {"magic", "version", "rule_type", "outbound", "rules", "created_at"}
    missing = required_fields - set(data.keys())
    if missing:
        raise RuleBinaryCorruptionError(
            f"Missing required fields: {', '.join(sorted(missing))}"
        )

    # Validate rule_type
    if data["rule_type"] not in VALID_RULE_TYPES:
        raise RuleBinaryCorruptionError(
            f"Invalid rule_type in data: {data['rule_type']}"
        )

    logger.debug(
        "Read rule binary: path=%s, type=%s, outbound=%s, rules=%d",
        file_path, data["rule_type"], data["outbound"], len(data["rules"])
    )

    return data


def validate_rule_binary(file_path: str) -> Tuple[bool, str]:
    """Quick validation of a binary rule file without full parsing.

    Performs lightweight validation suitable for health checks:
    - Magic bytes check
    - Version check
    - Checksum verification

    Args:
        file_path: Path to the binary rule file

    Returns:
        Tuple of (is_valid, error_message)
        - (True, "") if valid
        - (False, "error description") if invalid
    """
    file_path = Path(file_path)

    if not file_path.exists():
        return False, f"File not found: {file_path}"

    try:
        with open(file_path, "rb") as f:
            # Read header only first
            header = f.read(5)
            if len(header) < 5:
                return False, "File too small to contain header"

            # Check magic
            if header[:4] != MAGIC:
                return False, f"Invalid magic bytes: {header[:4]!r}"

            # Check version
            if header[4] != VERSION:
                return False, f"Unsupported version: {header[4]}"

            # Read rest for checksum verification
            f.seek(0)
            binary_data = f.read()

    except IOError as e:
        return False, f"Failed to read file: {e}"

    # Verify minimum size
    MIN_SIZE = 4 + 1 + 1 + 32
    if len(binary_data) < MIN_SIZE:
        return False, f"File too small: {len(binary_data)} bytes"

    # Verify checksum
    stored_checksum = binary_data[-32:].hex()
    packed_data = binary_data[5:-32]
    computed_checksum = _compute_checksum(packed_data)

    if computed_checksum != stored_checksum:
        return False, "Checksum mismatch"

    return True, ""


def get_rule_binary_info(file_path: str) -> Dict[str, Any]:
    """Get metadata from a binary rule file without loading all rules.

    Useful for API responses and status displays where full rule
    list is not needed.

    Args:
        file_path: Path to the binary rule file

    Returns:
        Dictionary with metadata:
        {
            "file_path": str,
            "file_size": int,
            "version": int,
            "rule_type": str,
            "outbound": str,
            "rule_count": int,
            "created_at": str,
            "tag": Optional[str],
            "checksum": str,
            "is_valid": bool
        }

    Raises:
        FileNotFoundError: If file does not exist
        RuleBinaryCorruptionError: If file format is invalid
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Rule binary file not found: {file_path}")

    file_size = file_path.stat().st_size

    # Read full data (we need checksum and count)
    data = read_rule_binary(str(file_path))

    # Compute checksum for info
    with open(file_path, "rb") as f:
        binary_data = f.read()
    packed_data = binary_data[5:-32]
    checksum = _compute_checksum(packed_data)

    info = {
        "file_path": str(file_path.absolute()),
        "file_size": file_size,
        "version": data["version"],
        "rule_type": data["rule_type"],
        "outbound": data["outbound"],
        "rule_count": len(data["rules"]),
        "created_at": data["created_at"],
        "checksum": checksum,
        "is_valid": True,
    }

    if "tag" in data:
        info["tag"] = data["tag"]

    logger.debug(
        "Got rule binary info: path=%s, type=%s, count=%d",
        file_path, info["rule_type"], info["rule_count"]
    )

    return info


def list_rule_binaries(directory: str) -> List[Dict[str, Any]]:
    """List all rule binary files in a directory.

    Args:
        directory: Directory path to scan

    Returns:
        List of info dictionaries for each valid binary file.
        Invalid files are logged but not included.
    """
    directory = Path(directory)

    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    results = []

    for file_path in directory.glob("*.bin"):
        try:
            is_valid, error = validate_rule_binary(str(file_path))
            if is_valid:
                info = get_rule_binary_info(str(file_path))
                results.append(info)
            else:
                logger.warning(
                    "Skipping invalid rule binary: %s - %s",
                    file_path, error
                )
        except Exception as e:
            logger.warning(
                "Error reading rule binary %s: %s",
                file_path, e
            )

    logger.info(
        "Listed %d rule binaries in %s",
        len(results), directory
    )

    return results


if __name__ == "__main__":
    # Self-test
    import sys
    import tempfile

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("Rule Binary Module Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test_rules.bin")

        # Test write
        print("\n1. Testing write_rule_binary()...")
        test_rules = ["example.com", "test.org", "*.google.com"]
        checksum = write_rule_binary(
            test_file,
            rules=test_rules,
            rule_type="domain",
            outbound="proxy",
            tag="test-rules"
        )
        print(f"   Written: {test_file}")
        print(f"   Checksum: {checksum}")

        # Test read
        print("\n2. Testing read_rule_binary()...")
        data = read_rule_binary(test_file, expected_checksum=checksum)
        print(f"   Read {len(data['rules'])} rules")
        print(f"   rule_type: {data['rule_type']}")
        print(f"   outbound: {data['outbound']}")
        print(f"   created_at: {data['created_at']}")
        assert data["rules"] == test_rules, "Rules mismatch!"

        # Test validate
        print("\n3. Testing validate_rule_binary()...")
        is_valid, error = validate_rule_binary(test_file)
        print(f"   Valid: {is_valid}")
        assert is_valid, f"Validation failed: {error}"

        # Test info
        print("\n4. Testing get_rule_binary_info()...")
        info = get_rule_binary_info(test_file)
        print(f"   rule_count: {info['rule_count']}")
        print(f"   file_size: {info['file_size']} bytes")
        print(f"   tag: {info.get('tag')}")

        # Test list
        print("\n5. Testing list_rule_binaries()...")
        # Write another file
        write_rule_binary(
            os.path.join(tmpdir, "ip_rules.bin"),
            rules=["1.2.3.4", "10.0.0.0/8"],
            rule_type="ip",
            outbound="direct"
        )
        binaries = list_rule_binaries(tmpdir)
        print(f"   Found {len(binaries)} rule binaries")
        assert len(binaries) == 2, f"Expected 2 binaries, got {len(binaries)}"

        # Test error cases
        print("\n6. Testing error handling...")

        # Invalid rule_type
        try:
            write_rule_binary(test_file, ["test"], "invalid_type", "out")
            print("   ERROR: Should have raised ValueError")
            sys.exit(1)
        except ValueError as e:
            print(f"   Caught expected ValueError: {e}")

        # Corruption detection
        corrupt_file = os.path.join(tmpdir, "corrupt.bin")
        with open(corrupt_file, "wb") as f:
            f.write(b"RULE\x01" + b"garbage" * 10 + b"\x00" * 32)
        is_valid, error = validate_rule_binary(corrupt_file)
        print(f"   Corrupt file detected: {not is_valid}, error: {error}")
        assert not is_valid, "Corrupt file should be invalid"

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
