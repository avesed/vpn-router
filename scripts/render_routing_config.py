#!/usr/bin/env python3
"""
Shared Routing Config Generator - Phase 3.5

Generates routing configuration for both rust-router and sing-box from the
central database. This ensures both routers have consistent configuration
for seamless failover.

Output Formats:
    --format=rust-router: JSON for rust-router (IPC-style config)
    --format=sing-box: JSON for sing-box (sing-box.generated.json)

Usage:
    python3 render_routing_config.py --format=rust-router --output=/etc/rust-router/config.json
    python3 render_routing_config.py --format=sing-box --output=/etc/sing-box/sing-box.generated.json
    python3 render_routing_config.py --format=both  # Generate both configs

Environment Variables:
    GEODATA_DB_PATH: Path to geoip database
    USER_DB_PATH: Path to user config database
    SING_BOX_BASE_CONFIG: Base config template for sing-box
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Configure logging (统一日志配置，通过 LOG_LEVEL 环境变量控制)
try:
    from log_config import setup_logging, get_logger
    setup_logging()
    logger = get_logger("render_routing_config")
except ImportError:
    _log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, _log_level, logging.INFO),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger("render_routing_config")

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Try to import database helper
try:
    from db_helper import get_db, get_egress_interface_name
    HAS_DATABASE = True
except ImportError:
    HAS_DATABASE = False
    logger.warning("db_helper not available, using mock data")


# =============================================================================
# Constants
# =============================================================================

INTERFACE_MAX_LEN = 15  # Linux IFNAMSIZ

DEFAULT_GEODATA_DB_PATH = "/etc/sing-box/geoip-geodata.db"
DEFAULT_USER_DB_PATH = "/etc/sing-box/user-config.db"
DEFAULT_SING_BOX_BASE_CONFIG = "/etc/sing-box/sing-box.json"

# Port ranges
V2RAY_SOCKS_PORT_BASE = 37101
WARP_SOCKS_PORT_BASE = 38001
PEER_SOCKS_PORT_BASE = 37201

# Default ports
DEFAULT_TPROXY_PORT = 7893
DEFAULT_CLASH_API_PORT = 9090

# Port validation
MIN_PORT = 1
MAX_PORT = 65535

# Interface name validation
INTERFACE_NAME_PATTERN = r'^[a-zA-Z][a-zA-Z0-9_-]*$'


class OutputFormat(Enum):
    """Output format type"""
    RUST_ROUTER = "rust-router"
    SING_BOX = "sing-box"
    BOTH = "both"


class EgressType(Enum):
    """Egress type classification"""
    PIA = "pia"
    CUSTOM = "custom"
    WARP_WG = "warp_wg"
    # Phase 3: WARP_MASQUE removed - WireGuard only
    V2RAY = "v2ray"
    OPENVPN = "openvpn"
    DIRECT = "direct"
    BLOCK = "block"
    PEER = "peer"


class RuleType(Enum):
    """Rule type classification"""
    DOMAIN = "domain"
    DOMAIN_SUFFIX = "domain_suffix"
    DOMAIN_KEYWORD = "domain_keyword"
    DOMAIN_REGEX = "domain_regex"
    GEOIP = "geoip"
    IP_CIDR = "ip_cidr"
    PORT = "port"
    PROTOCOL = "protocol"
    GEOSITE = "geosite"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class OutboundConfig:
    """Generic outbound configuration"""
    tag: str
    egress_type: EgressType
    enabled: bool = True

    # For WireGuard-based outbounds
    interface: Optional[str] = None
    routing_mark: Optional[int] = None
    routing_table: Optional[int] = None

    # For SOCKS5-based outbounds (V2Ray only, Phase 3: WARP MASQUE removed)
    socks_addr: Optional[str] = None
    socks_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None

    # For direct outbounds
    bind_interface: Optional[str] = None
    bind_address: Optional[str] = None


@dataclass
class RuleConfig:
    """Routing rule configuration"""
    rule_type: RuleType
    target: str
    outbound: str
    priority: int = 0
    enabled: bool = True


@dataclass
class EcmpGroupConfig:
    """ECMP load balancing group configuration"""
    tag: str
    members: List[str]
    group_type: str = "loadbalance"  # "loadbalance" or "failover"
    weights: Optional[Dict[str, int]] = None
    routing_table: Optional[int] = None
    enabled: bool = True
    health_check_url: Optional[str] = None
    health_check_interval: Optional[int] = None


@dataclass
class RoutingConfig:
    """Complete routing configuration"""
    outbounds: List[OutboundConfig] = field(default_factory=list)
    rules: List[RuleConfig] = field(default_factory=list)
    ecmp_groups: List[EcmpGroupConfig] = field(default_factory=list)
    default_outbound: str = "direct"
    dns_servers: List[Dict[str, Any]] = field(default_factory=list)


# =============================================================================
# Helper Functions
# =============================================================================

def get_egress_interface_name_fallback(tag: str, egress_type: EgressType) -> str:
    """Get egress interface name with fallback if db_helper not available.

    Args:
        tag: Egress tag
        egress_type: Type of egress

    Returns:
        Interface name (max 15 chars)
    """
    if HAS_DATABASE:
        # Use the database helper function
        is_pia = egress_type == EgressType.PIA
        if egress_type == EgressType.WARP_WG:
            # Special case for WARP
            prefix = "wg-warp-"
        elif egress_type == EgressType.PEER:
            prefix = "wg-peer-"
        elif is_pia:
            prefix = "wg-pia-"
        else:
            prefix = "wg-eg-"

        max_tag_len = INTERFACE_MAX_LEN - len(prefix)
        if len(tag) <= max_tag_len:
            return f"{prefix}{tag}"
        else:
            tag_hash = hashlib.md5(tag.encode('utf-8')).hexdigest()[:max_tag_len]
            return f"{prefix}{tag_hash}"
    else:
        # Fallback implementation matching db_helper
        prefix_map = {
            EgressType.PIA: "wg-pia-",
            EgressType.CUSTOM: "wg-eg-",
            EgressType.WARP_WG: "wg-warp-",
            EgressType.PEER: "wg-peer-",
        }
        prefix = prefix_map.get(egress_type, "wg-eg-")
        max_tag_len = INTERFACE_MAX_LEN - len(prefix)

        if len(tag) <= max_tag_len:
            return f"{prefix}{tag}"
        else:
            tag_hash = hashlib.md5(tag.encode('utf-8')).hexdigest()[:max_tag_len]
            return f"{prefix}{tag_hash}"


def safe_int_env(name: str, default: int) -> int:
    """Safely read an integer from environment variable.

    Args:
        name: Environment variable name
        default: Default value

    Returns:
        Integer value from environment or default
    """
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning(f"Invalid integer value '{value}' for {name}, using default {default}")
        return default


def validate_port(port: int, context: str = "") -> bool:
    """Validate that a port number is in valid range.

    Args:
        port: Port number to validate
        context: Context for error messages (e.g., outbound tag)

    Returns:
        True if valid, False otherwise
    """
    if not isinstance(port, int) or port < MIN_PORT or port > MAX_PORT:
        ctx = f" ({context})" if context else ""
        logger.warning(f"Invalid port {port}{ctx}: must be {MIN_PORT}-{MAX_PORT}")
        return False
    return True


def validate_interface_name(name: str, context: str = "") -> bool:
    """Validate that an interface name is valid.

    Args:
        name: Interface name to validate
        context: Context for error messages

    Returns:
        True if valid, False otherwise
    """
    if not name:
        return False
    if len(name) > INTERFACE_MAX_LEN:
        ctx = f" ({context})" if context else ""
        logger.warning(f"Interface name '{name}'{ctx} too long: max {INTERFACE_MAX_LEN} chars")
        return False
    if not re.match(INTERFACE_NAME_PATTERN, name):
        ctx = f" ({context})" if context else ""
        logger.warning(f"Invalid interface name '{name}'{ctx}: must match {INTERFACE_NAME_PATTERN}")
        return False
    return True


# =============================================================================
# Database Loading Functions
# =============================================================================

class DatabaseLoader:
    """Loads configuration from the database"""

    def __init__(self, geodata_path: str, user_db_path: str):
        """Initialize the database loader.

        Args:
            geodata_path: Path to geoip database
            user_db_path: Path to user config database
        """
        self.geodata_path = geodata_path
        self.user_db_path = user_db_path
        self._db = None

    def _get_db(self):
        """Get database connection"""
        if not HAS_DATABASE:
            return None
        if self._db is None:
            self._db = get_db(self.geodata_path, self.user_db_path)
        return self._db

    def load_pia_profiles(self) -> List[OutboundConfig]:
        """Load PIA WireGuard profiles"""
        db = self._get_db()
        if not db:
            logger.warning("Database not available for PIA profiles loading")
            return []

        outbounds = []
        try:
            profiles = db.get_pia_profiles(enabled_only=True)
            for profile in profiles:
                if not profile.get("private_key"):
                    continue  # Skip unconfigured profiles

                tag = profile["name"]
                interface = get_egress_interface_name_fallback(tag, EgressType.PIA)

                outbounds.append(OutboundConfig(
                    tag=tag,
                    egress_type=EgressType.PIA,
                    enabled=True,
                    interface=interface,
                ))
            logger.info(f"Loaded {len(outbounds)} PIA profiles")
        except Exception as e:
            logger.error(f"Failed to load PIA profiles: {e}")

        return outbounds

    def load_custom_wireguard(self) -> List[OutboundConfig]:
        """Load custom WireGuard egress"""
        db = self._get_db()
        if not db:
            logger.warning("Database not available for custom WireGuard loading")
            return []

        outbounds = []
        try:
            egress_list = db.get_custom_egress_list(enabled_only=True)
            for egress in egress_list:
                tag = egress.get("tag")
                if not tag:
                    continue

                interface = get_egress_interface_name_fallback(tag, EgressType.CUSTOM)

                outbounds.append(OutboundConfig(
                    tag=tag,
                    egress_type=EgressType.CUSTOM,
                    enabled=True,
                    interface=interface,
                ))
            logger.info(f"Loaded {len(outbounds)} custom WireGuard egress")
        except Exception as e:
            logger.error(f"Failed to load custom WireGuard: {e}")

        return outbounds

    def load_v2ray_egress(self) -> List[OutboundConfig]:
        """Load V2Ray/Xray egress (SOCKS5 based)"""
        db = self._get_db()
        if not db:
            logger.warning("Database not available for V2Ray egress loading")
            return []

        outbounds = []
        try:
            egress_list = db.get_v2ray_egress_list(enabled_only=True)
            for egress in egress_list:
                tag = egress.get("tag")
                socks_port = egress.get("socks_port")
                if not tag or not socks_port:
                    continue

                # Validate port range
                if not validate_port(socks_port, tag):
                    continue

                outbounds.append(OutboundConfig(
                    tag=tag,
                    egress_type=EgressType.V2RAY,
                    enabled=True,
                    socks_addr="127.0.0.1",
                    socks_port=socks_port,
                ))
            logger.info(f"Loaded {len(outbounds)} V2Ray egress")
        except Exception as e:
            logger.error(f"Failed to load V2Ray egress: {e}")

        return outbounds

    def load_warp_egress(self) -> List[OutboundConfig]:
        """Load WARP egress (Phase 3: WireGuard only, MASQUE removed)"""
        db = self._get_db()
        if not db:
            logger.warning("Database not available for WARP egress loading")
            return []

        outbounds = []
        try:
            egress_list = db.get_warp_egress_list(enabled_only=True)
            for egress in egress_list:
                tag = egress.get("tag")

                if not tag:
                    continue

                # Phase 3: Only WireGuard protocol supported
                interface = get_egress_interface_name_fallback(tag, EgressType.WARP_WG)
                outbounds.append(OutboundConfig(
                    tag=tag,
                    egress_type=EgressType.WARP_WG,
                    enabled=True,
                    interface=interface,
                ))
            logger.info(f"Loaded {len(outbounds)} WARP WireGuard egress")
        except Exception as e:
            logger.error(f"Failed to load WARP egress: {e}")

        return outbounds

    def load_openvpn_egress(self) -> List[OutboundConfig]:
        """Load OpenVPN egress"""
        db = self._get_db()
        if not db:
            logger.warning("Database not available for OpenVPN egress loading")
            return []

        outbounds = []
        try:
            egress_list = db.get_openvpn_egress_list(enabled_only=True)
            for egress in egress_list:
                tag = egress.get("tag")
                tun_device = egress.get("tun_device")

                if not tag or not tun_device:
                    continue

                outbounds.append(OutboundConfig(
                    tag=tag,
                    egress_type=EgressType.OPENVPN,
                    enabled=True,
                    bind_interface=tun_device,
                ))
            logger.info(f"Loaded {len(outbounds)} OpenVPN egress")
        except Exception as e:
            logger.error(f"Failed to load OpenVPN egress: {e}")

        return outbounds

    def load_direct_egress(self) -> List[OutboundConfig]:
        """Load direct egress (bound to interface/IP)"""
        db = self._get_db()
        if not db:
            logger.warning("Database not available for direct egress loading")
            return []

        outbounds = []
        try:
            egress_list = db.get_direct_egress_list(enabled_only=True)
            for egress in egress_list:
                tag = egress.get("tag")
                if not tag or tag == "direct":
                    continue  # Don't override default direct

                outbounds.append(OutboundConfig(
                    tag=tag,
                    egress_type=EgressType.DIRECT,
                    enabled=True,
                    bind_interface=egress.get("bind_interface"),
                    bind_address=egress.get("inet4_bind_address"),
                ))
            logger.info(f"Loaded {len(outbounds)} direct egress")
        except Exception as e:
            logger.error(f"Failed to load direct egress: {e}")

        return outbounds

    def load_routing_rules(self) -> List[RuleConfig]:
        """Load routing rules from database"""
        db = self._get_db()
        if not db:
            logger.warning("Database not available for routing rules loading")
            return []

        rules = []
        try:
            db_rules = db.get_routing_rules(enabled_only=True)
            for rule in db_rules:
                rule_type_str = rule.get("rule_type", "")
                try:
                    rule_type = RuleType(rule_type_str)
                except ValueError:
                    # Try mapping common variations
                    type_map = {
                        "domain_exact": RuleType.DOMAIN,
                        "ip": RuleType.IP_CIDR,
                        "cidr": RuleType.IP_CIDR,
                    }
                    rule_type = type_map.get(rule_type_str)
                    if not rule_type:
                        logger.warning(f"Unknown rule type: {rule_type_str}")
                        continue

                rules.append(RuleConfig(
                    rule_type=rule_type,
                    target=rule.get("target", ""),
                    outbound=rule.get("outbound", "direct"),
                    priority=rule.get("priority", 0),
                    enabled=True,
                ))
            logger.info(f"Loaded {len(rules)} routing rules")
        except Exception as e:
            logger.error(f"Failed to load routing rules: {e}")

        return rules

    def load_default_outbound(self) -> str:
        """Load default outbound from settings"""
        db = self._get_db()
        if not db:
            logger.warning("Database not available for default outbound loading, using 'direct'")
            return "direct"

        try:
            default = db.get_setting("default_outbound", "direct")
            return default or "direct"
        except Exception as e:
            logger.error(f"Failed to load default outbound: {e}")
            return "direct"

    def load_outbound_groups(self) -> List[EcmpGroupConfig]:
        """Load ECMP outbound groups from database"""
        groups = []
        db = self._get_db()
        if not db:
            logger.warning("Database not available for outbound groups loading")
            return groups

        try:
            db_groups = db.get_outbound_groups(enabled_only=True)
            for group in db_groups:
                groups.append(EcmpGroupConfig(
                    tag=group.get("tag", ""),
                    members=group.get("members", []),
                    group_type=group.get("type", "loadbalance"),
                    weights=group.get("weights"),
                    routing_table=group.get("routing_table"),
                    enabled=bool(group.get("enabled", True)),
                    health_check_url=group.get("health_check_url"),
                    health_check_interval=group.get("health_check_interval"),
                ))
            logger.info(f"Loaded {len(groups)} outbound groups")
        except Exception as e:
            logger.error(f"Failed to load outbound groups: {e}")

        return groups

    def load_all(self) -> RoutingConfig:
        """Load complete routing configuration"""
        outbounds = []

        # Always include base outbounds
        outbounds.append(OutboundConfig(tag="direct", egress_type=EgressType.DIRECT, enabled=True))
        outbounds.append(OutboundConfig(tag="block", egress_type=EgressType.BLOCK, enabled=True))

        # Load all egress types
        outbounds.extend(self.load_pia_profiles())
        outbounds.extend(self.load_custom_wireguard())
        outbounds.extend(self.load_v2ray_egress())
        outbounds.extend(self.load_warp_egress())
        outbounds.extend(self.load_openvpn_egress())
        outbounds.extend(self.load_direct_egress())

        # Load ECMP groups
        ecmp_groups = self.load_outbound_groups()

        # Load rules and default
        rules = self.load_routing_rules()
        default_outbound = self.load_default_outbound()

        return RoutingConfig(
            outbounds=outbounds,
            rules=rules,
            ecmp_groups=ecmp_groups,
            default_outbound=default_outbound,
        )


# =============================================================================
# Config Generators
# =============================================================================

class RustRouterConfigGenerator:
    """Generates rust-router configuration format"""

    def generate(self, config: RoutingConfig) -> Dict[str, Any]:
        """Generate rust-router config JSON.

        Args:
            config: Routing configuration

        Returns:
            Dict suitable for JSON serialization matching rust-router's Config struct
        """
        outbounds = []
        valid_outbound_tags: set[str] = set()

        for ob in config.outbounds:
            outbound_dict = self._convert_outbound(ob)
            if outbound_dict:
                outbounds.append(outbound_dict)
                valid_outbound_tags.add(outbound_dict["tag"])
            elif ob.egress_type in (EgressType.PIA, EgressType.CUSTOM, EgressType.WARP_WG, EgressType.PEER):
                # Phase 11-Fix.AE: WireGuard outbounds are valid even though managed via IPC
                # Rules referencing them should NOT be remapped to default
                valid_outbound_tags.add(ob.tag)
                logger.debug(f"Marked WireGuard outbound '{ob.tag}' as valid (managed via IPC)")
            elif ob.egress_type == EgressType.V2RAY:
                # Phase 11-Fix.AE: SOCKS5 outbounds are also managed via IPC
                # Phase 3: WARP_MASQUE removed
                valid_outbound_tags.add(ob.tag)
                logger.debug(f"Marked SOCKS5 outbound '{ob.tag}' as valid (managed via IPC)")

        # Phase 6-Fix.AI: Add ECMP group tags to valid outbounds
        # Groups are managed via IPC (CreateEcmpGroup command) but rules can reference them
        for group in config.ecmp_groups:
            valid_outbound_tags.add(group.tag)
            logger.debug(f"Marked ECMP group '{group.tag}' as valid (managed via IPC)")

        # Phase 6-Fix.AF: Check if default outbound is IPC-managed (SOCKS5/WireGuard)
        # These outbounds are added dynamically via IPC, not in static config.
        # Set static default to "direct", then Python manager sets real default via IPC.
        default_outbound = config.default_outbound

        # Build set of outbound tags that are IPC-managed (not in static config)
        # Phase 3: WARP_MASQUE removed
        ipc_managed_tags = set()
        for ob in config.outbounds:
            if ob.egress_type in (EgressType.PIA, EgressType.CUSTOM, EgressType.WARP_WG, EgressType.PEER,
                                  EgressType.V2RAY):
                ipc_managed_tags.add(ob.tag)
        # ECMP groups are also IPC-managed
        for group in config.ecmp_groups:
            ipc_managed_tags.add(group.tag)

        if default_outbound in ipc_managed_tags:
            logger.info(f"Default outbound '{default_outbound}' is IPC-managed, using 'direct' in static config")
            logger.info(f"Python manager will set real default '{default_outbound}' via IPC after startup")
            default_outbound = "direct"
        elif default_outbound not in valid_outbound_tags:
            logger.warning(f"Default outbound '{default_outbound}' was skipped, remapping to 'direct'")
            default_outbound = "direct"

        # Filter rules to only include those with valid outbounds
        # For rules referencing skipped outbounds (e.g., SOCKS5), use default outbound
        # Phase 12-Fix: IPC-managed rules are SKIPPED from static config entirely.
        # This avoids the race condition where traffic goes to "direct" before IPC sync.
        # The default_outbound will be used for unmatched traffic until IPC pushes correct rules.
        # Python manager will sync ALL rules (including IPC-managed) via IPC after startup.
        rules = []
        skipped_count = 0
        ipc_skipped_count = 0
        for rule in config.rules:
            outbound = rule.outbound
            if outbound in ipc_managed_tags:
                # Phase 12-Fix: Skip IPC-managed rules in static config
                # These will fall through to default_outbound until IPC sync completes
                # This is better than mapping to "direct" which could be wrong
                ipc_skipped_count += 1
                continue
            elif outbound not in valid_outbound_tags:
                # Rule references a skipped outbound, reroute to default
                skipped_count += 1
                outbound = default_outbound
                # Skip if default outbound is also invalid (shouldn't happen since we validated above)
                if outbound not in valid_outbound_tags:
                    continue

            rules.append({
                "type": rule.rule_type.value,  # Rust uses #[serde(rename = "type")]
                "target": rule.target,
                "outbound": outbound,
                "priority": rule.priority,
                "enabled": rule.enabled,
            })

        if skipped_count > 0:
            logger.info(f"Remapped {skipped_count} rules from skipped outbounds to default")
        if ipc_skipped_count > 0:
            logger.info(f"Skipped {ipc_skipped_count} IPC-managed rules from static config (will sync via IPC)")

        tproxy_port = safe_int_env("RUST_ROUTER_PORT", DEFAULT_TPROXY_PORT)
        listen_addr = os.environ.get("RUST_ROUTER_LISTEN_ADDR", "127.0.0.1")
        socket_path = os.environ.get("RUST_ROUTER_SOCKET", "/var/run/rust-router.sock")

        return {
            # ListenConfig - required
            "listen": {
                "address": f"{listen_addr}:{tproxy_port}",
                "tcp_enabled": True,
                "udp_enabled": True,
                "tcp_backlog": 1024,
                "udp_timeout_secs": 300,
                "reuse_port": True,
                "sniff_timeout_ms": 300,
            },
            # Outbounds - required
            "outbounds": outbounds,
            # Default outbound - required (top-level, not in routing)
            # Phase 11-Fix.AB: Use validated default_outbound (may have been remapped)
            "default_outbound": default_outbound,
            # IpcConfig - required
            "ipc": {
                "socket_path": socket_path,
                "socket_mode": 432,  # 0o660
                "enabled": True,
                "max_message_size": 1048576,  # 1MB
            },
            # LogConfig - optional with defaults
            "log": {
                "level": os.environ.get("RUST_LOG", "info"),
            },
            # ConnectionConfig - optional with defaults
            "connection": {
                "max_connections": safe_int_env("RUST_ROUTER_MAX_CONNECTIONS", 65536),
                "connection_timeout_secs": 30,
                "idle_timeout_secs": 300,
            },
            # RulesConfig - optional with defaults
            "rules": {
                "rules": rules,
                "geoip_db_path": os.environ.get("GEOIP_DB_PATH", "/etc/sing-box/geoip.db"),
                "domain_catalog_path": os.environ.get("DOMAIN_CATALOG_PATH", "/etc/sing-box/domain-catalog.json"),
            },
        }

    def _convert_outbound(self, ob: OutboundConfig) -> Optional[Dict[str, Any]]:
        """Convert OutboundConfig to rust-router format.

        Note: rust-router currently only supports Direct and Block outbound types
        in config. WireGuard-based outbounds use Direct with bind_interface.
        SOCKS5 outbounds (V2Ray only, Phase 3: WARP MASQUE removed) are not yet supported and will be skipped.

        WireGuard outbounds are managed via IPC by rust_router_manager.py (userspace mode).
        """

        if ob.egress_type == EgressType.DIRECT:
            result: Dict[str, Any] = {
                "type": "direct",  # lowercase to match serde deserialization
                "tag": ob.tag,
                "enabled": ob.enabled,
            }
            if ob.bind_interface:
                result["bind_interface"] = ob.bind_interface
            if ob.bind_address:
                result["bind_address"] = ob.bind_address
            return result

        elif ob.egress_type == EgressType.BLOCK:
            return {
                "type": "block",  # lowercase to match serde deserialization
                "tag": ob.tag,
                "enabled": ob.enabled,
            }

        elif ob.egress_type in (EgressType.PIA, EgressType.CUSTOM, EgressType.WARP_WG, EgressType.PEER):
            # WireGuard-based outbounds are managed via IPC (userspace mode)
            # They will be added by rust_router_manager.py
            logger.info(f"Skipping WireGuard outbound '{ob.tag}' in static config (managed via IPC)")
            return None

        elif ob.egress_type == EgressType.V2RAY:
            # Phase 3: WARP_MASQUE removed - only V2Ray SOCKS5 remains
            # SOCKS5-based outbounds are not yet supported in rust-router config
            # These will need to be added via IPC when that's implemented
            logger.warning(f"SOCKS5 outbound '{ob.tag}' not yet supported in rust-router, skipping")
            return None

        elif ob.egress_type == EgressType.OPENVPN:
            # OpenVPN: direct with bind_interface (the tun device)
            return {
                "type": "direct",  # lowercase to match serde deserialization
                "tag": ob.tag,
                "enabled": ob.enabled,
                "bind_interface": ob.bind_interface,
            }

        else:
            logger.warning(f"Unknown egress type: {ob.egress_type}")
            return None


class SingBoxConfigGenerator:
    """Generates sing-box configuration format"""

    def __init__(self, base_config_path: str):
        """Initialize with base config template.

        Args:
            base_config_path: Path to sing-box.json template
        """
        self.base_config_path = base_config_path

    def generate(self, config: RoutingConfig) -> Dict[str, Any]:
        """Generate sing-box config JSON.

        Args:
            config: Routing configuration

        Returns:
            Dict suitable for JSON serialization
        """
        # Load base config
        base = self._load_base_config()

        # Build outbounds
        outbounds = base.get("outbounds", [])
        existing_tags = {ob.get("tag") for ob in outbounds}

        for ob in config.outbounds:
            if ob.tag in existing_tags:
                # Update existing
                for i, existing in enumerate(outbounds):
                    if existing.get("tag") == ob.tag:
                        outbounds[i] = self._convert_outbound(ob)
                        break
            else:
                # Insert before block
                singbox_ob = self._convert_outbound(ob)
                if singbox_ob:
                    block_idx = next(
                        (i for i, x in enumerate(outbounds) if x.get("tag") in ("block", "adblock")),
                        len(outbounds)
                    )
                    outbounds.insert(block_idx, singbox_ob)
                    existing_tags.add(ob.tag)

        base["outbounds"] = outbounds

        # Build routing rules
        route = base.setdefault("route", {})
        rules = route.setdefault("rules", [])

        # Keep action rules (sniff, hijack-dns) at the beginning
        action_rules = [r for r in rules if r.get("action") in ("sniff", "hijack-dns")]
        other_rules = [r for r in rules if r.get("action") not in ("sniff", "hijack-dns")]

        # Add new rules
        for rule in config.rules:
            singbox_rule = self._convert_rule(rule)
            if singbox_rule:
                other_rules.append(singbox_rule)

        route["rules"] = action_rules + other_rules
        route["final"] = config.default_outbound

        return base

    def _load_base_config(self) -> Dict[str, Any]:
        """Load base sing-box configuration"""
        try:
            with open(self.base_config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Base config not found: {self.base_config_path}")
            return self._default_base_config()
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in base config: {e}")
            return self._default_base_config()

    def _default_base_config(self) -> Dict[str, Any]:
        """Return default base configuration"""
        return {
            "log": {"level": "info"},
            "inbounds": [
                {
                    "type": "tproxy",
                    "tag": "tproxy-in",
                    "listen": "0.0.0.0",
                    "listen_port": safe_int_env("TPROXY_PORT", DEFAULT_TPROXY_PORT),
                    "sniff": True,
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
            ],
            "route": {
                "rules": [
                    {"action": "sniff", "sniffer": ["tls", "http", "quic"]},
                    {"action": "hijack-dns", "protocol": "dns"},
                ],
                "final": "direct",
            },
            "experimental": {
                "clash_api": {
                    "external_controller": f"0.0.0.0:{safe_int_env('CLASH_API_PORT', DEFAULT_CLASH_API_PORT)}",
                }
            }
        }

    def _convert_outbound(self, ob: OutboundConfig) -> Optional[Dict[str, Any]]:
        """Convert OutboundConfig to sing-box format"""
        if ob.egress_type == EgressType.DIRECT:
            result = {
                "type": "direct",
                "tag": ob.tag,
            }
            if ob.bind_interface:
                result["bind_interface"] = ob.bind_interface
            if ob.bind_address:
                result["inet4_bind_address"] = ob.bind_address
            return result

        elif ob.egress_type == EgressType.BLOCK:
            return {
                "type": "block",
                "tag": ob.tag,
            }

        elif ob.egress_type in (EgressType.PIA, EgressType.CUSTOM, EgressType.WARP_WG, EgressType.PEER):
            # WireGuard: direct outbound with bind_interface
            return {
                "type": "direct",
                "tag": ob.tag,
                "bind_interface": ob.interface,
            }

        elif ob.egress_type == EgressType.V2RAY:
            # Phase 3: WARP_MASQUE removed - only V2Ray SOCKS5 remains
            # SOCKS5 outbound
            return {
                "type": "socks",
                "tag": ob.tag,
                "server": ob.socks_addr,
                "server_port": ob.socks_port,
            }

        elif ob.egress_type == EgressType.OPENVPN:
            return {
                "type": "direct",
                "tag": ob.tag,
                "bind_interface": ob.bind_interface,
            }

        else:
            logger.warning(f"Unknown egress type for sing-box: {ob.egress_type}")
            return None

    def _convert_rule(self, rule: RuleConfig) -> Optional[Dict[str, Any]]:
        """Convert RuleConfig to sing-box format"""
        if not rule.enabled:
            return None

        singbox_rule = {"outbound": rule.outbound}

        if rule.rule_type == RuleType.DOMAIN:
            singbox_rule["domain"] = [rule.target]
        elif rule.rule_type == RuleType.DOMAIN_SUFFIX:
            singbox_rule["domain_suffix"] = [rule.target]
        elif rule.rule_type == RuleType.DOMAIN_KEYWORD:
            singbox_rule["domain_keyword"] = [rule.target]
        elif rule.rule_type == RuleType.DOMAIN_REGEX:
            singbox_rule["domain_regex"] = [rule.target]
        elif rule.rule_type == RuleType.GEOIP:
            singbox_rule["geoip"] = [rule.target]
        elif rule.rule_type == RuleType.IP_CIDR:
            singbox_rule["ip_cidr"] = [rule.target]
        elif rule.rule_type == RuleType.PORT:
            singbox_rule["port"] = [int(rule.target)]
        elif rule.rule_type == RuleType.PROTOCOL:
            singbox_rule["protocol"] = [rule.target]
        elif rule.rule_type == RuleType.GEOSITE:
            singbox_rule["geosite"] = [rule.target]
        else:
            logger.warning(f"Unknown rule type for sing-box: {rule.rule_type}")
            return None

        return singbox_rule


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point for config generation"""
    parser = argparse.ArgumentParser(
        description="Generate routing configuration for rust-router and/or sing-box"
    )
    parser.add_argument(
        "--format", "-f",
        type=str,
        default="both",
        choices=["rust-router", "sing-box", "both"],
        help="Output format (default: both)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path (required for single format, ignored for 'both')"
    )
    parser.add_argument(
        "--rust-router-output",
        type=str,
        default="/etc/rust-router/config.json",
        help="rust-router output path (for --format=both)"
    )
    parser.add_argument(
        "--sing-box-output",
        type=str,
        default="/etc/sing-box/sing-box.generated.json",
        help="sing-box output path (for --format=both)"
    )
    parser.add_argument(
        "--geodata-db",
        type=str,
        default=os.environ.get("GEODATA_DB_PATH", DEFAULT_GEODATA_DB_PATH),
        help="Path to geoip database"
    )
    parser.add_argument(
        "--user-db",
        type=str,
        default=os.environ.get("USER_DB_PATH", DEFAULT_USER_DB_PATH),
        help="Path to user config database"
    )
    parser.add_argument(
        "--base-config",
        type=str,
        default=os.environ.get("SING_BOX_BASE_CONFIG", DEFAULT_SING_BOX_BASE_CONFIG),
        help="Path to sing-box base config template"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run unit tests"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print config to stdout instead of writing to file"
    )

    args = parser.parse_args()

    if args.test:
        return run_tests()

    # Load configuration from database
    loader = DatabaseLoader(args.geodata_db, args.user_db)
    config = loader.load_all()

    logger.info(f"Loaded {len(config.outbounds)} outbounds, {len(config.rules)} rules")

    # Generate output based on format
    output_format = OutputFormat(args.format)

    if output_format == OutputFormat.RUST_ROUTER:
        generator = RustRouterConfigGenerator()
        output = generator.generate(config)
        output_path = args.output or args.rust_router_output
        _write_output(output, output_path, args.dry_run)

    elif output_format == OutputFormat.SING_BOX:
        generator = SingBoxConfigGenerator(args.base_config)
        output = generator.generate(config)
        output_path = args.output or args.sing_box_output
        _write_output(output, output_path, args.dry_run)

    elif output_format == OutputFormat.BOTH:
        # Generate rust-router config
        rust_gen = RustRouterConfigGenerator()
        rust_output = rust_gen.generate(config)
        _write_output(rust_output, args.rust_router_output, args.dry_run, "rust-router")

        # Generate sing-box config
        singbox_gen = SingBoxConfigGenerator(args.base_config)
        singbox_output = singbox_gen.generate(config)
        _write_output(singbox_output, args.sing_box_output, args.dry_run, "sing-box")

    return 0


def _write_output(output: Dict[str, Any], path: str, dry_run: bool, label: str = "") -> None:
    """Write output to file or stdout.

    Args:
        output: Config dict to write
        path: Output file path
        dry_run: If True, print to stdout instead
        label: Optional label for output
    """
    json_str = json.dumps(output, indent=2, ensure_ascii=False)

    if dry_run:
        if label:
            print(f"\n=== {label} ===")
        print(json_str)
    else:
        # Ensure parent directory exists
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        # Write atomically
        tmp_path = f"{path}.tmp"
        with open(tmp_path, 'w') as f:
            f.write(json_str)
            f.write('\n')
        os.rename(tmp_path, path)

        logger.info(f"Written{' ' + label if label else ''} config to {path}")


# =============================================================================
# Unit Tests
# =============================================================================

def run_tests() -> int:
    """Run unit tests"""
    import unittest

    class TestOutputFormat(unittest.TestCase):
        """Test OutputFormat enum"""

        def test_values(self):
            self.assertEqual(OutputFormat.RUST_ROUTER.value, "rust-router")
            self.assertEqual(OutputFormat.SING_BOX.value, "sing-box")
            self.assertEqual(OutputFormat.BOTH.value, "both")

    class TestEgressType(unittest.TestCase):
        """Test EgressType enum"""

        def test_all_types(self):
            # Phase 3: WARP_MASQUE removed - 8 types total
            types = [EgressType.PIA, EgressType.CUSTOM, EgressType.WARP_WG,
                     EgressType.V2RAY, EgressType.OPENVPN,
                     EgressType.DIRECT, EgressType.BLOCK, EgressType.PEER]
            self.assertEqual(len(types), 8)

    class TestRuleType(unittest.TestCase):
        """Test RuleType enum"""

        def test_all_types(self):
            types = [RuleType.DOMAIN, RuleType.DOMAIN_SUFFIX, RuleType.DOMAIN_KEYWORD,
                     RuleType.DOMAIN_REGEX, RuleType.GEOIP, RuleType.IP_CIDR,
                     RuleType.PORT, RuleType.PROTOCOL, RuleType.GEOSITE]
            self.assertEqual(len(types), 9)

    class TestOutboundConfig(unittest.TestCase):
        """Test OutboundConfig dataclass"""

        def test_default_values(self):
            ob = OutboundConfig(tag="test", egress_type=EgressType.DIRECT)
            self.assertEqual(ob.tag, "test")
            self.assertTrue(ob.enabled)
            self.assertIsNone(ob.interface)

        def test_with_interface(self):
            ob = OutboundConfig(tag="test", egress_type=EgressType.PIA, interface="wg-pia-us")
            self.assertEqual(ob.interface, "wg-pia-us")

    class TestRuleConfig(unittest.TestCase):
        """Test RuleConfig dataclass"""

        def test_default_values(self):
            rule = RuleConfig(rule_type=RuleType.DOMAIN, target="google.com", outbound="proxy")
            self.assertEqual(rule.priority, 0)
            self.assertTrue(rule.enabled)

    class TestRoutingConfig(unittest.TestCase):
        """Test RoutingConfig dataclass"""

        def test_default_values(self):
            config = RoutingConfig()
            self.assertEqual(len(config.outbounds), 0)
            self.assertEqual(len(config.rules), 0)
            self.assertEqual(config.default_outbound, "direct")

    class TestInterfaceNameGeneration(unittest.TestCase):
        """Test interface name generation"""

        def test_short_tag(self):
            name = get_egress_interface_name_fallback("us", EgressType.PIA)
            self.assertEqual(name, "wg-pia-us")
            self.assertLessEqual(len(name), INTERFACE_MAX_LEN)

        def test_long_tag_hashed(self):
            long_tag = "very-long-tag-name-that-exceeds-limit"
            name = get_egress_interface_name_fallback(long_tag, EgressType.CUSTOM)
            self.assertLessEqual(len(name), INTERFACE_MAX_LEN)
            self.assertTrue(name.startswith("wg-eg-"))

        def test_warp_prefix(self):
            name = get_egress_interface_name_fallback("cf", EgressType.WARP_WG)
            self.assertEqual(name, "wg-warp-cf")

        def test_peer_prefix(self):
            name = get_egress_interface_name_fallback("node1", EgressType.PEER)
            self.assertEqual(name, "wg-peer-node1")

    class TestSafeIntEnv(unittest.TestCase):
        """Test safe_int_env function"""

        def test_default(self):
            result = safe_int_env("NONEXISTENT_VAR_12345", 42)
            self.assertEqual(result, 42)

        def test_valid_value(self):
            os.environ["TEST_INT_VAR"] = "123"
            try:
                result = safe_int_env("TEST_INT_VAR", 0)
                self.assertEqual(result, 123)
            finally:
                del os.environ["TEST_INT_VAR"]

        def test_invalid_value(self):
            os.environ["TEST_INT_VAR"] = "not_a_number"
            try:
                result = safe_int_env("TEST_INT_VAR", 99)
                self.assertEqual(result, 99)
            finally:
                del os.environ["TEST_INT_VAR"]

    class TestRustRouterConfigGenerator(unittest.TestCase):
        """Test RustRouterConfigGenerator"""

        def test_generate_empty(self):
            gen = RustRouterConfigGenerator()
            config = RoutingConfig()
            output = gen.generate(config)
            self.assertIn("version", output)
            self.assertIn("outbounds", output)
            self.assertIn("routing", output)

        def test_generate_with_outbounds(self):
            gen = RustRouterConfigGenerator()
            config = RoutingConfig(
                outbounds=[
                    OutboundConfig(tag="direct", egress_type=EgressType.DIRECT),
                    OutboundConfig(tag="block", egress_type=EgressType.BLOCK),
                    OutboundConfig(tag="us-east", egress_type=EgressType.PIA, interface="wg-pia-us-east"),
                ],
                default_outbound="direct"
            )
            output = gen.generate(config)
            self.assertEqual(len(output["outbounds"]), 3)

        def test_socks5_outbound(self):
            gen = RustRouterConfigGenerator()
            config = RoutingConfig(
                outbounds=[
                    OutboundConfig(
                        tag="v2ray-jp",
                        egress_type=EgressType.V2RAY,
                        socks_addr="127.0.0.1",
                        socks_port=37101
                    ),
                ]
            )
            output = gen.generate(config)
            ob = output["outbounds"][0]
            self.assertEqual(ob["type"], "socks5")
            self.assertEqual(ob["server_addr"], "127.0.0.1:37101")

    class TestSingBoxConfigGenerator(unittest.TestCase):
        """Test SingBoxConfigGenerator"""

        def test_default_base_config(self):
            gen = SingBoxConfigGenerator("/nonexistent/path.json")
            base = gen._default_base_config()
            self.assertIn("log", base)
            self.assertIn("inbounds", base)
            self.assertIn("outbounds", base)
            self.assertIn("route", base)

        def test_convert_direct_outbound(self):
            gen = SingBoxConfigGenerator("/nonexistent")
            ob = OutboundConfig(tag="direct", egress_type=EgressType.DIRECT)
            result = gen._convert_outbound(ob)
            self.assertEqual(result["type"], "direct")
            self.assertEqual(result["tag"], "direct")

        def test_convert_wireguard_outbound(self):
            gen = SingBoxConfigGenerator("/nonexistent")
            ob = OutboundConfig(tag="us", egress_type=EgressType.PIA, interface="wg-pia-us")
            result = gen._convert_outbound(ob)
            self.assertEqual(result["type"], "direct")
            self.assertEqual(result["bind_interface"], "wg-pia-us")

        def test_convert_socks_outbound(self):
            gen = SingBoxConfigGenerator("/nonexistent")
            ob = OutboundConfig(
                tag="proxy",
                egress_type=EgressType.V2RAY,
                socks_addr="127.0.0.1",
                socks_port=37101
            )
            result = gen._convert_outbound(ob)
            self.assertEqual(result["type"], "socks")
            self.assertEqual(result["server_port"], 37101)

        def test_convert_domain_rule(self):
            gen = SingBoxConfigGenerator("/nonexistent")
            rule = RuleConfig(
                rule_type=RuleType.DOMAIN,
                target="google.com",
                outbound="proxy"
            )
            result = gen._convert_rule(rule)
            self.assertEqual(result["domain"], ["google.com"])
            self.assertEqual(result["outbound"], "proxy")

        def test_convert_geoip_rule(self):
            gen = SingBoxConfigGenerator("/nonexistent")
            rule = RuleConfig(
                rule_type=RuleType.GEOIP,
                target="CN",
                outbound="cn-direct"
            )
            result = gen._convert_rule(rule)
            self.assertEqual(result["geoip"], ["CN"])

        def test_disabled_rule_skipped(self):
            gen = SingBoxConfigGenerator("/nonexistent")
            rule = RuleConfig(
                rule_type=RuleType.DOMAIN,
                target="test.com",
                outbound="proxy",
                enabled=False
            )
            result = gen._convert_rule(rule)
            self.assertIsNone(result)

    class TestValidation(unittest.TestCase):
        """Test validation functions"""

        def test_port_validation_valid(self):
            """Test valid port numbers"""
            self.assertTrue(validate_port(80, "http"))
            self.assertTrue(validate_port(443, "https"))
            self.assertTrue(validate_port(1, "min"))
            self.assertTrue(validate_port(65535, "max"))

        def test_port_validation_invalid(self):
            """Test invalid port numbers"""
            self.assertFalse(validate_port(0, "zero"))
            self.assertFalse(validate_port(-1, "negative"))
            self.assertFalse(validate_port(65536, "overflow"))
            self.assertFalse(validate_port(99999, "too large"))

        def test_port_validation_non_integer(self):
            """Test non-integer port values"""
            self.assertFalse(validate_port("80", "string"))  # type: ignore
            self.assertFalse(validate_port(None, "none"))  # type: ignore

        def test_interface_name_validation_valid(self):
            """Test valid interface names"""
            self.assertTrue(validate_interface_name("wg0", "wireguard"))
            self.assertTrue(validate_interface_name("eth0", "ethernet"))
            self.assertTrue(validate_interface_name("wg-pia-us", "pia"))
            self.assertTrue(validate_interface_name("tun0", "tunnel"))

        def test_interface_name_validation_invalid(self):
            """Test invalid interface names"""
            self.assertFalse(validate_interface_name("", "empty"))
            self.assertFalse(validate_interface_name("0eth", "starts with number"))
            self.assertFalse(validate_interface_name("this-is-a-very-long-interface-name", "too long"))

    class TestDatabaseLoader(unittest.TestCase):
        """Test DatabaseLoader with mocks"""

        def test_database_loader_get_pia_profiles(self):
            """Test loading PIA profiles from mock DB"""
            from unittest.mock import MagicMock, patch

            mock_db = MagicMock()
            mock_db.get_pia_profiles.return_value = [
                {"name": "us-east", "private_key": "key1", "enabled": True},
                {"name": "eu-west", "private_key": "key2", "enabled": True},
            ]

            loader = DatabaseLoader("/test/geoip.db", "/test/user.db")
            loader._db = mock_db

            with patch.object(loader, '_get_db', return_value=mock_db):
                outbounds = loader.load_pia_profiles()

            self.assertEqual(len(outbounds), 2)
            self.assertEqual(outbounds[0].tag, "us-east")
            self.assertEqual(outbounds[0].egress_type, EgressType.PIA)

        def test_database_loader_get_custom_egress(self):
            """Test loading custom WireGuard egress from mock DB"""
            from unittest.mock import MagicMock, patch

            mock_db = MagicMock()
            mock_db.get_custom_egress_list.return_value = [
                {"tag": "custom1", "enabled": True},
                {"tag": "custom2", "enabled": True},
            ]

            loader = DatabaseLoader("/test/geoip.db", "/test/user.db")
            loader._db = mock_db

            with patch.object(loader, '_get_db', return_value=mock_db):
                outbounds = loader.load_custom_wireguard()

            self.assertEqual(len(outbounds), 2)
            self.assertEqual(outbounds[0].tag, "custom1")
            self.assertEqual(outbounds[0].egress_type, EgressType.CUSTOM)

        def test_database_loader_get_v2ray_egress(self):
            """Test loading V2Ray egress from mock DB"""
            from unittest.mock import MagicMock, patch

            mock_db = MagicMock()
            mock_db.get_v2ray_egress_list.return_value = [
                {"tag": "v2ray-jp", "socks_port": 37101, "enabled": True},
            ]

            loader = DatabaseLoader("/test/geoip.db", "/test/user.db")
            loader._db = mock_db

            with patch.object(loader, '_get_db', return_value=mock_db):
                outbounds = loader.load_v2ray_egress()

            self.assertEqual(len(outbounds), 1)
            self.assertEqual(outbounds[0].socks_port, 37101)

        def test_database_loader_get_warp_egress(self):
            """Test loading WARP egress from mock DB (Phase 3: WireGuard only)"""
            from unittest.mock import MagicMock, patch

            mock_db = MagicMock()
            mock_db.get_warp_egress_list.return_value = [
                {"tag": "warp-wg", "protocol": "wireguard", "enabled": True},
                # Phase 3: MASQUE support removed
            ]

            loader = DatabaseLoader("/test/geoip.db", "/test/user.db")
            loader._db = mock_db

            with patch.object(loader, '_get_db', return_value=mock_db):
                outbounds = loader.load_warp_egress()

            self.assertEqual(len(outbounds), 1)
            self.assertEqual(outbounds[0].egress_type, EgressType.WARP_WG)

        def test_database_loader_get_rules(self):
            """Test loading routing rules from mock DB"""
            from unittest.mock import MagicMock, patch

            mock_db = MagicMock()
            mock_db.get_routing_rules.return_value = [
                {"rule_type": "domain", "target": "google.com", "outbound": "proxy", "priority": 1},
                {"rule_type": "geoip", "target": "CN", "outbound": "direct", "priority": 2},
            ]

            loader = DatabaseLoader("/test/geoip.db", "/test/user.db")
            loader._db = mock_db

            with patch.object(loader, '_get_db', return_value=mock_db):
                rules = loader.load_routing_rules()

            self.assertEqual(len(rules), 2)
            self.assertEqual(rules[0].rule_type, RuleType.DOMAIN)
            self.assertEqual(rules[1].rule_type, RuleType.GEOIP)

        def test_database_loader_connection_error(self):
            """Test database loader logs error and returns empty on connection failure"""
            from unittest.mock import MagicMock, patch

            mock_db = MagicMock()
            mock_db.get_pia_profiles.side_effect = Exception("Database connection failed")

            loader = DatabaseLoader("/test/geoip.db", "/test/user.db")
            loader._db = mock_db

            with patch.object(loader, '_get_db', return_value=mock_db):
                outbounds = loader.load_pia_profiles()

            # Should return empty list, not raise exception
            self.assertEqual(len(outbounds), 0)

        def test_database_loader_no_db(self):
            """Test database loader returns empty when DB unavailable"""
            loader = DatabaseLoader("/test/geoip.db", "/test/user.db")
            loader._db = None

            outbounds = loader.load_pia_profiles()
            self.assertEqual(len(outbounds), 0)

    class TestAtomicFileWrite(unittest.TestCase):
        """Test atomic file writing"""

        def test_atomic_file_write_success(self):
            """Test successful atomic file write"""
            import tempfile
            import os

            output = {"test": "data"}
            with tempfile.TemporaryDirectory() as tmpdir:
                path = os.path.join(tmpdir, "test.json")
                _write_output(output, path, dry_run=False)

                # Verify file was written
                self.assertTrue(os.path.exists(path))
                with open(path) as f:
                    content = json.load(f)
                self.assertEqual(content["test"], "data")

        def test_atomic_file_write_creates_parent_dirs(self):
            """Test atomic write creates parent directories"""
            import tempfile
            import os

            output = {"test": "nested"}
            with tempfile.TemporaryDirectory() as tmpdir:
                path = os.path.join(tmpdir, "nested", "dir", "test.json")
                _write_output(output, path, dry_run=False)

                self.assertTrue(os.path.exists(path))

        def test_dry_run_no_file_created(self):
            """Test dry run doesn't create file"""
            import tempfile
            import os
            from io import StringIO
            import sys

            output = {"test": "dry_run"}
            with tempfile.TemporaryDirectory() as tmpdir:
                path = os.path.join(tmpdir, "test.json")

                # Capture stdout
                old_stdout = sys.stdout
                sys.stdout = StringIO()
                try:
                    _write_output(output, path, dry_run=True)
                    printed = sys.stdout.getvalue()
                finally:
                    sys.stdout = old_stdout

                # File should not exist
                self.assertFalse(os.path.exists(path))
                # JSON should be printed
                self.assertIn('"test"', printed)

    class TestCLIParsing(unittest.TestCase):
        """Test CLI argument parsing"""

        def test_cli_format_rust_router(self):
            """Test CLI parsing for rust-router format"""
            # Just test the OutputFormat enum parsing
            fmt = OutputFormat("rust-router")
            self.assertEqual(fmt, OutputFormat.RUST_ROUTER)

        def test_cli_format_sing_box(self):
            """Test CLI parsing for sing-box format"""
            fmt = OutputFormat("sing-box")
            self.assertEqual(fmt, OutputFormat.SING_BOX)

        def test_cli_format_both(self):
            """Test CLI parsing for both formats"""
            fmt = OutputFormat("both")
            self.assertEqual(fmt, OutputFormat.BOTH)

    class TestUnknownEgressHandling(unittest.TestCase):
        """Test handling of unknown egress types"""

        def test_rust_router_unknown_egress_type(self):
            """Test RustRouterConfigGenerator handles unknown egress gracefully"""
            gen = RustRouterConfigGenerator()

            # Create a mock egress type by modifying the enum value directly
            ob = OutboundConfig(tag="unknown", egress_type=EgressType.DIRECT)
            # Override the type to simulate an unknown type scenario
            result = gen._convert_outbound(ob)

            # Should return a direct outbound for DIRECT type
            self.assertIsNotNone(result)
            self.assertEqual(result["type"], "direct")

        def test_singbox_unknown_rule_type(self):
            """Test SingBoxConfigGenerator handles unknown rule types"""
            gen = SingBoxConfigGenerator("/nonexistent")

            # This tests the fallback path
            rule = RuleConfig(
                rule_type=RuleType.DOMAIN,
                target="test.com",
                outbound="proxy"
            )
            result = gen._convert_rule(rule)
            self.assertIsNotNone(result)

    class TestPortValidationInLoaders(unittest.TestCase):
        """Test port validation is applied in database loaders"""

        def test_v2ray_loader_rejects_invalid_port(self):
            """Test V2Ray loader skips entries with invalid ports"""
            from unittest.mock import MagicMock, patch

            mock_db = MagicMock()
            mock_db.get_v2ray_egress_list.return_value = [
                {"tag": "valid", "socks_port": 37101, "enabled": True},
                {"tag": "invalid", "socks_port": 99999, "enabled": True},  # Invalid port
                {"tag": "zero", "socks_port": 0, "enabled": True},  # Invalid port
            ]

            loader = DatabaseLoader("/test/geoip.db", "/test/user.db")
            loader._db = mock_db

            with patch.object(loader, '_get_db', return_value=mock_db):
                outbounds = loader.load_v2ray_egress()

            # Only valid entry should be loaded
            self.assertEqual(len(outbounds), 1)
            self.assertEqual(outbounds[0].tag, "valid")

        # Phase 3: test_warp_masque_loader_rejects_invalid_port removed (MASQUE deprecated)

    # Run tests
    print("Running render_routing_config unit tests...")
    print("=" * 60)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestOutputFormat))
    suite.addTests(loader.loadTestsFromTestCase(TestEgressType))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleType))
    suite.addTests(loader.loadTestsFromTestCase(TestOutboundConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestRoutingConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestInterfaceNameGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestSafeIntEnv))
    suite.addTests(loader.loadTestsFromTestCase(TestRustRouterConfigGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestSingBoxConfigGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseLoader))
    suite.addTests(loader.loadTestsFromTestCase(TestAtomicFileWrite))
    suite.addTests(loader.loadTestsFromTestCase(TestCLIParsing))
    suite.addTests(loader.loadTestsFromTestCase(TestUnknownEgressHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestPortValidationInLoaders))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
