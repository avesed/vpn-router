#!/usr/bin/env python3
"""
Async Rule Loader Module

Provides asynchronous loading of binary rule sets with:
- Concurrent loading of multiple rule sets
- Per-set locking to prevent duplicate loads
- Database status tracking
- Error handling with recovery
- Thread-safe access to loaded rules

Loading SLA:
- Phase 1 (<500ms): API available
- Phase 2 (<1s): Core routing rules
- Phase 3 (<5s): Large GeoIP sets (background)

Usage:
    from rule_loader import AsyncRuleLoader
    from db_helper import get_db

    db = get_db()
    loader = AsyncRuleLoader(Path("/data/rules"), db)

    # Start background loading
    await loader.start_background_load()

    # Wait for initial load to complete
    await loader.wait_for_load(timeout=5.0)

    # Get all loaded rules for RuleEngine
    rules = loader.get_all_rules()
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# Import logging utilities
try:
    from log_config import get_logger
except ImportError:
    import logging
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)

# Import rule binary reader
from rule_binary import (
    read_rule_binary,
    validate_rule_binary,
    RuleBinaryError,
    RuleBinaryCorruptionError,
    RuleBinaryChecksumError,
)

# Import adblock converter for remote rule sets
from convert_adblock import convert_to_binary

# Import database manager type for type hints
from db_helper import DatabaseManager

# Module logger
logger = get_logger(__name__)


# Rule set status constants (matching db_helper.VALID_RULE_SET_STATUSES)
class RuleSetStatus:
    """Status values for rule sets."""
    PENDING = "pending"
    LOADING = "loading"
    LOADED = "loaded"
    ERROR = "error"


# Remote rule set status constants (downloading phase added)
class RemoteRuleSetStatus:
    """Status values for remote rule sets (adblock)."""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    LOADED = "loaded"
    ERROR = "error"


# Priority tiers for loading order
class LoadPriority:
    """Priority tiers for rule set loading order."""
    CRITICAL = 100  # Core rules needed immediately
    HIGH = 75       # Important rules for routing
    NORMAL = 50     # Standard rules
    LOW = 25        # Background rules (GeoIP, large sets)
    BACKGROUND = 0  # Optional/auxiliary rules


@dataclass
class LoadResult:
    """Result of loading a single rule set."""
    set_id: str
    success: bool
    rule_count: int = 0
    load_time_ms: float = 0.0
    error_message: Optional[str] = None


@dataclass
class LoaderStats:
    """Statistics for the rule loader."""
    loaded_count: int = 0
    failed_count: int = 0
    total_rules: int = 0
    total_load_time_ms: float = 0.0
    last_load_started: Optional[datetime] = None
    last_load_completed: Optional[datetime] = None
    load_in_progress: bool = False
    pending_sets: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "loaded_count": self.loaded_count,
            "failed_count": self.failed_count,
            "total_rules": self.total_rules,
            "total_load_time_ms": round(self.total_load_time_ms, 2),
            "last_load_started": self.last_load_started.isoformat() if self.last_load_started else None,
            "last_load_completed": self.last_load_completed.isoformat() if self.last_load_completed else None,
            "load_in_progress": self.load_in_progress,
            "pending_sets": self.pending_sets,
        }


class AsyncRuleLoader:
    """
    Asynchronous rule set loader with concurrent loading and status tracking.

    Thread-safe for reading loaded rules; writing is protected by per-set locks.
    """

    def __init__(
        self,
        rules_dir: Path,
        db: DatabaseManager,
        max_concurrent_loads: int = 4,
    ):
        """
        Initialize the async rule loader.

        Args:
            rules_dir: Directory containing binary rule files
            db: DatabaseManager instance for status tracking
            max_concurrent_loads: Maximum concurrent file loads
        """
        self.rules_dir = Path(rules_dir)
        self.db = db
        self.max_concurrent_loads = max_concurrent_loads

        # Loaded rule data: set_id -> rule data dict
        self._loaded_sets: Dict[str, dict] = {}

        # Loaded remote rule data: tag -> rule data dict
        self._loaded_remote_sets: Dict[str, dict] = {}

        # Per-set locks to prevent duplicate loads
        self._locks: Dict[str, asyncio.Lock] = {}

        # Global lock for managing the locks dict
        self._global_lock = asyncio.Lock()

        # Semaphore to limit concurrent file I/O
        self._load_semaphore = asyncio.Semaphore(max_concurrent_loads)

        # Event signaling initial load completion
        self._load_complete = asyncio.Event()

        # Statistics
        self._stats = LoaderStats()

        # Background task reference
        self._background_task: Optional[asyncio.Task] = None

        # Callbacks for load events
        self._on_load_callbacks: List[Callable[[str, bool], None]] = []

        logger.info(
            "AsyncRuleLoader initialized: rules_dir=%s, max_concurrent=%d",
            self.rules_dir, max_concurrent_loads
        )

    async def _get_lock(self, set_id: str) -> asyncio.Lock:
        """
        Get or create a lock for a specific rule set.

        Args:
            set_id: Rule set identifier

        Returns:
            asyncio.Lock for the specified set
        """
        async with self._global_lock:
            if set_id not in self._locks:
                self._locks[set_id] = asyncio.Lock()
            return self._locks[set_id]

    async def get_lock(self, set_id: str) -> asyncio.Lock:
        """
        Get or create lock for a set (for external atomic operations).

        This allows external code to coordinate with the loader for
        operations that need to be atomic with respect to loading.

        Args:
            set_id: Rule set identifier

        Returns:
            asyncio.Lock for the specified set
        """
        return await self._get_lock(set_id)

    def _update_db_status(
        self,
        set_id: str,
        status: str,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Update rule set status in database.

        Args:
            set_id: Rule set identifier
            status: New status value
            error_message: Optional error message for error status

        Returns:
            True if update succeeded
        """
        try:
            return self.db.update_rule_set_status(set_id, status, error_message)
        except Exception as e:
            logger.error("Failed to update status for %s: %s", set_id, e)
            return False

    async def _load_file(self, file_path: Path, checksum: Optional[str] = None) -> dict:
        """
        Load a binary rule file asynchronously.

        Uses asyncio.to_thread() to avoid blocking the event loop.

        Args:
            file_path: Path to the binary rule file
            checksum: Optional expected checksum for verification

        Returns:
            Loaded rule data dictionary

        Raises:
            FileNotFoundError: If file does not exist
            RuleBinaryError: If file is invalid or corrupted
        """
        return await asyncio.to_thread(
            read_rule_binary, str(file_path), checksum
        )

    async def load_rule_set(self, set_id: str) -> bool:
        """
        Load a specific rule set with lock protection.

        If the set is already loaded, returns immediately.
        If another coroutine is loading this set, waits for it to complete.

        Args:
            set_id: Rule set identifier

        Returns:
            True if loading succeeded (or was already loaded)
        """
        lock = await self._get_lock(set_id)

        async with lock:
            # Check if already loaded
            if set_id in self._loaded_sets:
                logger.debug("Rule set %s already loaded", set_id)
                return True

            # Get rule set info from database
            rule_set = self.db.get_rule_set(set_id)
            if not rule_set:
                logger.warning("Rule set not found in database: %s", set_id)
                return False

            # Skip disabled sets
            if not rule_set.get("enabled", True):
                logger.debug("Rule set %s is disabled, skipping", set_id)
                return False

            # Build file path
            file_path = self.rules_dir / rule_set["file_path"]
            checksum = rule_set.get("checksum")

            # Update status to loading
            self._update_db_status(set_id, RuleSetStatus.LOADING)

            start_time = time.monotonic()

            try:
                # Acquire semaphore to limit concurrent I/O
                async with self._load_semaphore:
                    logger.debug("Loading rule set %s from %s", set_id, file_path)

                    # Load the file
                    data = await self._load_file(file_path, checksum)

                # Store loaded data
                self._loaded_sets[set_id] = data

                # Calculate load time
                load_time_ms = (time.monotonic() - start_time) * 1000

                # Update statistics
                rule_count = len(data.get("rules", []))
                self._stats.loaded_count += 1
                self._stats.total_rules += rule_count
                self._stats.total_load_time_ms += load_time_ms

                # Update database status
                self._update_db_status(set_id, RuleSetStatus.LOADED)

                logger.info(
                    "Loaded rule set %s: %d rules in %.1fms",
                    set_id, rule_count, load_time_ms
                )

                # Notify callbacks
                for callback in self._on_load_callbacks:
                    try:
                        callback(set_id, True)
                    except Exception as e:
                        logger.error("Load callback error: %s", e)

                return True

            except FileNotFoundError as e:
                error_msg = f"File not found: {file_path}"
                logger.error("Failed to load %s: %s", set_id, error_msg)
                self._update_db_status(set_id, RuleSetStatus.ERROR, error_msg)
                self._stats.failed_count += 1
                return False

            except (RuleBinaryCorruptionError, RuleBinaryChecksumError) as e:
                error_msg = f"Corrupted file: {e}"
                logger.error("Failed to load %s: %s", set_id, error_msg)
                self._update_db_status(set_id, RuleSetStatus.ERROR, error_msg)
                self._stats.failed_count += 1
                return False

            except RuleBinaryError as e:
                error_msg = f"Binary read error: {e}"
                logger.error("Failed to load %s: %s", set_id, error_msg)
                self._update_db_status(set_id, RuleSetStatus.ERROR, error_msg)
                self._stats.failed_count += 1
                return False

            except Exception as e:
                error_msg = f"Unexpected error: {type(e).__name__}: {e}"
                logger.exception("Unexpected error loading %s", set_id)
                self._update_db_status(set_id, RuleSetStatus.ERROR, error_msg)
                self._stats.failed_count += 1
                return False

    async def reload_rule_set(self, set_id: str) -> bool:
        """
        Reload a rule set (force refresh).

        Unloads the set if loaded, then loads it again.

        Args:
            set_id: Rule set identifier

        Returns:
            True if reload succeeded
        """
        lock = await self._get_lock(set_id)

        async with lock:
            # Remove from loaded sets if present
            old_data = self._loaded_sets.pop(set_id, None)

            if old_data:
                # Adjust statistics
                old_count = len(old_data.get("rules", []))
                self._stats.loaded_count -= 1
                self._stats.total_rules -= old_count
                logger.debug("Unloaded %s for reload (%d rules)", set_id, old_count)

        # Load fresh
        return await self.load_rule_set(set_id)

    async def unload_rule_set(self, set_id: str) -> bool:
        """
        Unload a rule set from memory.

        Args:
            set_id: Rule set identifier

        Returns:
            True if the set was unloaded (False if not loaded)
        """
        lock = await self._get_lock(set_id)

        async with lock:
            if set_id not in self._loaded_sets:
                logger.debug("Rule set %s not loaded, nothing to unload", set_id)
                return False

            # Remove from loaded sets
            data = self._loaded_sets.pop(set_id)
            rule_count = len(data.get("rules", []))

            # Adjust statistics
            self._stats.loaded_count -= 1
            self._stats.total_rules -= rule_count

            # Update database status back to pending
            self._update_db_status(set_id, RuleSetStatus.PENDING)

            logger.info("Unloaded rule set %s (%d rules)", set_id, rule_count)
            return True

    def get_all_rules(self) -> List[Dict[str, Any]]:
        """
        Get all loaded rules for RuleEngine synchronization.

        Returns a flattened list of rule entries with metadata.
        Includes both local rule sets and remote rule sets (adblock).
        Thread-safe for reading.

        Returns:
            List of rule dictionaries with structure:
            {
                "set_id": str,
                "rule_type": str,
                "outbound": str,
                "rule": str,
                "priority": int (optional),
                "source": str ("local" or "remote")
            }
        """
        rules = []

        # Local rule sets
        for set_id, data in self._loaded_sets.items():
            rule_type = data.get("rule_type", "domain")
            outbound = data.get("outbound", "direct")
            tag = data.get("tag")

            # Get priority from database if available
            rule_set = self.db.get_rule_set(set_id)
            priority = rule_set.get("priority", 0) if rule_set else 0

            for rule in data.get("rules", []):
                entry = {
                    "set_id": set_id,
                    "rule_type": rule_type,
                    "outbound": outbound,
                    "rule": rule,
                    "source": "local",
                }
                if priority != 0:
                    entry["priority"] = priority
                if tag:
                    entry["tag"] = tag
                rules.append(entry)

        # Remote rule sets (adblock)
        for tag, data in self._loaded_remote_sets.items():
            rule_type = data.get("rule_type", "domain_suffix")
            outbound = data.get("outbound", "block")

            for rule in data.get("rules", []):
                entry = {
                    "set_id": f"remote:{tag}",
                    "rule_type": rule_type,
                    "outbound": outbound,
                    "rule": rule,
                    "source": "remote",
                }
                rules.append(entry)

        return rules

    def get_loaded_set_ids(self) -> List[str]:
        """
        Get list of loaded set IDs.

        Returns:
            List of set identifiers that are currently loaded
        """
        return list(self._loaded_sets.keys())

    def is_loaded(self, set_id: str) -> bool:
        """
        Check if a set is loaded.

        Args:
            set_id: Rule set identifier

        Returns:
            True if the set is loaded in memory
        """
        return set_id in self._loaded_sets

    def get_loaded_set(self, set_id: str) -> Optional[dict]:
        """
        Get loaded rule set data.

        Args:
            set_id: Rule set identifier

        Returns:
            Rule set data if loaded, None otherwise
        """
        return self._loaded_sets.get(set_id)

    async def wait_for_load(self, timeout: float = 5.0) -> bool:
        """
        Wait for initial loading to complete.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if loading completed, False if timeout
        """
        try:
            await asyncio.wait_for(
                self._load_complete.wait(),
                timeout=timeout
            )
            return True
        except asyncio.TimeoutError:
            logger.warning("Timed out waiting for rule load after %.1fs", timeout)
            return False

    def get_stats(self) -> Dict[str, Any]:
        """
        Get loader statistics.

        Returns:
            Dictionary with loader statistics
        """
        return self._stats.to_dict()

    def add_load_callback(self, callback: Callable[[str, bool], None]) -> None:
        """
        Add a callback for load events.

        Callback is called with (set_id, success) after each load attempt.

        Args:
            callback: Function to call on load events
        """
        self._on_load_callbacks.append(callback)

    def remove_load_callback(self, callback: Callable[[str, bool], None]) -> None:
        """
        Remove a load callback.

        Args:
            callback: Previously added callback function
        """
        try:
            self._on_load_callbacks.remove(callback)
        except ValueError:
            pass

    async def start_background_load(self) -> None:
        """
        Start loading all enabled rule sets in background.

        Loads rule sets in priority order:
        1. Phase 1 (<500ms): High priority (critical routing rules)
        2. Phase 2 (<1s): Normal priority (standard rules)
        3. Phase 3 (<5s): Low priority (large GeoIP sets)

        Raises:
            RuntimeError: If background load is already running
        """
        if self._background_task and not self._background_task.done():
            raise RuntimeError("Background load already in progress")

        self._background_task = asyncio.create_task(
            self._background_load_impl(),
            name="rule_loader_background"
        )

    async def _background_load_impl(self) -> None:
        """Implementation of background loading."""
        self._stats.load_in_progress = True
        self._stats.last_load_started = datetime.now(timezone.utc)
        self._load_complete.clear()

        logger.info("Starting background rule load from %s", self.rules_dir)

        try:
            # Get all enabled rule sets from database
            rule_sets = self.db.get_rule_sets(enabled_only=True)

            if not rule_sets:
                logger.info("No enabled rule sets to load")
                self._load_complete.set()
                return

            # Sort by priority (highest first)
            rule_sets.sort(key=lambda x: x.get("priority", 0), reverse=True)

            self._stats.pending_sets = len(rule_sets)

            logger.info("Loading %d enabled rule sets", len(rule_sets))

            # Group by priority tiers
            high_priority = []
            normal_priority = []
            low_priority = []

            for rs in rule_sets:
                priority = rs.get("priority", 0)
                set_id = rs["id"]

                if priority >= LoadPriority.HIGH:
                    high_priority.append(set_id)
                elif priority >= LoadPriority.NORMAL:
                    normal_priority.append(set_id)
                else:
                    low_priority.append(set_id)

            # Phase 1: Load high priority sets (target <500ms)
            if high_priority:
                logger.info("Phase 1: Loading %d high priority sets", len(high_priority))
                phase1_start = time.monotonic()

                await asyncio.gather(
                    *[self.load_rule_set(set_id) for set_id in high_priority],
                    return_exceptions=True
                )

                phase1_time = (time.monotonic() - phase1_start) * 1000
                logger.info("Phase 1 completed in %.1fms", phase1_time)

            # Phase 2: Load normal priority sets (target <1s)
            if normal_priority:
                logger.info("Phase 2: Loading %d normal priority sets", len(normal_priority))
                phase2_start = time.monotonic()

                await asyncio.gather(
                    *[self.load_rule_set(set_id) for set_id in normal_priority],
                    return_exceptions=True
                )

                phase2_time = (time.monotonic() - phase2_start) * 1000
                logger.info("Phase 2 completed in %.1fms", phase2_time)

            # Phase 3: Load low priority sets (target <5s, background)
            if low_priority:
                logger.info("Phase 3: Loading %d low priority sets", len(low_priority))
                phase3_start = time.monotonic()

                await asyncio.gather(
                    *[self.load_rule_set(set_id) for set_id in low_priority],
                    return_exceptions=True
                )

                phase3_time = (time.monotonic() - phase3_start) * 1000
                logger.info("Phase 3 completed in %.1fms", phase3_time)

            # Phase 4: Load remote rule sets (adblock) - background, may require downloads
            remote_sets = self.db.get_remote_rule_sets(enabled_only=True)

            if remote_sets:
                logger.info("Phase 4: Loading %d remote rule sets", len(remote_sets))
                phase4_start = time.monotonic()

                await asyncio.gather(
                    *[self.load_remote_rule_set(rs["tag"]) for rs in remote_sets],
                    return_exceptions=True
                )

                phase4_time = (time.monotonic() - phase4_start) * 1000
                logger.info("Phase 4 completed in %.1fms", phase4_time)

            self._stats.pending_sets = 0
            self._stats.last_load_completed = datetime.now(timezone.utc)

            logger.info(
                "Background load complete: %d loaded, %d failed, %d total rules",
                self._stats.loaded_count,
                self._stats.failed_count,
                self._stats.total_rules
            )

        except asyncio.CancelledError:
            logger.warning("Background load cancelled")
            raise

        except Exception as e:
            logger.exception("Background load failed: %s", e)

        finally:
            self._stats.load_in_progress = False
            self._load_complete.set()

    async def cancel_background_load(self) -> None:
        """Cancel any running background load."""
        if self._background_task and not self._background_task.done():
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
            logger.info("Background load cancelled")

    async def reload_all(self) -> Dict[str, bool]:
        """
        Reload all enabled rule sets.

        Returns:
            Dictionary mapping set_id to reload success status
        """
        results = {}

        # Get all enabled rule sets
        rule_sets = self.db.get_rule_sets(enabled_only=True)

        for rs in rule_sets:
            set_id = rs["id"]
            results[set_id] = await self.reload_rule_set(set_id)

        return results

    # ========================================================================
    # Remote Rule Sets (adblock) - Download from URL, convert to binary
    # ========================================================================

    def _update_remote_db_status(
        self,
        tag: str,
        status: str,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Update remote rule set status in database.

        Args:
            tag: Remote rule set tag
            status: New status value
            error_message: Optional error message for error status

        Returns:
            True if update succeeded
        """
        try:
            return self.db.update_remote_rule_set_status(tag, status, error_message)
        except Exception as e:
            logger.error("Failed to update remote status for %s: %s", tag, e)
            return False

    async def _download_and_convert_remote(
        self,
        tag: str,
        url: str,
        format: str,
        outbound: str
    ) -> Tuple[Optional[str], int]:
        """
        Download and convert remote rule set to binary.

        Uses asyncio.to_thread() to avoid blocking the event loop.

        Args:
            tag: Rule set tag
            url: URL to download from
            format: Source format (adblock, hosts, domains)
            outbound: Outbound tag for matched rules

        Returns:
            (checksum, rule_count) tuple, checksum is None on failure
        """
        file_name = f"remote-{tag}.bin"
        file_path = self.rules_dir / file_name

        # Run blocking download/convert in thread pool
        return await asyncio.to_thread(
            convert_to_binary, url, format, file_path, outbound
        )

    async def load_remote_rule_set(self, tag: str, force_download: bool = False) -> bool:
        """
        Load a remote rule set (download if needed, then load binary).

        If the set is already loaded and not forcing download, returns immediately.
        If another coroutine is loading this set, waits for it to complete.

        Args:
            tag: Remote rule set tag
            force_download: Force re-download even if file exists

        Returns:
            True if loading succeeded (or was already loaded)
        """
        lock = await self._get_lock(f"remote:{tag}")

        async with lock:
            # Check if already loaded (and not forcing)
            if tag in self._loaded_remote_sets and not force_download:
                logger.debug("Remote rule set %s already loaded", tag)
                return True

            # Get remote rule set info from database
            rule_set = self.db.get_remote_rule_set(tag)
            if not rule_set:
                logger.warning("Remote rule set not found in database: %s", tag)
                return False

            # Skip disabled sets
            if not rule_set.get("enabled", True):
                logger.debug("Remote rule set %s is disabled, skipping", tag)
                return False

            url = rule_set.get("url")
            if not url:
                logger.error("Remote rule set %s has no URL", tag)
                return False

            format_type = rule_set.get("format", "adblock")
            outbound = rule_set.get("outbound", "block")
            file_path = rule_set.get("file_path")
            checksum = rule_set.get("checksum")

            start_time = time.monotonic()

            try:
                # Acquire semaphore to limit concurrent I/O
                async with self._load_semaphore:
                    # Check if we need to download
                    need_download = force_download or not file_path or not checksum
                    if not need_download:
                        # Check if file exists
                        full_path = self.rules_dir / file_path
                        if not full_path.exists():
                            need_download = True
                            logger.info("Binary file missing for %s, re-downloading", tag)

                    if need_download:
                        # Update status to downloading
                        self._update_remote_db_status(tag, RemoteRuleSetStatus.DOWNLOADING)

                        logger.info("Downloading remote rule set %s from %s", tag, url)

                        # Download and convert
                        new_checksum, rule_count = await self._download_and_convert_remote(
                            tag, url, format_type, outbound
                        )

                        if not new_checksum:
                            error_msg = "Download or conversion failed"
                            logger.error("Failed to download %s: %s", tag, error_msg)
                            self._update_remote_db_status(tag, RemoteRuleSetStatus.ERROR, error_msg)
                            self._stats.failed_count += 1
                            return False

                        # Update database with new file path and checksum
                        file_path = f"remote-{tag}.bin"
                        self.db.update_remote_rule_set(tag, {
                            "file_path": file_path,
                            "checksum": new_checksum,
                            "count": rule_count,
                        })
                        checksum = new_checksum

                        logger.info(
                            "Downloaded remote rule set %s: %d rules, checksum=%s",
                            tag, rule_count, checksum[:16]
                        )

                    # Now load the binary file
                    full_path = self.rules_dir / file_path
                    logger.debug("Loading remote rule set %s from %s", tag, full_path)

                    data = await self._load_file(full_path, checksum)

                # Store loaded data
                self._loaded_remote_sets[tag] = data

                # Calculate load time
                load_time_ms = (time.monotonic() - start_time) * 1000

                # Update statistics
                rule_count = len(data.get("rules", []))
                self._stats.loaded_count += 1
                self._stats.total_rules += rule_count
                self._stats.total_load_time_ms += load_time_ms

                # Update database status
                self._update_remote_db_status(tag, RemoteRuleSetStatus.LOADED)

                logger.info(
                    "Loaded remote rule set %s: %d rules in %.1fms",
                    tag, rule_count, load_time_ms
                )

                # Notify callbacks
                for callback in self._on_load_callbacks:
                    try:
                        callback(f"remote:{tag}", True)
                    except Exception as e:
                        logger.error("Load callback error: %s", e)

                return True

            except FileNotFoundError as e:
                error_msg = f"File not found: {e}"
                logger.error("Failed to load remote %s: %s", tag, error_msg)
                self._update_remote_db_status(tag, RemoteRuleSetStatus.ERROR, error_msg)
                self._stats.failed_count += 1
                return False

            except (RuleBinaryCorruptionError, RuleBinaryChecksumError) as e:
                error_msg = f"Corrupted file: {e}"
                logger.error("Failed to load remote %s: %s", tag, error_msg)
                self._update_remote_db_status(tag, RemoteRuleSetStatus.ERROR, error_msg)
                self._stats.failed_count += 1
                return False

            except RuleBinaryError as e:
                error_msg = f"Binary read error: {e}"
                logger.error("Failed to load remote %s: %s", tag, error_msg)
                self._update_remote_db_status(tag, RemoteRuleSetStatus.ERROR, error_msg)
                self._stats.failed_count += 1
                return False

            except Exception as e:
                error_msg = f"Unexpected error: {type(e).__name__}: {e}"
                logger.exception("Unexpected error loading remote %s", tag)
                self._update_remote_db_status(tag, RemoteRuleSetStatus.ERROR, error_msg)
                self._stats.failed_count += 1
                return False

    async def reload_remote_rule_set(self, tag: str) -> bool:
        """
        Reload a remote rule set (force re-download and refresh).

        Unloads the set if loaded, re-downloads, then loads again.

        Args:
            tag: Remote rule set tag

        Returns:
            True if reload succeeded
        """
        lock = await self._get_lock(f"remote:{tag}")

        async with lock:
            # Remove from loaded sets if present
            old_data = self._loaded_remote_sets.pop(tag, None)

            if old_data:
                # Adjust statistics
                old_count = len(old_data.get("rules", []))
                self._stats.loaded_count -= 1
                self._stats.total_rules -= old_count
                logger.debug("Unloaded remote %s for reload (%d rules)", tag, old_count)

        # Load fresh with force download
        return await self.load_remote_rule_set(tag, force_download=True)

    async def unload_remote_rule_set(self, tag: str) -> bool:
        """
        Unload a remote rule set from memory.

        Args:
            tag: Remote rule set tag

        Returns:
            True if the set was unloaded (False if not loaded)
        """
        lock = await self._get_lock(f"remote:{tag}")

        async with lock:
            if tag not in self._loaded_remote_sets:
                logger.debug("Remote rule set %s not loaded, nothing to unload", tag)
                return False

            # Remove from loaded sets
            data = self._loaded_remote_sets.pop(tag)
            rule_count = len(data.get("rules", []))

            # Adjust statistics
            self._stats.loaded_count -= 1
            self._stats.total_rules -= rule_count

            # Update database status back to pending
            self._update_remote_db_status(tag, RemoteRuleSetStatus.PENDING)

            logger.info("Unloaded remote rule set %s (%d rules)", tag, rule_count)
            return True

    def is_remote_loaded(self, tag: str) -> bool:
        """
        Check if a remote rule set is loaded.

        Args:
            tag: Remote rule set tag

        Returns:
            True if the set is loaded in memory
        """
        return tag in self._loaded_remote_sets

    def get_loaded_remote_set(self, tag: str) -> Optional[dict]:
        """
        Get loaded remote rule set data.

        Args:
            tag: Remote rule set tag

        Returns:
            Rule set data if loaded, None otherwise
        """
        return self._loaded_remote_sets.get(tag)

    def get_loaded_remote_set_ids(self) -> List[str]:
        """
        Get list of loaded remote set tags.

        Returns:
            List of remote set tags that are currently loaded
        """
        return list(self._loaded_remote_sets.keys())

    async def reload_all_remote(self) -> Dict[str, bool]:
        """
        Reload all enabled remote rule sets.

        Returns:
            Dictionary mapping tag to reload success status
        """
        results = {}

        # Get all enabled remote rule sets
        remote_sets = self.db.get_remote_rule_sets(enabled_only=True)

        for rs in remote_sets:
            tag = rs["tag"]
            results[tag] = await self.reload_remote_rule_set(tag)

        return results

    def reset_stats(self) -> None:
        """Reset loader statistics."""
        self._stats = LoaderStats()
        logger.debug("Loader statistics reset")


# Factory function for convenience
def create_rule_loader(
    rules_dir: str,
    db: DatabaseManager,
    max_concurrent: int = 4
) -> AsyncRuleLoader:
    """
    Create an AsyncRuleLoader instance.

    Args:
        rules_dir: Directory containing binary rule files
        db: DatabaseManager instance
        max_concurrent: Maximum concurrent loads

    Returns:
        Configured AsyncRuleLoader instance
    """
    return AsyncRuleLoader(
        rules_dir=Path(rules_dir),
        db=db,
        max_concurrent_loads=max_concurrent
    )


if __name__ == "__main__":
    # Self-test
    import tempfile
    import os

    # Setup logging for test
    try:
        from log_config import setup_logging
        setup_logging(detailed=True)
    except ImportError:
        import logging
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )

    from rule_binary import write_rule_binary

    print("=" * 60)
    print("AsyncRuleLoader Self-Test")
    print("=" * 60)

    async def run_tests():
        # Create temp directory for test rules
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir) / "rules"
            rules_dir.mkdir()

            # Create test rule files
            test_rules = {
                "test-domains": {
                    "rules": ["example.com", "test.org", "*.google.com"],
                    "rule_type": "domain",
                    "outbound": "proxy",
                    "priority": 100,  # High priority
                },
                "test-ips": {
                    "rules": ["1.2.3.4", "10.0.0.0/8", "192.168.1.0/24"],
                    "rule_type": "ip",
                    "outbound": "direct",
                    "priority": 50,  # Normal priority
                },
                "test-geoip": {
                    "rules": [f"10.{i}.0.0/16" for i in range(100)],  # Simulate large set
                    "rule_type": "ip",
                    "outbound": "vpn",
                    "priority": 10,  # Low priority
                },
            }

            # Write test files and track checksums
            checksums = {}
            for set_id, data in test_rules.items():
                file_path = rules_dir / f"{set_id}.bin"
                checksums[set_id] = write_rule_binary(
                    str(file_path),
                    rules=data["rules"],
                    rule_type=data["rule_type"],
                    outbound=data["outbound"],
                    tag=set_id
                )
                print(f"Created: {file_path}")

            # Create mock database manager
            class MockDatabaseManager:
                def __init__(self, rule_sets):
                    self._rule_sets = rule_sets
                    self._status = {rs["id"]: "pending" for rs in rule_sets}

                def get_rule_sets(self, enabled_only=True):
                    if enabled_only:
                        return [rs for rs in self._rule_sets if rs.get("enabled", True)]
                    return self._rule_sets

                def get_rule_set(self, set_id):
                    for rs in self._rule_sets:
                        if rs["id"] == set_id:
                            return rs
                    return None

                def update_rule_set_status(self, set_id, status, error_message=None):
                    self._status[set_id] = status
                    print(f"  [DB] {set_id} -> {status}" + (f" ({error_message})" if error_message else ""))
                    return True

            # Create mock rule set entries (simulating database rows)
            db_rule_sets = [
                {
                    "id": set_id,
                    "name": set_id.replace("-", " ").title(),
                    "rule_type": data["rule_type"],
                    "outbound": data["outbound"],
                    "rule_count": len(data["rules"]),
                    "file_path": f"{set_id}.bin",
                    "checksum": checksums[set_id],
                    "status": "pending",
                    "enabled": True,
                    "priority": data["priority"],
                }
                for set_id, data in test_rules.items()
            ]

            mock_db = MockDatabaseManager(db_rule_sets)

            # Create loader
            print("\n1. Creating AsyncRuleLoader...")
            loader = AsyncRuleLoader(rules_dir, mock_db, max_concurrent_loads=2)
            print(f"   Rules dir: {rules_dir}")

            # Test single load
            print("\n2. Testing single rule set load...")
            success = await loader.load_rule_set("test-domains")
            print(f"   load_rule_set('test-domains'): {success}")
            assert success, "Single load failed"
            assert loader.is_loaded("test-domains"), "Set should be loaded"

            # Test duplicate load (should be quick)
            print("\n3. Testing duplicate load (should skip)...")
            success = await loader.load_rule_set("test-domains")
            print(f"   Second load: {success}")

            # Test background load
            print("\n4. Testing background load...")
            await loader.start_background_load()
            loaded = await loader.wait_for_load(timeout=5.0)
            print(f"   Load completed: {loaded}")

            # Check stats
            print("\n5. Checking statistics...")
            stats = loader.get_stats()
            print(f"   Loaded: {stats['loaded_count']}")
            print(f"   Failed: {stats['failed_count']}")
            print(f"   Total rules: {stats['total_rules']}")
            print(f"   Total time: {stats['total_load_time_ms']:.1f}ms")

            # Test get_all_rules
            print("\n6. Testing get_all_rules()...")
            all_rules = loader.get_all_rules()
            print(f"   Total rule entries: {len(all_rules)}")
            assert len(all_rules) > 0, "Should have loaded rules"

            # Test reload
            print("\n7. Testing reload...")
            success = await loader.reload_rule_set("test-domains")
            print(f"   Reload success: {success}")

            # Test unload
            print("\n8. Testing unload...")
            success = await loader.unload_rule_set("test-ips")
            print(f"   Unload success: {success}")
            assert not loader.is_loaded("test-ips"), "Set should be unloaded"

            # Test loading non-existent set
            print("\n9. Testing non-existent set...")
            success = await loader.load_rule_set("non-existent")
            print(f"   Load non-existent: {success}")
            assert not success, "Should fail for non-existent set"

            # Final stats
            print("\n10. Final statistics...")
            stats = loader.get_stats()
            for key, value in stats.items():
                print(f"    {key}: {value}")

            print("\n" + "=" * 60)
            print("All tests passed!")
            print("=" * 60)

    # Run tests
    asyncio.run(run_tests())
