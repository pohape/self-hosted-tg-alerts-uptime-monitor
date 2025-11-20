#!/usr/bin/env python3
"""
One-shot CLI status viewer for the monitoring cache.

It does NOT perform any network requests.
It only reads:
  - config.yaml (to know which sites exist and thresholds)
  - the JSON cache file (to know last check results)
and prints a human-readable status to the terminal.
"""
import argparse
import time
from datetime import datetime
from typing import Any, Dict, Optional

from console_helper import Color, color_text
from filesystem_helper import load_yaml_or_exit, load_cache
from run import CACHE_PATH, CONFIG_PATH


def human_time(ts: Optional[int]) -> str:
    """Return a human-readable timestamp or a placeholder."""
    if not ts:
        return "never"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        return f"invalid ({ts})"


def human_age(ts: Optional[int]) -> str:
    """Return a human-readable age like '3m ago' or '2h ago'."""
    if not ts:
        return "n/a"
    now = int(time.time())
    delta = max(0, now - ts)

    if delta < 60:
        return f"{delta}s ago"
    minutes = delta // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def determine_state(site_cfg: Dict[str, Any], cache_entry: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Determine logical state for a site based on its cache entry.

    Returns a dict with:
      - state: "UP" | "DOWN" | "UNSTABLE" | "UNKNOWN"
      - color: Color enum for console output
      - error_msg: last error message (str or None)
    """
    if cache_entry is None:
        return {
            "state": "UNKNOWN",
            "color": Color.WARNING,
            "error_msg": "No cache entry found; probably never checked.",
        }

    last_error = cache_entry.get("last_error")
    failed_attempts = cache_entry.get("failed_attempts", 0)
    notify_after = site_cfg.get("notify_after_attempt", 1)

    # Site considered UP when there is explicitly no last_error
    if last_error is None:
        return {
            "state": "UP",
            "color": Color.SUCCESS,
            "error_msg": None,
        }

    # For older / unexpected cache shapes
    if not isinstance(last_error, dict):
        message = str(last_error)
    else:
        message = last_error.get("msg") or "Unknown error"

    if failed_attempts >= notify_after:
        state = "DOWN"
        color = Color.ERROR
    else:
        state = "UNSTABLE"
        color = Color.WARNING

    return {
        "state": state,
        "color": color,
        "error_msg": message,
    }


def print_site_status(
        site_name: str,
        site_cfg: Dict[str, Any],
        cache_entry: Optional[Dict[str, Any]],
        state_info: Dict[str, Any],
) -> None:
    """Print detailed status for a single site."""
    state = state_info["state"]
    color = state_info["color"]
    error_msg = state_info["error_msg"]

    last_checked_at = cache_entry.get("last_checked_at") if cache_entry else None
    failed_attempts = cache_entry.get("failed_attempts") if cache_entry else None
    notified_down = cache_entry.get("notified_down") if cache_entry else None
    notified_restore = cache_entry.get("notified_restore") if cache_entry else None

    url = site_cfg.get("url", "<no url>")
    schedule = site_cfg.get("schedule", "* * * * *")
    notify_after = site_cfg.get("notify_after_attempt", 1)

    color_text(f"{site_name}", Color.TITLE)
    color_text(f"  State: {state}", color)
    print(f"  URL: {url}")
    print(f"  Schedule: {schedule}")
    print(f"  Notify after attempts: {notify_after}")
    print(f"  Last check at: {human_time(last_checked_at)} ({human_age(last_checked_at)})")

    if failed_attempts is not None:
        print(f"  Failed attempts: {failed_attempts}")

    if notified_down:
        print(f"  First DOWN notification at: {human_time(notified_down)} ({human_age(notified_down)})")
    if notified_restore:
        print(f"  RESTORE notification at: {human_time(notified_restore)} ({human_age(notified_restore)})")

    if error_msg:
        print("  Last error:")
        print(f"    {error_msg}")

    print()  # blank line between sites


def print_summary(status_counts: Dict[str, int], total_sites: int) -> None:
    """Print a short numeric summary of states."""
    color_text("=== SUMMARY ===", Color.TITLE)
    print(f"  Total sites: {total_sites}")
    for key in ("UP", "DOWN", "UNSTABLE", "UNKNOWN"):
        print(f"  {key:8}: {status_counts.get(key, 0)}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Show current status of monitored sites based on the cache file."
    )
    parser.add_argument(
        "--only-down",
        action="store_true",
        help="Show only sites that are DOWN or UNSTABLE.",
    )

    args = parser.parse_args()

    config = load_yaml_or_exit(CONFIG_PATH)
    cache = load_cache(CACHE_PATH)
    sites = config.get("sites", {})

    if not sites:
        color_text("No sites defined in config.yaml", Color.ERROR)
        return

    color_text("=== CURRENT MONITORING STATUS ===", Color.TITLE)
    print(f"Config: {CONFIG_PATH}")
    print(f"Cache:  {CACHE_PATH}")
    print()

    status_counts: Dict[str, int] = {"UP": 0, "DOWN": 0, "UNSTABLE": 0, "UNKNOWN": 0}

    for site_name, site_cfg in sites.items():
        cache_entry = cache.get(site_name)
        state_info = determine_state(site_cfg, cache_entry)
        state = state_info["state"]
        status_counts[state] = status_counts.get(state, 0) + 1

        if args.only_down and state not in ("DOWN", "UNSTABLE"):
            continue

        print_site_status(site_name, site_cfg, cache_entry, state_info)

    print_summary(status_counts, total_sites=len(sites))

    # Orphan cache entries that no longer exist in config
    orphaned = [name for name in cache.keys() if name not in sites]
    if orphaned:
        color_text("Orphaned cache entries (not present in config.yaml):", Color.WARNING)
        for name in sorted(orphaned):
            print(f"  - {name}")
        print()


if __name__ == "__main__":
    main()
