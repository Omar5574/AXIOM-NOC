#!/usr/bin/env python3
"""
spike.py — NextGen NMS CPU Stress Injector
==========================================
Injects a fake 99% CPU utilization string into full_topology.json to
trigger the React frontend's red stress-aura rendering on demand.

Usage:
  python3 spike.py <Device_Name>   — spike a single device
  python3 spike.py ALL             — spike EVERY device in the topology
  python3 spike.py --reset ALL     — restore all devices to 0% CPU

The 'ALL' mode is designed for demo scenarios: run it, then refresh the
dashboard — every node on the map turns red simultaneously, simulating a
network-wide incident. When Ansible's background poller next runs and
writes real telemetry, the dashboard auto-heals back to green.
"""

import json
import sys
import urllib.request

# ── Constants ─────────────────────────────────────────────────────────────────
FILE_PATH   = 'full_topology.json'
SPIKE_CPU   = "CPU utilization for five seconds: 99%/0%; one minute: 99%; five minutes: 99%"
RESET_CPU   = "CPU utilization for five seconds: 0%/0%; one minute: 0%; five minutes: 0%"

# ANSI colour codes for hacker-style terminal output
RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def banner():
    print(f"{RED}{BOLD}")
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   NextGen NMS — CPU SPIKE INJECTOR v2.0     ║")
    print("  ║   Target: Hospital Network Infrastructure    ║")
    print("  ╚══════════════════════════════════════════════╝")
    print(f"{RESET}")

def inject_cpu(dev, cpu_string):
    """Mutates a device dict in-place with the given cpu_raw string."""
    if 'real_telemetry' not in dev:
        dev['real_telemetry'] = {}
    dev['real_telemetry']['cpu_raw'] = cpu_string

def main():
    banner()

    # ── Argument parsing ──────────────────────────────────────────────────────
    args = sys.argv[1:]
    if not args:
        print(f"{YELLOW}Usage:  python3 spike.py <Device_Name>{RESET}")
        print(f"        python3 spike.py ALL")
        print(f"        python3 spike.py --reset ALL")
        print(f"        python3 spike.py --reset <Device_Name>")
        sys.exit(1)

    # Optional --reset flag switches from spike → zero-out
    reset_mode  = '--reset' in args
    targets_raw = [a for a in args if a != '--reset']
    target_arg  = targets_raw[0].strip().upper() if targets_raw else ''
    target_all  = (target_arg == 'ALL')
    cpu_string  = RESET_CPU if reset_mode else SPIKE_CPU
    action_word = "RESET" if reset_mode else "SPIKE"
    action_icon = "🟢" if reset_mode else "🔥"

    # ── Load topology ─────────────────────────────────────────────────────────
    try:
        with open(FILE_PATH, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"{RED}❌  ERROR: '{FILE_PATH}' not found.")
        print(f"    Make sure you run this from the hospital-dashboard/ directory.{RESET}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{RED}❌  ERROR: Could not parse '{FILE_PATH}': {e}{RESET}")
        sys.exit(1)

    devices         = data.get('network_devices', [])
    available_names = [d.get('device_name', '?') for d in devices]

    if not devices:
        print(f"{YELLOW}⚠️   No devices found in '{FILE_PATH}'.{RESET}")
        sys.exit(1)

    # ── Injection logic ───────────────────────────────────────────────────────
    hit_count = 0

    if target_all:
        # ── Network-wide mode: blast every single device ──────────────────────
        print(f"{CYAN}[*] Mode: NETWORK-WIDE {action_word}{RESET}")
        print(f"{CYAN}[*] Targeting all {len(devices)} devices across both branches...{RESET}\n")

        for dev in devices:
            name = dev.get('device_name', '?')
            inject_cpu(dev, cpu_string)
            hit_count += 1
            print(f"  {action_icon}  [{hit_count:>2}] {name:<20} → cpu_raw injected")

        print(f"\n{RED if not reset_mode else GREEN}{BOLD}")
        if reset_mode:
            print(f"  ✅  RESET COMPLETE — {hit_count} devices returned to 0% CPU.")
            print(f"  Refresh the dashboard to see all nodes turn green.")
        else:
            print(f"  💥  NETWORK-WIDE SPIKE COMPLETE — {hit_count} DEVICES COMPROMISED.")
            print(f"  Refresh the dashboard — the entire map should burn red.")
            print(f"  When Ansible's next poll runs, the graph will auto-heal. 🛡️")
        print(RESET)

    else:
        # ── Single-device mode ────────────────────────────────────────────────
        target_name = targets_raw[0].strip()  # Preserve original casing
        print(f"{CYAN}[*] Mode: SINGLE DEVICE {action_word}{RESET}")
        print(f"{CYAN}[*] Looking for: {target_name}{RESET}\n")

        matched = False
        for dev in devices:
            if dev.get('device_name') == target_name:
                inject_cpu(dev, cpu_string)
                hit_count = 1
                matched = True
                print(f"  {action_icon}  Target acquired: {BOLD}{target_name}{RESET}")
                break

        if not matched:
            print(f"{RED}  ❌  ERROR: Device '{target_name}' not found in topology.{RESET}")
            print(f"\n  Available devices ({len(available_names)}):")
            for name in available_names:
                print(f"    • {name}")
            sys.exit(1)

        if reset_mode:
            print(f"\n{GREEN}{BOLD}  ✅  {target_name} CPU reset to 0%.{RESET}")
        else:
            print(f"\n{RED}{BOLD}  🔥  SPIKE INJECTED into [ {target_name} ]!")
            print(f"  Refresh the dashboard — watch it burn red.{RESET}")

    # ── Write back ────────────────────────────────────────────────────────────
    if hit_count > 0:
        try:
            with open(FILE_PATH, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"\n{CYAN}[✓] '{FILE_PATH}' saved successfully.{RESET}")

            # Silent webhook ping so the React UI refreshes immediately.
            try:
                req = urllib.request.Request(
                    'http://localhost:3001/api/notify-update',
                    data=b'{}',
                    method='POST',
                    headers={'Content-Type': 'application/json'},
                )
                urllib.request.urlopen(req, timeout=2).read()
            except Exception:
                pass
        except IOError as e:
            print(f"{RED}❌  ERROR: Could not write file: {e}{RESET}")
            sys.exit(1)

if __name__ == '__main__':
    main()