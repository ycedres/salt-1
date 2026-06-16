#!/usr/bin/env python3
"""
apply_patches.py - Robust, resume-capable Python script to apply git-formatted patches
in the precise order specified by patches/patches.orders.txt.

Features:
  - Parses patches/patches.orders.txt sequentially.
  - Applies patches using `git am --3way`.
  - Automatically handles empty/already-applied patches if git am reports it.
  - Detects conflicts and pauses for user input (or exits in non-interactive mode).
  - Persists state in `.patch_apply_state.json` to allow resuming seamlessly.
"""

import os
import sys
import json
import re
import subprocess

STATE_FILE = ".patch_apply_state.json"
ORDERS_FILE = "patches/patches.orders.txt"
PATCHES_DIR = "patches"

# ANSI Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg):
    print(f"{Colors.BLUE}[INFO]{Colors.END} {msg}")

def log_success(msg):
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {Colors.BOLD}{msg}{Colors.END}")

def log_warn(msg):
    print(f"{Colors.YELLOW}[WARN]{Colors.END} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")

def run_command(cmd, capture_output=True):
    """Runs a shell command and returns (stdout, stderr, returncode)."""
    if capture_output:
        proc = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    else:
        proc = subprocess.run(cmd, shell=True)
        return "", "", proc.returncode

def parse_patches_order():
    """Parses patches.orders.txt and returns a list of patch filenames in order."""
    if not os.path.exists(ORDERS_FILE):
        log_error(f"Orders file not found: {ORDERS_FILE}")
        sys.exit(1)
        
    patches = []
    # Match lines like "Patch123:  some-patch.patch"
    pattern = re.compile(r"^Patch\d+:\s*(.+)$")
    
    with open(ORDERS_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            # Ignore comments and empty lines
            if not line or line.startswith('#'):
                continue
            match = pattern.match(line)
            if match:
                patch_file = match.group(1).strip()
                patches.append(patch_file)
                
    return patches

def load_state():
    """Loads the application state from JSON."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log_warn(f"Failed to load state file: {e}. Starting fresh.")
    return {"current_index": 0, "history": {}}

def save_state(current_index, history):
    """Saves the application state to JSON."""
    state = {
        "current_index": current_index,
        "history": history
    }
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log_warn(f"Failed to save state file: {e}")

def check_git_am_status():
    """Checks if git is currently in the middle of a 'git am' session."""
    dot_git_am = os.path.join(".git", "rebase-apply")
    return os.path.isdir(dot_git_am)

def has_unmerged_files():
    """Checks if there are any unmerged files (conflicts) in the git repo."""
    stdout, _, _ = run_command("git diff --name-only --diff-filter=U")
    return bool(stdout.strip())

def main():
    non_interactive = "--non-interactive" in sys.argv or "-n" in sys.argv
    
    print(f"{Colors.HEADER}{Colors.BOLD}=== Salt Patch Applicator (3006 -> 3008.1) ==={Colors.END}")
    if non_interactive:
        print(f"{Colors.BLUE}{Colors.BOLD}[Non-Interactive Mode]{Colors.END}\n")
    else:
        print()
        
    # 1. Parse patches order
    all_patches = parse_patches_order()
    log_info(f"Loaded {len(all_patches)} patches from {ORDERS_FILE}")
    
    # 2. Check for missing patch files
    missing_patches = []
    for p in all_patches:
        p_path = os.path.join(PATCHES_DIR, p)
        if not os.path.exists(p_path):
            missing_patches.append(p)
    
    if missing_patches:
        log_warn(f"{len(missing_patches)} patch file(s) listed in order file are missing from {PATCHES_DIR}/ folder:")
        for mp in missing_patches[:10]:
            print(f"  - {mp}")
        if len(missing_patches) > 10:
            print(f"  - ... and {len(missing_patches) - 10} more")
        
        if not non_interactive:
            # Ask to proceed anyway or quit
            ans = input("\nDo you want to proceed by skipping missing files? [y/N]: ").strip().lower()
            if ans != 'y':
                log_info("Aborting.")
                sys.exit(0)
        else:
            log_info("Non-interactive: Automatically skipping missing patch files.")
            
    # 3. Load or initialize state
    state = load_state()
    start_index = state.get("current_index", 0)
    history = state.get("history", {})
    
    # Check if we should resume
    if start_index > 0:
        log_info(f"Found existing progress. Resuming from patch index {start_index} of {len(all_patches)}.")
        print(f"Next patch to apply: {Colors.BOLD}{all_patches[start_index]}{Colors.END}")
        if not non_interactive:
            ans = input("Resume? [Y/n]: ").strip().lower()
            if ans == 'n':
                start_index = 0
                history = {}
                save_state(0, {})
                log_info("Started a fresh patch application session.")
        else:
            log_info("Non-interactive: Automatically resuming session.")
            
    # Check for active git am session
    if check_git_am_status():
        log_warn("An active 'git am' session is already in progress.")
        if has_unmerged_files():
            if non_interactive:
                log_error("Active conflicts found in git. Exiting for manual/agent resolution.")
                sys.exit(2)
            else:
                print("Active conflicts detected. Please choose an action:")
                print("  [c] Continue the active session (git am --continue) - Use after manual resolution")
                print("  [s] Skip the active conflicting patch (git am --skip)")
                print("  [a] Abort the active session (git am --abort)")
                print("  [q] Quit and resolve manually")
                ans = input("Action: ").strip().lower()
                if ans == 'c':
                    _, _, rc = run_command("git am --continue", capture_output=False)
                    if rc != 0:
                        log_error("git am --continue failed. Resolve conflicts manually.")
                        sys.exit(1)
                elif ans == 's':
                    run_command("git am --skip")
                elif ans == 'a':
                    run_command("git am --abort")
                    log_info("Active 'git am' session aborted.")
                else:
                    sys.exit(0)
        else:
            log_info("No unmerged files found. Continuing active session...")
            _, _, rc = run_command("git am --continue", capture_output=False)
            if rc != 0:
                log_error("git am --continue failed. Please inspect.")
                sys.exit(1)
            # Since the active session completed, mark the current patch as resolved and advance index
            resolved_patch = all_patches[start_index]
            log_success(f"Resumed and successfully completed active session for: {resolved_patch}")
            history[resolved_patch] = "APPLIED_RESOLVED"
            start_index += 1
            save_state(start_index, history)
            
    # 4. Main application loop
    i = start_index
    while i < len(all_patches):
        patch_name = all_patches[i]
        patch_path = os.path.join(PATCHES_DIR, patch_name)
        
        if not os.path.exists(patch_path):
            log_warn(f"[{i+1}/{len(all_patches)}] Skipping missing patch file: {patch_name}")
            history[patch_name] = "MISSING"
            i += 1
            save_state(i, history)
            continue
            
        print(f"\n{Colors.BOLD}[{i+1}/{len(all_patches)}] Applying: {patch_name}{Colors.END}")
        
        # Execute git am --3way
        stdout, stderr, rc = run_command(f"git am --3way \"{patch_path}\"")
        
        if rc == 0:
            log_success(f"Applied: {patch_name}")
            history[patch_name] = "APPLIED"
            i += 1
            save_state(i, history)
            continue
            
        # If it failed, check for common scenarios
        output_full = stdout + "\n" + stderr
        
        # Scenario: Already applied or patch is empty (redundant)
        if "Patch is empty" in output_full or "No changes - did you forget to use 'git add'?" in output_full or "already applied" in output_full:
            log_info(f"Patch is empty or already applied upstream. Skipping automatically.")
            run_command("git am --skip")
            history[patch_name] = "SKIPPED_UPSTREAM"
            i += 1
            save_state(i, history)
            continue
            
        # Scenario: Merge Conflict
        log_error(f"Failed to apply patch: {patch_name}")
        print(f"{Colors.YELLOW}--- git am output ---{Colors.END}")
        print(output_full)
        print(f"{Colors.YELLOW}---------------------{Colors.END}")
        
        if non_interactive:
            log_error(f"Conflict encountered in non-interactive mode. Exiting with status 1.")
            sys.exit(1)
            
        # Interactive conflict resolution loop
        resolved = False
        while not resolved:
            print(f"\nOptions to resolve conflict on {Colors.BOLD}{patch_name}{Colors.END}:")
            print("  [c] Continue - Use after manual resolution (runs: git am --continue)")
            print("  [s] Skip - Skip this patch entirely (runs: git am --skip)")
            print("  [a] Abort - Abort git am session & exit script (runs: git am --abort)")
            print("  [q] Quit - Pause script but leave git in conflict state (can resume later)")
            print("  [d] Show diff - Run 'git diff' to see current conflict markers")
            
            ans = input("Choice: ").strip().lower()
            
            if ans == 'c':
                _, _, rc_cont = run_command("git am --continue", capture_output=False)
                if rc_cont == 0:
                    log_success(f"Conflict resolved and applied: {patch_name}")
                    history[patch_name] = "APPLIED_RESOLVED"
                    i += 1
                    save_state(i, history)
                    resolved = True
                else:
                    log_error("git am --continue failed. Check conflict markers again.")
            elif ans == 's':
                run_command("git am --skip")
                log_warn(f"Skipped patch: {patch_name}")
                history[patch_name] = "SKIPPED_MANUAL"
                i += 1
                save_state(i, history)
                resolved = True
            elif ans == 'a':
                run_command("git am --abort")
                log_info("git am session aborted.")
                sys.exit(0)
            elif ans == 'q':
                log_info("Exiting. You can resolve conflicts in your terminal, and then re-run this script to resume.")
                sys.exit(0)
            elif ans == 'd':
                diff_out, _, _ = run_command("git diff")
                print(f"\n{Colors.BLUE}--- git diff ---{Colors.END}")
                print(diff_out)
                print(f"{Colors.BLUE}----------------{Colors.END}")
            else:
                log_warn("Invalid option.")
                
    log_success("\nAll patches have been processed!")
    # Clear state file upon completion
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

if __name__ == "__main__":
    main()
