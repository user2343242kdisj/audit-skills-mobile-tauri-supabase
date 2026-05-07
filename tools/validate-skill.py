#!/usr/bin/env python3
"""Validate SKILL.md metadata for the curated audit-skills set.

Usage:
    python tools/validate-skill.py skills/my-skill/
    python tools/validate-skill.py --all
"""
import os
import re
import sys
import glob

REQUIRED_FIELDS = ["name", "description", "domain", "subdomain", "tags"]

# Subdomains actually used in the curated set (mobile + Tauri + Supabase audit).
ALLOWED_SUBDOMAINS = {
    "api-security",
    "application-security",
    "cloud-security",
    "cryptography",
    "devsecops",
    "identity-access-management",
    "malware-analysis",
    "mobile-security",
    "network-security",
    "offensive-security",
    "penetration-testing",
    "security-operations",
    "vulnerability-management",
    "web-application-security",
}

KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
DESCRIPTION_MIN_CHARS = 50

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def parse_frontmatter(text):
    if not text.startswith("---"):
        return None
    end = text.find("---", 3)
    if end == -1:
        return None
    block = text[3:end].strip()
    data = {}
    current_key = None
    list_values = []
    in_folded = False
    folded_lines = []

    for line in block.split("\n"):
        stripped = line.strip()

        if in_folded and stripped and not line.startswith(" ") and not line.startswith("\t"):
            if current_key and folded_lines:
                data[current_key] = " ".join(folded_lines)
            in_folded = False
            folded_lines = []
            current_key = None

        if in_folded:
            if stripped:
                folded_lines.append(stripped)
            continue

        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- ") and current_key:
            list_values.append(stripped[2:].strip().strip('"').strip("'"))
            data[current_key] = list(list_values)
            continue

        m = re.match(r"^(\w[\w_-]*):\s*\[(.+)\]\s*$", stripped)
        if m:
            current_key = m.group(1)
            items = [i.strip().strip('"').strip("'") for i in m.group(2).split(",")]
            data[current_key] = items
            list_values = list(items)
            continue

        m = re.match(r"^(\w[\w_-]*):\s*>[-|]?\s*$", stripped)
        if m:
            current_key = m.group(1)
            list_values = []
            in_folded = True
            folded_lines = []
            continue

        m = re.match(r'^(\w[\w_-]*):\s*(.*)$', stripped)
        if m:
            current_key = m.group(1)
            val = m.group(2).strip().strip('"').strip("'")
            list_values = []
            if val:
                data[current_key] = val
            continue

    if in_folded and current_key and folded_lines:
        data[current_key] = " ".join(folded_lines)

    return data


def validate_skill(skill_dir):
    errors = []
    skill_md = os.path.join(skill_dir, "SKILL.md")

    if not os.path.isfile(skill_md):
        return [f"SKILL.md not found in {skill_dir}"]

    try:
        content = open(skill_md, encoding="utf-8").read()
    except (IOError, UnicodeDecodeError) as e:
        return [f"Could not read SKILL.md: {e}"]

    fm = parse_frontmatter(content)
    if fm is None:
        return ["No valid YAML frontmatter found (must start with ---)"]

    for field in REQUIRED_FIELDS:
        if field not in fm:
            errors.append(f"Missing required field: {field}")

    name = fm.get("name", "")
    if name:
        if not KEBAB_RE.match(name):
            errors.append(f"Name '{name}' is not valid kebab-case")
        if len(name) > 64:
            errors.append(f"Name too long ({len(name)} chars, max 64)")

    desc = fm.get("description", "")
    if isinstance(desc, list):
        errors.append("Description must be a string, not a list")
    elif isinstance(desc, str) and len(desc) < DESCRIPTION_MIN_CHARS:
        errors.append(f"Description too short ({len(desc)} chars, min {DESCRIPTION_MIN_CHARS})")

    domain = fm.get("domain", "")
    if domain and domain != "cybersecurity":
        errors.append(f"Domain must be 'cybersecurity', got '{domain}'")

    subdomain = fm.get("subdomain", "")
    if subdomain and subdomain not in ALLOWED_SUBDOMAINS:
        errors.append(
            f"Unknown subdomain '{subdomain}'. Allowed: {', '.join(sorted(ALLOWED_SUBDOMAINS))}"
        )

    tags = fm.get("tags", [])
    if isinstance(tags, str):
        tags = [tags]
    if len(tags) < 2:
        errors.append(f"Need at least 2 tags, got {len(tags)}")

    return errors


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <skill-dir> | --all")
        sys.exit(1)

    if sys.argv[1] == "--all":
        skill_dirs = sorted(glob.glob("skills/*/"))
        if not skill_dirs:
            print("ERROR: No skill directories found. Run from the repository root.")
            sys.exit(1)
    else:
        skill_dirs = [sys.argv[1].rstrip("/") + "/"]

    total = passed = failed = 0
    for skill_dir in skill_dirs:
        if not os.path.isdir(skill_dir.rstrip("/")):
            print(f"{RED}SKIP{RESET} {skill_dir} — not a directory")
            continue
        total += 1
        errors = validate_skill(skill_dir.rstrip("/"))
        name = os.path.basename(skill_dir.rstrip("/"))
        if errors:
            failed += 1
            print(f"{RED}FAIL{RESET} {name}")
            for e in errors:
                print(f"      {YELLOW}→ {e}{RESET}")
        else:
            passed += 1
            print(f"{GREEN}PASS{RESET} {name}")

    print(f"\n{'='*50}")
    print(f"Total: {total}  {GREEN}Passed: {passed}{RESET}  {RED}Failed: {failed}{RESET}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
