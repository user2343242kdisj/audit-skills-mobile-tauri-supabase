#!/usr/bin/env python3
"""
Threat model starter for a mobile + Tauri-desktop + Supabase app.

Uses pytm (Python Threat Modeling): https://github.com/izar/pytm

Install:
    pip install pytm

Usage (from your app repo):
    python3 threat-model.py --report           # markdown report → stdout
    python3 threat-model.py --dfd | dot -Tpng -o dfd.png   # data-flow diagram
    python3 threat-model.py --seq | java -jar plantuml.jar -p > seq.svg
    python3 threat-model.py --list            # list threats only

Customize the boundaries, actors, assets and dataflows below for your
specific architecture, then commit `threat-model.py` to your app repo
alongside this template.
"""

from pytm import (
    TM, Actor, Boundary, Server, Datastore, Process, Lambda, Dataflow,
    Data, Classification, Lifetime, Threat,
)

tm = TM("Mobile + Tauri-desktop + Supabase")
tm.description = """
Threat model covering:
  - Mobile app (iOS + Android) — clients of Supabase REST + Realtime
  - Desktop app via Tauri 2 (Rust core + system WebView) — same clients
  - Supabase backend: Postgres + GoTrue + Storage + Edge Functions Deno + Realtime

Reference docs in this repo:
  - docs/owasp-mas-analysis.md
  - docs/tauri-2-security-analysis.md
  - docs/supabase-security-tools.md
"""
tm.isOrdered = True

# ---------------------------------------------------------------------------
# Boundaries (trust zones)
# ---------------------------------------------------------------------------
internet = Boundary("Internet")
user_device_mobile = Boundary("User mobile device")
user_device_desktop = Boundary("User desktop machine")
user_device_mobile.parent = internet
user_device_desktop.parent = internet

supabase_cloud = Boundary("Supabase cloud (AWS)")
edge_runtime = Boundary("Supabase Edge Runtime (Deno)")
postgres_zone = Boundary("Supabase Postgres VPC")
edge_runtime.parent = supabase_cloud
postgres_zone.parent = supabase_cloud

# ---------------------------------------------------------------------------
# Actors
# ---------------------------------------------------------------------------
end_user = Actor("End user")
end_user.inBoundary = internet

attacker_remote = Actor("Remote attacker")
attacker_remote.inBoundary = internet

attacker_local = Actor("Local attacker (device-level)")
attacker_local.inBoundary = internet
attacker_local.isAdmin = False

malicious_app = Actor("Malicious app on user device")
malicious_app.inBoundary = user_device_mobile

# ---------------------------------------------------------------------------
# Assets / Data
# ---------------------------------------------------------------------------
user_credentials = Data(
    "User credentials (email + password)",
    classification=Classification.RESTRICTED,
)
session_jwt = Data(
    "Session JWT",
    classification=Classification.RESTRICTED,
    isCredentials=True,
)
service_role_key = Data(
    "Supabase service_role JWT",
    classification=Classification.SECRET,
    isCredentials=True,
)
user_pii = Data(
    "User PII (profile, addresses, payments)",
    classification=Classification.PII,
)
storage_objects = Data(
    "User-uploaded files",
    classification=Classification.RESTRICTED,
)

# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------
mobile_app = Process("Mobile app (iOS / Android)")
mobile_app.inBoundary = user_device_mobile
mobile_app.OS = "iOS / Android"
mobile_app.implementsAuthenticationScheme = True
mobile_app.handlesResources = True

tauri_app = Process("Tauri desktop app")
tauri_app.inBoundary = user_device_desktop
tauri_app.OS = "macOS / Windows / Linux"
tauri_app.implementsAuthenticationScheme = True

postgrest = Server("PostgREST API")
postgrest.inBoundary = supabase_cloud
postgrest.providesIntegrity = True
postgrest.providesConfidentiality = True
postgrest.implementsAuthenticationScheme = True
postgrest.sanitizesInput = True

gotrue = Server("GoTrue (auth)")
gotrue.inBoundary = supabase_cloud
gotrue.implementsAuthenticationScheme = True
gotrue.providesConfidentiality = True

storage = Server("Storage API")
storage.inBoundary = supabase_cloud

edge_fn = Lambda("Edge Function (Deno)")
edge_fn.inBoundary = edge_runtime
edge_fn.environment = "Deno on Vercel-style serverless"

postgres = Datastore("Postgres DB")
postgres.inBoundary = postgres_zone
postgres.storesPII = True
postgres.storesSensitiveData = True
postgres.isEncrypted = True
postgres.providesRowLevelSecurity = True

# ---------------------------------------------------------------------------
# Dataflows
# ---------------------------------------------------------------------------
flow_user_login = Dataflow(end_user, mobile_app, "User submits credentials")
flow_user_login.protocol = "HTTPS"
flow_user_login.data = user_credentials
flow_user_login.dstPort = 443

flow_mobile_to_gotrue = Dataflow(mobile_app, gotrue, "Login / refresh / MFA")
flow_mobile_to_gotrue.protocol = "HTTPS"
flow_mobile_to_gotrue.dstPort = 443
flow_mobile_to_gotrue.data = user_credentials

flow_gotrue_to_mobile = Dataflow(gotrue, mobile_app, "JWT issuance")
flow_gotrue_to_mobile.protocol = "HTTPS"
flow_gotrue_to_mobile.dstPort = 443
flow_gotrue_to_mobile.data = session_jwt

flow_mobile_to_postgrest = Dataflow(mobile_app, postgrest, "REST queries with JWT")
flow_mobile_to_postgrest.protocol = "HTTPS"
flow_mobile_to_postgrest.dstPort = 443
flow_mobile_to_postgrest.data = session_jwt

flow_postgrest_to_pg = Dataflow(postgrest, postgres, "SQL via SET ROLE + RLS")
flow_postgrest_to_pg.protocol = "Postgres"
flow_postgrest_to_pg.dstPort = 5432
flow_postgrest_to_pg.data = user_pii
flow_postgrest_to_pg.isEncrypted = True

flow_tauri_to_postgrest = Dataflow(tauri_app, postgrest, "REST queries from Tauri")
flow_tauri_to_postgrest.protocol = "HTTPS"
flow_tauri_to_postgrest.dstPort = 443
flow_tauri_to_postgrest.data = session_jwt

flow_mobile_to_edge = Dataflow(mobile_app, edge_fn, "Edge Function invoke")
flow_mobile_to_edge.protocol = "HTTPS"
flow_mobile_to_edge.dstPort = 443
flow_mobile_to_edge.data = session_jwt

flow_edge_to_postgrest = Dataflow(edge_fn, postgrest, "Server-to-server with service_role")
flow_edge_to_postgrest.protocol = "HTTPS"
flow_edge_to_postgrest.dstPort = 443
flow_edge_to_postgrest.data = service_role_key

flow_storage_signed = Dataflow(mobile_app, storage, "Signed URL upload/download")
flow_storage_signed.protocol = "HTTPS"
flow_storage_signed.dstPort = 443
flow_storage_signed.data = storage_objects

flow_attacker_remote = Dataflow(attacker_remote, postgrest, "BOLA/IDOR probes")
flow_attacker_remote.protocol = "HTTPS"
flow_attacker_remote.note = "Verified by tools/bola-harness.py in CI"

flow_malicious_app = Dataflow(malicious_app, mobile_app, "Deeplink hijack / IPC abuse")
flow_malicious_app.protocol = "Custom URL scheme / Android intent"
flow_malicious_app.note = "MASVS-PLATFORM-1; covered by exploiting-deeplink-vulnerabilities skill"

# ---------------------------------------------------------------------------
# Custom threats (additions to pytm's built-in library)
# ---------------------------------------------------------------------------
# pytm.process() will run STRIDE against every component + dataflow and
# produce a ranked findings list. Below are extras from our own audit.

CUSTOM_THREATS = [
    # MAS-related
    "INP01: Untrusted deeplink/intent input (MASVS-PLATFORM-1)",
    "INP02: Insecure data storage in mobile keychain/keystore (MASVS-STORAGE-1)",
    "DR01:  Cert pinning bypass via Frida (MASVS-NETWORK-2)",
    # Tauri-related
    "TAU01: Capability over-grant (windows=['*'] + shell:allow-execute)",
    "TAU02: dangerousDisableAssetCspModification + 'unsafe-inline'",
    "TAU03: Updater manifest hijack (manifest unsigned)",
    "TAU04: Origin-resolution bug on Windows/Android (CVE-2026-42184)",
    # Supabase-related
    "SB01:  RLS disabled on public schema table (Splinter 0013)",
    "SB02:  service_role exposed to client bundle",
    "SB03:  GoTrue OIDC bypass via Apple/Azure (CVE-2026-31813)",
    "SB04:  MCP lethal trifecta — service_role to LLM agent",
    "SB05:  Storage bucket public + listing enabled (Splinter 0025)",
    "SB06:  Edge Function leaks Deno.env in error response",
]

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    tm.process()
    # pytm prints STRIDE findings + DFD on its own. The CUSTOM_THREATS
    # above are reminders to manually verify in addition to STRIDE.
    print("\n# Custom threats to verify manually")
    for t in CUSTOM_THREATS:
        print(f"- {t}")
