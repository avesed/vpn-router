# Audit Notes

## Review 1 - Auth Configuration (Initial Pass)
Scope: newly added auth configuration and frontend wiring.

Observations:
- Backend auth middleware protects `/api/*` with JWT HS256 + bcrypt; public paths include `/api/auth/status`, `/api/auth/setup`, `/api/auth/login`, `/api/health` (`scripts/api_server.py`).
- Auth endpoints added: `/api/auth/status`, `/api/auth/setup`, `/api/auth/login`, `/api/auth/refresh`, `/api/auth/me` (`scripts/api_server.py`).
- DB schema updates: `admin_auth` table and `jwt_secret_key` stored in settings (`scripts/init_user_db.py`, `scripts/db_helper.py`).
- Frontend flow: AuthContext token store + refresh, request client attaches Authorization and redirects on 401, ProtectedRoute gating, Login/Setup pages (`frontend/src/contexts/AuthContext.tsx`, `frontend/src/api/client.ts`, `frontend/src/components/ProtectedRoute.tsx`, `frontend/src/pages/Login.tsx`, `frontend/src/pages/Setup.tsx`).

Notes:
- This pass was an inventory check; no defects were recorded at the time.

## Review 2 - Full Project Review (sing-box + WG/OpenVPN/Xray + Frontend)
Scope: sing-box config generation, WG/OpenVPN/Xray integration, frontend workflows, and auth checks.

Findings:
- High: Kernel WireGuard egress interfaces are not synced after PIA/custom egress changes; sing-box uses `bind_interface` for tags that may not exist, breaking routing (`scripts/api_server.py:1967`, `scripts/api_server.py:3705`, `scripts/api_server.py:3623`, `scripts/render_singbox.py:434`).
- High: OpenVPN egress create/update/delete only regenerates sing-box config; `openvpn_manager` is not reloaded so tunnels do not start/refresh until manual restart (`scripts/api_server.py:4082`, `scripts/api_server.py:4156`, `scripts/openvpn_manager.py:340`).
- Medium: OpenVPN `crl_verify` is parsed/stored but never written to client config and update path does not persist it, so revocation lists are ignored (`scripts/openvpn_manager.py:90`, `scripts/api_server.py:4166`).
- Medium: OpenVPN SOCKS5 proxy supports CONNECT only and resolves DNS on the host; with `route-nopull` this can break UDP and risk DNS leakage (`scripts/socks5_proxy.py:30`, `scripts/socks5_proxy.py:192`, `scripts/openvpn_manager.py:103`).
- Medium: Auth middleware fails open on DB errors, allowing unauthenticated access if the DB is locked or corrupted (`scripts/api_server.py:701`).
- Low: Duplicate `ensure_xray_socks_inbound` definitions with different ports (7891 vs 38001); the earlier version is unused, causing confusion (`scripts/render_singbox.py:170`, `scripts/render_singbox.py:1571`).

Testing:
- Not run.
