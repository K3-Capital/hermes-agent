"""Hermetic tests for the iron-proxy egress integration.

Covers the pure-function surface (token mint, mapping discovery, config build,
config + mappings I/O), the binary install path (HTTP downloads + tar
extraction + checksum verification fully mocked), the subprocess lifecycle
(spawn / PID / pid_alive / stop, with subprocess.Popen mocked), and the
docker backend's egress arg builder.

Live network and the real ``iron-proxy`` binary are NEVER touched.  See
``tests/test_iron_proxy_e2e.py`` (gated behind a marker) for the real-binary
smoke test.
"""

from __future__ import annotations

import fnmatch
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.proxy_sources import iron_proxy as ip


# ---------------------------------------------------------------------------
# Per-test isolation
# ---------------------------------------------------------------------------


@pytest.fixture
def hermes_home(tmp_path, monkeypatch):
    """Point HERMES_HOME at a temp dir so install paths don't touch the real $HOME."""

    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    # Make sure no stale provider keys influence discovery.
    for key in list(os.environ):
        if key.endswith("_API_KEY"):
            monkeypatch.delenv(key, raising=False)
    return home


# ---------------------------------------------------------------------------
# Token mint + mapping discovery
# ---------------------------------------------------------------------------


def test_mint_proxy_token_has_prefix_and_length():
    t = ip.mint_proxy_token("alpha")
    assert t.startswith("alpha-")
    assert len(t) >= len("alpha-") + 32






    # Unknown providers (no entry in _BEARER_PROVIDERS) are skipped, not warned.




# ---------------------------------------------------------------------------
# Config / mapping serialization
# ---------------------------------------------------------------------------


def _sample_mapping(env_name: str = "OPENROUTER_API_KEY") -> ip.TokenMapping:
    return ip.TokenMapping(
        proxy_token=ip.mint_proxy_token("test"),
        real_env_name=env_name,
        upstream_hosts=("openrouter.ai", "*.openrouter.ai"),
    )




def test_build_proxy_config_custom_allowed_hosts(tmp_path):
    m = _sample_mapping("OPENAI_API_KEY")
    cfg = ip.build_proxy_config(
        mappings=[m],
        ca_cert=tmp_path / "ca.crt",
        ca_key=tmp_path / "ca.key",
        allowed_hosts=["custom-host.test"],
    )
    domains = cfg["transforms"][0]["config"]["domains"]
    # Custom allowed_hosts wins as the base; mapping's hosts get appended.
    assert "custom-host.test" in domains
    assert "openrouter.ai" in domains  # comes from the mapping


# ---------------------------------------------------------------------------
# Default SSRF deny list (regression: docs promise cloud metadata is denied)
# ---------------------------------------------------------------------------








# ---------------------------------------------------------------------------
# Bind policy (regression: must not bind 0.0.0.0)
# ---------------------------------------------------------------------------












# ---------------------------------------------------------------------------
# audit_log file pre-creation (parameter still accepted; v0.39 doesn't
# wire it into the binary config but ensure_audit_log() still creates
# the file at 0o600 as a logrotate / monitoring sentinel)
# ---------------------------------------------------------------------------


def test_audit_log_kwarg_does_not_inject_audit_path_v039(tmp_path):
    """v0.39 of iron-proxy rejects ``log.audit_path`` (not a struct
    field).  build_proxy_config still accepts the audit_log kwarg for
    forward compatibility but MUST NOT emit it into the rendered yaml
    until the upstream binary supports it.  See the kwarg's docstring
    for the upgrade path."""

    cfg = ip.build_proxy_config(
        mappings=[_sample_mapping()],
        ca_cert=tmp_path / "ca.crt",
        ca_key=tmp_path / "ca.key",
        audit_log=tmp_path / "audit.log",
    )
    assert "audit_path" not in cfg["log"], (
        "iron-proxy v0.39 has no log.audit_path field; emitting it "
        "causes 'field audit_path not found in type config.Log' at "
        "daemon start.  ensure_audit_log() still creates the file as "
        "an operator-facing logrotate target."
    )








def test_load_mappings_handles_corrupt_json(hermes_home):
    state = ip._proxy_state_dir()
    (state / "mappings.json").write_text("{not json", encoding="utf-8")
    assert ip.load_mappings() == []




# ---------------------------------------------------------------------------
# Token-preservation on re-setup (regression: clobbered live sandboxes)
# ---------------------------------------------------------------------------








# ---------------------------------------------------------------------------
# Uncovered provider detection (regression: signature-auth providers bypass)
# ---------------------------------------------------------------------------










# ---------------------------------------------------------------------------
# Binary discovery + lazy install
# ---------------------------------------------------------------------------






def _make_fake_tar(binary_name: str, payload: bytes = b"#!/bin/sh\necho ok\n") -> bytes:
    """Build a tar.gz with one file at the root, named ``binary_name``."""

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=binary_name)
        info.size = len(payload)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()








# ── GPG release-signature verification (maxpetrusenko P1) ────────────────────

def test_verify_checksums_signature_skips_without_gpg(hermes_home, monkeypatch, tmp_path):
    """No gpg on PATH → degrade gracefully (return False), do not raise."""
    monkeypatch.setattr(ip.shutil, "which", lambda name: None)
    cks = tmp_path / "checksums.txt"
    cks.write_text("abc  iron-proxy.tar.gz\n")
    assert ip._verify_checksums_signature(tmp_path, cks) is False










def test_pick_tar_member_rejects_path_traversal():
    """A malicious tar that escapes via '..' must be refused."""

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="../iron-proxy")
        info.size = 1
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(b"x"))
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="Could not find iron-proxy"):
            ip._pick_tar_member(tf, "iron-proxy")


# ---------------------------------------------------------------------------
# Subprocess lifecycle
# ---------------------------------------------------------------------------


















def test_start_proxy_idempotent_when_already_running(hermes_home, monkeypatch):
    state = ip._proxy_state_dir()
    pid_file = state / "iron-proxy.pid"
    pid_file.write_text("12345")
    monkeypatch.setattr(ip, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(ip, "_port_listening", lambda h, p: True)
    monkeypatch.setattr(ip, "iron_proxy_version", lambda b: "test")
    # Materialize config so we get past that check (we shouldn't reach it,
    # but if the idempotent path regresses we want a clean failure mode).
    (state / "proxy.yaml").write_text("proxy: {}")
    # Sentinel: subprocess.Popen must NOT be called.
    with patch("subprocess.Popen", lambda *a, **k: pytest.fail("should not spawn")):
        status = ip.start_proxy()
    # Should return without spawning anything.
    assert status is not None


# ---------------------------------------------------------------------------
# Docker integration
# ---------------------------------------------------------------------------












# ---------------------------------------------------------------------------
# Platform asset name resolution
# ---------------------------------------------------------------------------






# ---------------------------------------------------------------------------
# Subprocess env minimization (regression: host secrets leaked to proxy)
# ---------------------------------------------------------------------------


def test_subprocess_env_strips_unrelated_secrets(hermes_home, monkeypatch):
    """``_build_proxy_subprocess_env`` must NOT carry every host secret
    over to the proxy.  /proc/<pid>/environ on the proxy would otherwise
    expose all of them to same-uid local processes."""

    # Unrelated env vars that should NOT propagate.
    monkeypatch.setenv("MY_PRIVATE_TOKEN", "should-not-leak")
    monkeypatch.setenv("DATABASE_URL", "postgres://very-private")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-very-secret")
    # Provider keys that ARE in load_mappings should propagate.
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-real")
    ip.write_mappings([_sample_mapping("OPENROUTER_API_KEY")])

    env = ip._build_proxy_subprocess_env()
    assert "MY_PRIVATE_TOKEN" not in env
    assert "DATABASE_URL" not in env
    assert "SLACK_BOT_TOKEN" not in env
    assert env.get("OPENROUTER_API_KEY") == "sk-or-real"






# ---------------------------------------------------------------------------
# CA generation TOCTOU (regression: 0o600 only set AFTER copy)
# ---------------------------------------------------------------------------


def test_ca_key_created_with_0o600(hermes_home, monkeypatch):
    """The CA private key must NEVER exist on disk with default umask
    permissions, even transiently.  Fix: open with explicit mode=0o600
    so the very first byte is written under tight perms."""

    # ensure_ca_cert shells out to openssl; mock the subprocess.run calls
    # so we don't need openssl on the test host AND don't depend on its
    # output format.
    def fake_run(args, **kwargs):
        # First call: genrsa → -out is at args[-2]
        if args[1] == "genrsa":
            out = args[-2]
            Path(out).write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")
        elif args[1] == "req":
            # Find -out path
            i = args.index("-out")
            Path(args[i + 1]).write_bytes(b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
        result = MagicMock()
        result.returncode = 0
        return result

    monkeypatch.setattr(ip.shutil, "which", lambda name: "/usr/bin/openssl" if name == "openssl" else None)
    monkeypatch.setattr(ip.subprocess, "run", fake_run)

    ca_crt, ca_key = ip.ensure_ca_cert()
    assert ca_key.exists()
    mode = ca_key.stat().st_mode & 0o777
    assert mode == 0o600, f"CA key has perms {oct(mode)}, expected 0o600"


# ---------------------------------------------------------------------------
# Audit log permissions (regression: depended on umask)
# ---------------------------------------------------------------------------


def test_ensure_audit_log_creates_with_0o600(hermes_home, tmp_path):
    audit = tmp_path / "audit.log"
    ip.ensure_audit_log(audit)
    assert audit.exists()
    mode = audit.stat().st_mode & 0o777
    assert mode == 0o600


def test_ensure_audit_log_tightens_existing_perms(hermes_home, tmp_path):
    audit = tmp_path / "audit.log"
    audit.write_text("preexisting content\n")
    os.chmod(audit, 0o644)
    ip.ensure_audit_log(audit)
    mode = audit.stat().st_mode & 0o777
    assert mode == 0o600


# ---------------------------------------------------------------------------
# State dir hardening (regression: world-traversable on multi-user hosts)
# ---------------------------------------------------------------------------


def test_proxy_state_dir_is_0o700(hermes_home):
    state = ip._proxy_state_dir()
    mode = state.stat().st_mode & 0o777
    assert mode == 0o700




# ---------------------------------------------------------------------------
# Mappings clobber refused when corrupt (regression: silent 403s)
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# CA missing → enforce_on_docker semantics (regression: silent fail-open)
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Docker env collision detection (regression: docker_env silently bypassed proxy)
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# v3 round: bridge-IP parser hardening (P1 #1)
# ---------------------------------------------------------------------------








# ---------------------------------------------------------------------------
# v3: default deny-list adjacency (P2 IPv4-mapped-v6 + CGNAT)
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Header-auth providers (x-api-key family) — match_headers + aliases
# ---------------------------------------------------------------------------










def test_mappings_roundtrip_preserves_headers_and_aliases(hermes_home):
    m = ip.TokenMapping(
        proxy_token=ip.mint_proxy_token("gemini"),
        real_env_name="GEMINI_API_KEY",
        upstream_hosts=("generativelanguage.googleapis.com",),
        match_headers=("x-goog-api-key",),
        alias_env_names=("GOOGLE_API_KEY",),
    )
    ip.write_mappings([m])
    loaded = ip.load_mappings()
    assert loaded[0].match_headers == ("x-goog-api-key",)
    assert loaded[0].alias_env_names == ("GOOGLE_API_KEY",)








# ---------------------------------------------------------------------------
# Management API (hot reload)
# ---------------------------------------------------------------------------




def test_ensure_management_token_persists_and_is_stable(hermes_home):
    t1 = ip.ensure_management_token()
    t2 = ip.ensure_management_token()
    assert t1 == t2
    assert t1.startswith("hermes-mgmt-")
    p = ip._proxy_state_dir() / "management.token"
    assert p.exists()
    assert (p.stat().st_mode & 0o777) == 0o600




def test_reload_proxy_refuses_when_not_running(hermes_home, monkeypatch):
    monkeypatch.setattr(ip, "_read_pid", lambda: None)
    with pytest.raises(RuntimeError, match="not running"):
        ip.reload_proxy()




def test_reload_proxy_posts_bearer_to_management_endpoint(hermes_home, monkeypatch):
    monkeypatch.setattr(ip, "_read_pid", lambda: 4242)
    monkeypatch.setattr(ip, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        ip, "_read_management_listen_from_config",
        lambda config_path=None: ("127.0.0.1", 9092),
    )
    ip.ensure_management_token()

    captured = {}

    class _FakeResp:
        status = 200
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["auth"] = req.get_header("Authorization")
        return _FakeResp()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert ip.reload_proxy() is True
    assert captured["url"] == "http://127.0.0.1:9092/v1/reload"
    assert captured["method"] == "POST"
    token = (ip._proxy_state_dir() / "management.token").read_text().strip()
    assert captured["auth"] == f"Bearer {token}"


def test_start_proxy_injects_management_key_env(hermes_home, monkeypatch):
    """When the generated config has a management listener, start_proxy
    must inject the bearer key env var — v0.39 refuses to start when
    api_key_env is empty."""

    cfg_path = ip._proxy_state_dir() / "proxy.yaml"
    cfg = ip.build_proxy_config(
        mappings=[_sample_mapping()],
        ca_cert=hermes_home / "ca.crt",
        ca_key=hermes_home / "ca.key",
        http_listen=["127.0.0.1:9090"],
    )
    ip.write_proxy_config(cfg)
    (hermes_home / "bin").mkdir(parents=True, exist_ok=True)
    fake_bin = hermes_home / "bin" / "iron-proxy"
    fake_bin.write_text("#!/bin/sh\nsleep 60\n")
    fake_bin.chmod(0o755)

    captured_env = {}

    class _FakeProc:
        pid = 99999
        def poll(self):
            return None

    def fake_popen(cmd, **kw):
        captured_env.update(kw.get("env") or {})
        return _FakeProc()

    monkeypatch.setattr(ip.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(ip, "_write_pidfile_safely", lambda pf, pid: None)
    monkeypatch.setattr(ip, "_port_listening", lambda h, p: True)
    monkeypatch.setattr(ip, "get_status", lambda: ip.ProxyStatus(pid=99999, listening=True))

    ip.start_proxy(binary=fake_bin, config_path=cfg_path, install_if_missing=False)
    assert captured_env.get(ip._MGMT_API_KEY_ENV)
    assert captured_env[ip._MGMT_API_KEY_ENV].startswith("hermes-mgmt-")


# ---------------------------------------------------------------------------
# v3: _pid_proc_starttime parser (handles comm with parens, brackets)
# ---------------------------------------------------------------------------






# ---------------------------------------------------------------------------
# v3: stop_proxy SIGKILL suppression on pid recycle (P3 #5 coverage gap)
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# v3: _reset_for_tests actually clears module state (P3 #1)
# ---------------------------------------------------------------------------


def test_reset_for_tests_clears_version_cache_and_nonce():
    """_reset_for_tests must clear _VERSION_CACHE and _proxy_nonce so
    in-process callers don't see leakage between tests."""

    ip._VERSION_CACHE["dummy"] = "v0.0.0-fake"
    ip._proxy_nonce = "fake-nonce-12345"
    ip._reset_for_tests()
    assert ip._VERSION_CACHE == {}
    assert ip._proxy_nonce is None


# ---------------------------------------------------------------------------
# v3: version cache doesn't poison on empty stdout (P2 _VERSION_CACHE bug B)
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# v3: NODE_OPTIONS append-merge in docker env (arshkumarsingh #1)
# ---------------------------------------------------------------------------


def test_docker_egress_node_options_uses_sentinel(hermes_home, monkeypatch):
    """``_egress_proxy_args_for_docker`` should NOT put NODE_OPTIONS in
    env_overrides directly; it uses a sentinel key
    ``_HERMES_EGRESS_NODE_OPTIONS_APPEND`` so DockerEnvironment can
    append-merge with the operator's existing NODE_OPTIONS."""

    from tools.environments.docker import _egress_proxy_args_for_docker
    from hermes_cli.config import load_config, save_config

    state = ip._proxy_state_dir()
    ca = state / "ca.crt"
    ca.write_text("fake-ca")
    (state / "ca.key").write_text("fake-key")
    mapping = _sample_mapping("OPENROUTER_API_KEY")
    proxy_cfg = ip.build_proxy_config(
        mappings=[mapping], ca_cert=ca, ca_key=state / "ca.key", tunnel_port=9090,
    )
    ip.write_proxy_config(proxy_cfg)
    ip.write_mappings([mapping])

    cfg = load_config()
    cfg.setdefault("proxy", {})["enabled"] = True
    cfg["proxy"]["enforce_on_docker"] = True
    save_config(cfg)

    (state / "iron-proxy.pid").write_text("99999")
    monkeypatch.setattr(ip, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(ip, "_port_listening", lambda h, p: True)

    _, env, _ = _egress_proxy_args_for_docker()
    # The egress dict should contain the sentinel, NOT a raw NODE_OPTIONS.
    assert env.get("_HERMES_EGRESS_NODE_OPTIONS_APPEND") == "--use-openssl-ca"
    assert "NODE_OPTIONS" not in env, (
        "NODE_OPTIONS in egress env_overrides would clobber the operator's "
        "docker_env NODE_OPTIONS — that's exactly the bug arshkumarsingh "
        "flagged."
    )


# ---------------------------------------------------------------------------
# v3: ensure_audit_log fails loud on OSError (P2 promise mismatch)
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# v3: persisted nonce roundtrip (stephenschoettler #3 cross-CLI defense)
# ---------------------------------------------------------------------------


def test_persisted_nonce_roundtrip(hermes_home, monkeypatch):
    """Write the nonce next to the pidfile (simulating one CLI invocation
    finishing start_proxy), then verify a fresh _read_persisted_nonce
    can pick it up — that's what cross-process _pid_alive uses."""

    nonce_path = ip._persisted_nonce_path()
    nonce_path.parent.mkdir(parents=True, exist_ok=True)
    nonce_path.write_text("test-nonce-abc123")
    assert ip._read_persisted_nonce() == "test-nonce-abc123"




# ---------------------------------------------------------------------------
# v4 round (GodsBoy follow-up): bind-host-aware liveness probes +
# allow_env_fallback on the partial-secret path
# ---------------------------------------------------------------------------






def test_get_status_probes_configured_bind_host(hermes_home, monkeypatch):
    """get_status must probe the configured bind host (e.g. the docker
    bridge IP), not loopback unconditionally."""

    state = ip._proxy_state_dir()
    (state / "proxy.yaml").write_text(
        "proxy:\n  http_listen: 172.17.0.1:9123\n", encoding="utf-8"
    )
    (state / "ca.crt").write_text("cert")
    ip._write_pidfile_safely(ip._pidfile(), 99999)
    monkeypatch.setattr(ip, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(ip, "find_iron_proxy", lambda **kw: None)

    probed = {}

    def fake_probe(host, port):
        probed["host"] = host
        probed["port"] = port
        return True

    monkeypatch.setattr(ip, "_port_listening", fake_probe)
    status = ip.get_status()
    assert probed == {"host": "172.17.0.1", "port": 9123}
    assert status.listening is True
    assert status.tunnel_port == 9123


def test_partial_bitwarden_secrets_honor_allow_env_fallback(
    hermes_home, monkeypatch,
):
    """The missing-secret branch's own error message tells operators to
    set proxy.allow_env_fallback — so the flag must actually work there
    (previously only the empty-token branch honored it)."""

    ip.write_mappings([_sample_mapping("OPENROUTER_API_KEY")])
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-host-fallback")

    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(
        bw, "fetch_bitwarden_secrets", lambda **kw: ({}, []),
    )
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    bw_cfg = {
        "project_id": "proj",
        "access_token_env": "BWS_ACCESS_TOKEN",
        "allow_env_fallback": True,
    }

    env = ip._build_proxy_subprocess_env(
        refresh_from_bitwarden=True, bitwarden_config=bw_cfg,
    )
    # Falls back to the host env value instead of raising.
    assert env.get("OPENROUTER_API_KEY") == "sk-host-fallback"


def test_partial_bitwarden_secrets_raise_without_fallback(
    hermes_home, monkeypatch,
):
    """Strict default: missing BWS secrets raise."""

    ip.write_mappings([_sample_mapping("OPENROUTER_API_KEY")])
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-host")

    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(
        bw, "fetch_bitwarden_secrets", lambda **kw: ({}, []),
    )
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    bw_cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}

    with pytest.raises(RuntimeError, match="did not return secrets"):
        ip._build_proxy_subprocess_env(
            refresh_from_bitwarden=True, bitwarden_config=bw_cfg,
        )


def test_bitwarden_importerror_raise_without_fallback(
    hermes_home, monkeypatch,
):
    """Strict default: ImportError on BWS module raises when
    allow_env_fallback is unset, matching the sibling branches."""

    ip.write_mappings([_sample_mapping("OPENROUTER_API_KEY")])
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-host")

    # Simulate the BWS SDK not being installed.  The lazy import
    # ``from agent.secret_sources import bitwarden`` inside
    # _build_proxy_subprocess_env resolves through the parent package's
    # cached attribute; deleting both the sys.modules entry AND the
    # parent-package attribute forces a real import that we intercept.
    #
    # In addition, block importlib.reload in case the test infra used it.
    import agent.secret_sources as ss
    monkeypatch.delitem(sys.modules, "agent.secret_sources.bitwarden", raising=False)
    monkeypatch.delitem(sys.modules, "agent.secret_sources.bitwarden.bws", raising=False)
    monkeypatch.delattr(ss, "bitwarden", raising=False)

    # Now block the re-import.  ``from agent.secret_sources import
    # bitwarden`` resolves to a submodule attribute; setting it to a
    # sentinel that raises on attribute access is more reliable than
    # trying to intercept __import__ at the C level.
    class _MissingBWS:
        """Sentinel: accessing any attribute raises ImportError."""
        def __getattr__(self, _name):
            raise ImportError("bws SDK not installed")
        def __call__(self, *a, **kw):
            raise ImportError("bws SDK not installed")
    monkeypatch.setattr(ss, "bitwarden", _MissingBWS(), raising=False)

    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    bw_cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}

    with pytest.raises(RuntimeError, match="Bitwarden refresh module unavailable"):
        ip._build_proxy_subprocess_env(
            refresh_from_bitwarden=True, bitwarden_config=bw_cfg,
        )


# ---------------------------------------------------------------------------
# Required data-provider scopes, per-host method/query scoping, durable
# mappings and the public-host policy (stage-2 native egress work)
# ---------------------------------------------------------------------------

# Frozen stage-1 contract for the required data providers: canonical env
# name plus aliases, exact hosts, exact credential location(s) and the
# per-host method scope.  Mirrors the reviewed credential inventory; the
# disabled Solodit entry is deliberately absent.
_REQUIRED_SCOPES = {
    "XAI_API_KEY": dict(
        aliases=("GROK_API_KEY", "XAI_GROK_API_KEY"),
        hosts=("api.x.ai",),
        match_headers=("Authorization",),
        methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        match_query=False,
    ),
    "ARKHAM_API_KEY": dict(
        aliases=(),
        hosts=("api.arkm.com",),
        match_headers=("API-Key",),
        methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        match_query=False,
    ),
    "ETHERSCAN_API_KEY": dict(
        aliases=(),
        hosts=(
            "api.etherscan.io",
            "api.basescan.org",
            "api.arbiscan.io",
            "api-optimistic.etherscan.io",
        ),
        match_headers=(),
        methods=("GET", "HEAD", "POST"),
        match_query=True,
    ),
    "COINGECKO_DEMO_API_KEY": dict(
        aliases=("COINGECKO_API_KEY",),
        hosts=("api.coingecko.com",),
        match_headers=("x-cg-demo-api-key",),
        methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        match_query=False,
    ),
    "FIRECRAWL_API_KEY": dict(
        aliases=(),
        hosts=("api.firecrawl.dev",),
        match_headers=("Authorization",),
        methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        match_query=False,
    ),
    "TENDERLY_ACCESS_TOKEN": dict(
        aliases=("TENDERLY_ACCESS_KEY", "TENDERLY_API_KEY"),
        hosts=("api.tenderly.co",),
        match_headers=("X-Access-Key",),
        methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        match_query=False,
    ),
    "OPENROUTER_API_KEY": dict(
        aliases=(),
        hosts=("openrouter.ai", "*.openrouter.ai"),
        match_headers=("Authorization",),
        methods=("POST",),
        match_query=False,
    ),
}


def _secret_rules(config):
    return [
        secret
        for transform in config["transforms"]
        if transform["name"] == "secrets"
        for secret in transform["config"]["secrets"]
    ]


def _glob_matches(host: str, pattern: str) -> bool:
    """Mirror iron-proxy's documented host-glob semantics for assertions.

    ``*`` matches any host; ``*.example.com`` matches ``example.com`` and
    every subdomain depth; anything else is a path-style glob (hostnames
    contain no ``/``, so fnmatch is exact here).
    """
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) or host == pattern[2:]
    return fnmatch.fnmatchcase(host, pattern)


def test_required_data_providers_discovered_with_exact_scope():
    """Every required data provider is a first-class registry entry with the
    frozen canonical name, aliases, hosts, credential locations and the
    per-host method scope."""

    names = list(_REQUIRED_SCOPES)
    discovered = ip.discover_provider_mappings(available_env_names=names)
    by_name = {m.real_env_name: m for m in discovered}
    assert set(by_name) == set(names)
    for name, scope in _REQUIRED_SCOPES.items():
        m = by_name[name]
        assert set(m.alias_env_names) == set(scope["aliases"]), name
        assert set(m.upstream_hosts) == set(scope["hosts"]), name
        assert tuple(m.methods) == scope["methods"], name
        assert set(h.lower() for h in m.match_headers) == set(
            h.lower() for h in scope["match_headers"]
        ), name
        assert m.match_query is scope["match_query"], name


def test_alias_only_discovery_collapses_to_canonical():
    """An alias in the host env alone mints ONE mapping under the canonical
    name (two require-rules on the same host would reject each other)."""

    for name, scope in _REQUIRED_SCOPES.items():
        for alias in scope["aliases"]:
            got = ip.discover_provider_mappings(available_env_names=[alias])
            assert len(got) == 1, alias
            assert got[0].real_env_name == name, alias


def test_coingecko_pro_credential_not_discovered():
    """Demo-only: a Pro env name must never mint a mapping or collapse into
    the Demo family."""

    assert ip.discover_provider_mappings(
        available_env_names=["COINGECKO_PRO_API_KEY"]
    ) == []


def test_generated_rules_carry_exact_scopes(tmp_path):
    """Generated secrets rules keep the exact host/header/query/method scope
    (including an intentionally empty header list for query-only auth)."""

    names = list(_REQUIRED_SCOPES)
    discovered = ip.discover_provider_mappings(available_env_names=names)
    config = ip.build_proxy_config(
        mappings=discovered,
        ca_cert=tmp_path / "ca.crt",
        ca_key=tmp_path / "ca.key",
    )
    rules = _secret_rules(config)
    by_name = {r["source"]["var"]: r for r in rules}
    assert set(by_name) == set(names)
    for name, scope in _REQUIRED_SCOPES.items():
        rule = by_name[name]
        replace = rule["replace"]
        assert set(h.lower() for h in replace["match_headers"]) == set(
            h.lower() for h in scope["match_headers"]
        ), name
        assert replace["match_query"] is scope["match_query"], name
        assert replace["require"] is True, name
        hosts = [entry["host"] for entry in rule["rules"]]
        assert len(hosts) == len(set(hosts)), name
        assert set(hosts) == set(scope["hosts"]), name
        for entry in rule["rules"]:
            assert tuple(entry["methods"]) == scope["methods"], name


def test_generated_rules_never_match_connect():
    """Every generated rule is method-scoped and excludes CONNECT: the
    proxy runs the transform pipeline on the synthetic CONNECT request that
    opens each HTTPS tunnel, where no proxy token can be present yet — a
    method-less require rule would reject the tunnel itself."""

    discovered = ip.discover_provider_mappings(
        available_env_names=list(ip._BEARER_PROVIDERS)
        + list(ip._HEADER_AUTH_PROVIDERS)
    )
    config = ip.build_proxy_config(
        mappings=discovered + [
            # explicit-method mapping keeps its own (CONNECT-free) scope
            ip.TokenMapping(
                proxy_token=ip.mint_proxy_token("custom"),
                real_env_name="CUSTOM_QUERY_KEY",
                upstream_hosts=("custom.example",),
                match_headers=(),
                methods=("POST",),
                match_query=True,
            ),
        ],
        ca_cert=Path("/fixture/ca.crt"),
        ca_key=Path("/fixture/ca.key"),
    )
    for rule in _secret_rules(config):
        for entry in rule["rules"]:
            methods = entry.get("methods")
            assert methods, rule["source"]["var"]
            assert "CONNECT" not in methods, rule["source"]["var"]


def test_cli_subscription_oauth_hosts_never_swapped(tmp_path):
    """Codex/CLI subscription OAuth endpoints pass through unchanged; no
    generated rule matches auth.openai.com / chatgpt.com for any of the
    built-in providers (their keys must never be substituted there)."""

    discovered = ip.discover_provider_mappings(
        available_env_names=list(ip._BEARER_PROVIDERS)
        + list(ip._HEADER_AUTH_PROVIDERS)
    )
    config = ip.build_proxy_config(
        mappings=discovered,
        ca_cert=tmp_path / "ca.crt",
        ca_key=tmp_path / "ca.key",
    )
    oauth_hosts = ("auth.openai.com", "chatgpt.com", "api.chatgpt.com")
    for rule in _secret_rules(config):
        for entry in rule["rules"]:
            for host in oauth_hosts:
                assert not _glob_matches(host, entry["host"]), (
                    f"{rule['source']['var']} would swap on {host}"
                )


def test_mappings_roundtrip_preserves_scope_fields(hermes_home):
    """write_mappings/load_mappings round-trips method scope, per-mapping
    query matching and an explicitly empty header list."""

    mappings = ip.discover_provider_mappings(
        available_env_names=list(_REQUIRED_SCOPES)
    )
    ip.write_mappings(mappings)
    assert ip.load_mappings() == mappings


def test_legacy_mappings_file_loads_with_bearer_defaults(hermes_home):
    """mappings.json written before the scope fields existed still loads:
    Authorization header, no explicit method scope, query matching on."""

    import json as _json

    state = ip._proxy_state_dir()
    (state / "mappings.json").write_text(_json.dumps({
        "version": 1,
        "tokens": [{
            "proxy_token": "hermes-proxy-legacy",
            "env_name": "OPENAI_API_KEY",
            "upstream_hosts": ["api.openai.com"],
        }],
    }))
    loaded = ip.load_mappings()
    assert len(loaded) == 1
    assert loaded[0].match_headers == ("Authorization",)
    assert loaded[0].methods == ()
    assert loaded[0].match_query is True


def test_merge_refreshes_scope_and_preserves_tokens():
    """Rediscovery keeps minted tokens but refreshes changed scopes; rotation
    still mints fresh tokens."""

    existing = [ip.TokenMapping(
        proxy_token="hermes-proxy-old",
        real_env_name="ARKHAM_API_KEY",
        upstream_hosts=("api.arkm.com",),
        match_headers=("Authorization",),
        methods=(),
        match_query=True,
    )]
    discovered = ip.discover_provider_mappings(available_env_names=["ARKHAM_API_KEY"])
    merged = ip.merge_mappings(existing=existing, discovered=discovered)
    assert merged[0].proxy_token == "hermes-proxy-old"
    assert tuple(merged[0].match_headers) == ("API-Key",)
    assert tuple(merged[0].methods) == _REQUIRED_SCOPES["ARKHAM_API_KEY"]["methods"]
    assert merged[0].match_query is False
    rotated = ip.merge_mappings(existing=existing, discovered=discovered, rotate=True)
    assert rotated[0].proxy_token != "hermes-proxy-old"


def test_public_host_policy_flag(tmp_path):
    """allow_public_hosts=True makes the generated allowlist permissive for
    general public traffic while the SSRF deny list and host-scoped secrets
    stay intact; the default keeps the strict list."""

    mapping = _sample_mapping("OPENAI_API_KEY")
    strict = ip.build_proxy_config(
        mappings=[mapping], ca_cert=tmp_path / "ca.crt", ca_key=tmp_path / "ca.key",
    )
    public = ip.build_proxy_config(
        mappings=[mapping], ca_cert=tmp_path / "ca.crt", ca_key=tmp_path / "ca.key",
        allow_public_hosts=True,
    )
    strict_domains = strict["transforms"][0]["config"]["domains"]
    public_domains = public["transforms"][0]["config"]["domains"]
    assert "*" not in strict_domains
    assert "*" in public_domains
    # SSRF defaults survive the permissive allowlist.
    assert strict["proxy"]["upstream_deny_cidrs"] == public["proxy"]["upstream_deny_cidrs"]
    assert "169.254.0.0/16" in public["proxy"]["upstream_deny_cidrs"]
    # Secrets stay host-scoped under the public policy.
    rule = next(
        r for r in _secret_rules(public)
        if r["source"]["var"] == "OPENAI_API_KEY"
    )
    assert [entry["host"] for entry in rule["rules"]] == list(mapping.upstream_hosts)
    assert "*" not in [entry["host"] for entry in rule["rules"]]


def test_registry_conflict_detection():
    """Conflicting host/header scope for the same env name (canonical or
    alias) fails closed; the production registry is conflict-free."""

    assert ip.find_registry_conflicts() == []
    conflicting = {
        "ALPHA_API_KEY": {"hosts": ("api.alpha.example",), "match_headers": ("Authorization",), "aliases": ()},
        "BETA_API_KEY": {"hosts": ("api.alpha.example",), "match_headers": ("Authorization",), "aliases": ("ALPHA_API_KEY",)},
    }
    conflicts = ip.find_registry_conflicts(conflicting)
    assert conflicts, "same env name with a different provider must be reported"


def test_missing_required_mapping_refuses_before_container_creation(hermes_home, monkeypatch):
    """With proxy.required_env_names configured, a sandbox is refused when a
    required provider has no minted mapping — the failure lands before any
    container is created (enforce_on_docker), not inside the sandbox."""

    from tools.environments.docker import _egress_proxy_args_for_docker
    from hermes_cli.config import load_config, save_config

    state = ip._proxy_state_dir()
    (state / "ca.crt").write_text("fake-ca")
    (state / "ca.key").write_text("fake-key")
    mapping = _sample_mapping("OPENROUTER_API_KEY")
    proxy_cfg = ip.build_proxy_config(
        mappings=[mapping], ca_cert=state / "ca.crt", ca_key=state / "ca.key",
    )
    ip.write_proxy_config(proxy_cfg)
    ip.write_mappings([mapping])

    cfg = load_config()
    cfg.setdefault("proxy", {})["enabled"] = True
    cfg["proxy"]["enforce_on_docker"] = True
    cfg["proxy"]["required_env_names"] = ["OPENROUTER_API_KEY", "ARKHAM_API_KEY"]
    save_config(cfg)

    (state / "iron-proxy.pid").write_text("99999")
    monkeypatch.setattr(ip, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(ip, "_port_listening", lambda h, p: True)

    with pytest.raises(RuntimeError, match="ARKHAM_API_KEY"):
        _egress_proxy_args_for_docker()

    # Satisfying the requirement makes the same state start cleanly.
    cfg = load_config()
    cfg["proxy"]["required_env_names"] = ["OPENROUTER_API_KEY"]
    save_config(cfg)
    volume_args, env, host_args = _egress_proxy_args_for_docker()
    assert env.get("OPENROUTER_API_KEY") == mapping.proxy_token




# ---------------------------------------------------------------------------
# D5: alias-family credential-VALUE validation (spec review S2-R2)
# ---------------------------------------------------------------------------

# Frozen families used by the value-validation matrix (canonical, aliases)
_FAMILY_MATRIX = [
    ("XAI_API_KEY", ("GROK_API_KEY", "XAI_GROK_API_KEY")),
    ("TENDERLY_ACCESS_TOKEN", ("TENDERLY_ACCESS_KEY", "TENDERLY_API_KEY")),
    ("COINGECKO_DEMO_API_KEY", ("COINGECKO_API_KEY",)),
]


def _family_mapping(canonical: str, aliases=()) -> ip.TokenMapping:
    return ip.TokenMapping(
        proxy_token=ip.mint_proxy_token("fam"),
        real_env_name=canonical,
        upstream_hosts=("api.family.test",),
        alias_env_names=tuple(aliases),
    )


@pytest.mark.parametrize("canonical,aliases", _FAMILY_MATRIX)
def test_family_value_conflicts_matrix(canonical, aliases):
    """One non-empty value (or equal repeats) passes; different non-empty
    values fail closed; empty/whitespace values count as absent."""
    m = [_family_mapping(canonical, aliases)]
    alias0 = aliases[0]
    ok_cases = [
        {canonical: "v1"},                 # canonical-only
        {alias0: "v1"},                    # alias-only
        {canonical: "v1", alias0: "v1"},   # equal values
        {canonical: "", alias0: "v1"},     # empty canonical
        {canonical: "   ", alias0: "v1"},  # whitespace-only canonical
        {canonical: "v1", alias0: " v1 "}, # whitespace-equal
        {},                                # nothing set
    ]
    for values in ok_cases:
        assert ip.find_family_value_conflicts(values, mappings=m) == [], values
    # canonical/alias conflict → canonical named, no values returned
    conflicts = ip.find_family_value_conflicts({canonical: "v1", alias0: "v2"}, mappings=m)
    assert conflicts == [canonical]
    if len(aliases) > 1:
        alias1 = aliases[1]
        assert ip.find_family_value_conflicts({alias0: "a", alias1: "b"}, mappings=m) == [canonical]
        assert ip.find_family_value_conflicts({alias0: "a", alias1: "a"}, mappings=m) == []


@pytest.mark.parametrize("canonical,aliases", _FAMILY_MATRIX)
def test_build_proxy_subprocess_env_rejects_conflicting_family_values(
    hermes_home, monkeypatch, canonical, aliases,
):
    """Reviewed repro: conflicting canonical/alias values must fail closed
    at proxy start — and the error must never reveal a value."""
    ip.write_mappings([_family_mapping(canonical, aliases)])
    monkeypatch.setenv(canonical, "synthetic-conflict-A")
    monkeypatch.setenv(aliases[0], "synthetic-conflict-B")

    with pytest.raises(RuntimeError) as excinfo:
        ip._build_proxy_subprocess_env()

    message = str(excinfo.value)
    assert canonical in message
    assert "synthetic-conflict-A" not in message
    assert "synthetic-conflict-B" not in message


def test_build_proxy_subprocess_env_equal_values_control(hermes_home, monkeypatch):
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    monkeypatch.setenv("XAI_API_KEY", "same-value")
    monkeypatch.setenv("GROK_API_KEY", "same-value")
    env = ip._build_proxy_subprocess_env()
    assert env.get("XAI_API_KEY") == "same-value"


def test_build_proxy_subprocess_env_alias_only_mirrors_canonical(hermes_home, monkeypatch):
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    monkeypatch.setenv("GROK_API_KEY", "alias-value")
    env = ip._build_proxy_subprocess_env()
    assert env.get("XAI_API_KEY") == "alias-value"


def test_build_proxy_subprocess_env_empty_canonical_uses_alias(hermes_home, monkeypatch):
    ip.write_mappings([
        _family_mapping("TENDERLY_ACCESS_TOKEN", ("TENDERLY_ACCESS_KEY",)),
    ])
    monkeypatch.setenv("TENDERLY_ACCESS_TOKEN", "   ")
    monkeypatch.setenv("TENDERLY_ACCESS_KEY", "alias-value")
    env = ip._build_proxy_subprocess_env()
    assert env.get("TENDERLY_ACCESS_TOKEN") == "alias-value"


def test_build_proxy_subprocess_env_rotation_mismatch_fails_at_restart(hermes_home, monkeypatch):
    """Restart/rotation semantics: build once with equal values, then
    re-run with a half-rotated family (canonical rotated, alias stale) —
    the second start must fail closed."""
    ip.write_mappings([_family_mapping("COINGECKO_DEMO_API_KEY", ("COINGECKO_API_KEY",))])
    monkeypatch.setenv("COINGECKO_DEMO_API_KEY", "v1")
    monkeypatch.setenv("COINGECKO_API_KEY", "v1")
    assert ip._build_proxy_subprocess_env().get("COINGECKO_DEMO_API_KEY") == "v1"

    monkeypatch.setenv("COINGECKO_DEMO_API_KEY", "v2")  # rotated; alias stale
    with pytest.raises(RuntimeError, match="COINGECKO_DEMO_API_KEY"):
        ip._build_proxy_subprocess_env()


def test_build_proxy_subprocess_env_extra_env_conflict_fails_closed(hermes_home, monkeypatch):
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    monkeypatch.setenv("XAI_API_KEY", "v")
    monkeypatch.setenv("GROK_API_KEY", "v")
    with pytest.raises(RuntimeError, match="XAI_API_KEY"):
        ip._build_proxy_subprocess_env(extra_env={"XAI_API_KEY": "other"})


def test_build_proxy_subprocess_env_rejects_bws_internal_conflict(hermes_home, monkeypatch):
    """A Bitwarden project carrying two different values across one family
    fails closed instead of silently collapsing onto the canonical."""
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(
        bw, "fetch_bitwarden_secrets",
        lambda **kw: ({"XAI_API_KEY": "fresh-A", "GROK_API_KEY": "fresh-B"}, []),
    )
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}

    with pytest.raises(RuntimeError) as excinfo:
        ip._build_proxy_subprocess_env(refresh_from_bitwarden=True, bitwarden_config=cfg)
    assert "XAI_API_KEY" in str(excinfo.value)
    assert "fresh-A" not in str(excinfo.value)
    assert "fresh-B" not in str(excinfo.value)


def test_build_proxy_subprocess_env_rejects_parent_alias_vs_bws_rotation(
    hermes_home, monkeypatch,
):
    """Cross-source conflict: freshly rotated canonical in BWS vs a stale
    alias still present in the host env fails closed."""
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    monkeypatch.setenv("GROK_API_KEY", "stale-alias")
    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(
        bw, "fetch_bitwarden_secrets",
        lambda **kw: ({"XAI_API_KEY": "rotated"}, []),
    )
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}

    with pytest.raises(RuntimeError, match="XAI_API_KEY"):
        ip._build_proxy_subprocess_env(refresh_from_bitwarden=True, bitwarden_config=cfg)


def test_family_env_names_reads_persisted_mappings(hermes_home):
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY", "XAI_GROK_API_KEY"))])
    assert ip.family_env_names() == {"XAI_API_KEY", "GROK_API_KEY", "XAI_GROK_API_KEY"}
    assert ip.is_egress_mapped_credential("GROK_API_KEY") is True
    assert ip.is_egress_mapped_credential("TENOR_API_KEY") is False


# ---------------------------------------------------------------------------
# S2-R4: complete-family resolution from every supported source (host env,
# refreshed Bitwarden values, caller overrides)
# ---------------------------------------------------------------------------


def _xai_alias_only_mapping():
    return [_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))]


def test_build_proxy_subprocess_env_host_alias_only_resolves_canonical(hermes_home, monkeypatch):
    ip.write_mappings(_xai_alias_only_mapping())
    monkeypatch.setenv("GROK_API_KEY", "synthetic-one")
    env = ip._build_proxy_subprocess_env()
    assert env.get("XAI_API_KEY") == "synthetic-one"


def test_build_proxy_subprocess_env_bws_alias_only_resolves_canonical(hermes_home, monkeypatch):
    """S2-R4 repro: a Bitwarden project provisioning ONLY the alias must
    satisfy the family — setup already persisted the canonical mapping, and
    start must not refuse on canonical-key membership alone."""
    ip.write_mappings(_xai_alias_only_mapping())
    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(
        bw, "fetch_bitwarden_secrets",
        lambda **kw: ({"GROK_API_KEY": "synthetic-one"}, []),
    )
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}

    env = ip._build_proxy_subprocess_env(refresh_from_bitwarden=True, bitwarden_config=cfg)
    assert env.get("XAI_API_KEY") == "synthetic-one"


def test_build_proxy_subprocess_env_bws_empty_canonical_alias(hermes_home, monkeypatch):
    """A whitespace-only canonical from Bitwarden must not shadow the
    populated alias — the emitted canonical is non-empty."""
    ip.write_mappings(_xai_alias_only_mapping())
    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(
        bw, "fetch_bitwarden_secrets",
        lambda **kw: ({"XAI_API_KEY": " ", "GROK_API_KEY": "synthetic-one"}, []),
    )
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}

    env = ip._build_proxy_subprocess_env(refresh_from_bitwarden=True, bitwarden_config=cfg)
    assert env.get("XAI_API_KEY") == "synthetic-one"


def test_build_proxy_subprocess_env_override_alias_only_resolves_canonical(hermes_home, monkeypatch):
    """Caller-supplied alias-only overrides resolve onto the canonical
    name the proxy config references."""
    ip.write_mappings(_xai_alias_only_mapping())
    env = ip._build_proxy_subprocess_env(extra_env={"GROK_API_KEY": "synthetic-one"})
    assert env.get("XAI_API_KEY") == "synthetic-one"


def test_build_proxy_subprocess_env_bws_alias_replaces_stale_host_same_name(hermes_home, monkeypatch):
    """Rotation: a fresh Bitwarden value for the SAME name replaces the
    stale host value by explicit precedence — the rotation is used and the
    stale value is not."""
    ip.write_mappings(_xai_alias_only_mapping())
    monkeypatch.setenv("GROK_API_KEY", "synthetic-old")
    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(
        bw, "fetch_bitwarden_secrets",
        lambda **kw: ({"GROK_API_KEY": "synthetic-one"}, []),
    )
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    cfg = {
        "project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN",
        "allow_env_fallback": True,
    }

    env = ip._build_proxy_subprocess_env(refresh_from_bitwarden=True, bitwarden_config=cfg)
    assert env.get("XAI_API_KEY") == "synthetic-one"

    # And without the fallback flag the same rotation works too — the BWS
    # value is what satisfies the family.
    strict_cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}
    env = ip._build_proxy_subprocess_env(refresh_from_bitwarden=True, bitwarden_config=strict_cfg)
    assert env.get("XAI_API_KEY") == "synthetic-one"


def test_build_proxy_subprocess_env_bws_strict_still_refuses_absent_family(hermes_home, monkeypatch):
    """The rotation guarantee is unchanged: a family with no non-empty value
    from Bitwarden (even with a stale HOST alias present) fails closed
    without the documented fallback — no silent stale-host pickup."""
    ip.write_mappings(_xai_alias_only_mapping())
    monkeypatch.setenv("GROK_API_KEY", "synthetic-old")
    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(bw, "fetch_bitwarden_secrets", lambda **kw: ({}, []))
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}

    with pytest.raises(RuntimeError, match=r"did not return secrets.*XAI_API_KEY"):
        ip._build_proxy_subprocess_env(refresh_from_bitwarden=True, bitwarden_config=cfg)


def test_build_proxy_subprocess_env_override_satisfies_strict_bws_family(hermes_home, monkeypatch):
    """An EXPLICIT caller override counts as a supported source: it satisfies
    the family-availability check even in strict Bitwarden mode (it is not
    the silent host-env fallback the strict mode forbids)."""
    ip.write_mappings(_xai_alias_only_mapping())
    import agent.secret_sources.bitwarden as bw
    monkeypatch.setattr(bw, "fetch_bitwarden_secrets", lambda **kw: ({}, []))
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}

    env = ip._build_proxy_subprocess_env(
        refresh_from_bitwarden=True, bitwarden_config=cfg,
        extra_env={"GROK_API_KEY": "synthetic-one"},
    )
    assert env.get("XAI_API_KEY") == "synthetic-one"


# ---------------------------------------------------------------------------
# S2-R4 output normalization: a blank/whitespace caller canonical must not
# overwrite the family value resolved from a populated alias — asserted on
# the FINAL returned environment and at the real launch boundary
# ---------------------------------------------------------------------------

_FINAL_VALUE = "synthetic-review-value"


def _build_final_env(monkeypatch, source: str, overrides):
    """Mirror of the reviewed output-boundary fixture: one populated alias
    source (host / Bitwarden / caller), optional caller overrides."""
    import agent.secret_sources.bitwarden as bw

    monkeypatch.setattr(
        bw, "fetch_bitwarden_secrets",
        lambda **kw: ({"GROK_API_KEY": _FINAL_VALUE} if source == "bws" else {}, []),
    )
    if source == "host":
        monkeypatch.setenv("GROK_API_KEY", _FINAL_VALUE)
    caller = {"GROK_API_KEY": _FINAL_VALUE} if source == "override" else {}
    caller.update(overrides)
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    cfg = {"project_id": "proj", "access_token_env": "BWS_ACCESS_TOKEN"}
    return ip._build_proxy_subprocess_env(
        extra_env=caller,
        refresh_from_bitwarden=(source == "bws"),
        bitwarden_config=cfg,
    )


@pytest.mark.parametrize("blank", ["", " \t"])
@pytest.mark.parametrize("source", ["host", "bws", "override"])
def test_blank_caller_canonical_keeps_resolved_family_value(
    hermes_home, monkeypatch, source, blank,
):
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    env = _build_final_env(monkeypatch, source, {"XAI_API_KEY": blank})
    assert env.get("XAI_API_KEY") == _FINAL_VALUE
    assert (env.get("XAI_API_KEY") or "").strip(), "canonical must be non-empty"
    assert env.get("XAI_API_KEY") != blank


@pytest.mark.parametrize("source", ["host", "bws", "override"])
def test_alias_only_final_env_controls(hermes_home, monkeypatch, source):
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    env = _build_final_env(monkeypatch, source, {})
    assert env.get("XAI_API_KEY") == _FINAL_VALUE


def test_non_family_caller_override_preserved_with_family_resolution(
    hermes_home, monkeypatch,
):
    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    env = _build_final_env(
        monkeypatch, "override", {"REVIEW_NON_FAMILY_SETTING": "synthetic-setting"},
    )
    assert env.get("XAI_API_KEY") == _FINAL_VALUE
    assert env.get("REVIEW_NON_FAMILY_SETTING") == "synthetic-setting"


def test_start_proxy_launch_env_resolves_blank_caller_canonical(
    hermes_home, monkeypatch,
):
    """Launch boundary: real start_proxy with extra_env carrying a blank
    canonical plus a populated alias must hand the child an env whose
    canonical is the resolved value.  Popen is intercepted — no process is
    launched."""
    import yaml

    ip.write_mappings([_family_mapping("XAI_API_KEY", ("GROK_API_KEY",))])
    state = ip._proxy_state_dir()
    config_path = state / "caller-start.yaml"
    config_path.write_text(
        yaml.safe_dump(ip.build_proxy_config(
            mappings=ip.load_mappings(),
            ca_cert=state / "synthetic-ca.crt",
            ca_key=state / "synthetic-ca.key",
            http_listen=["127.0.0.1:18080"],
        )),
        encoding="utf-8",
    )
    captured: dict = {}

    class _LaunchTripwire(Exception):
        pass

    def tripwire(*args, **kwargs):
        captured.update(kwargs.get("env") or {})
        raise _LaunchTripwire()

    monkeypatch.setattr(ip.subprocess, "Popen", tripwire)

    with pytest.raises(_LaunchTripwire):
        ip.start_proxy(
            binary=state / "synthetic-no-binary",
            config_path=config_path,
            install_if_missing=False,
            extra_env={"XAI_API_KEY": " ", "GROK_API_KEY": _FINAL_VALUE},
        )
    assert captured.get("XAI_API_KEY") == _FINAL_VALUE
