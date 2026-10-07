"""S2-R1 egress-family protection regressions for the native Docker backend.

The reviewed spec-review cases, reproduced at mocked process-IO boundaries:

* creation, init, runtime and ``docker exec`` env resolution must deliver
  the OPAQUE proxy token for every mapped family name (canonical + all
  aliases) — never the real host value, including after late skill
  registration;
* explicit ``docker_forward_env`` / ``docker_env`` / ``docker_extra_args``
  collisions with a family name fail closed BEFORE any container is
  created (enforced mode), and warn-and-preserve under the documented
  ``enforce_on_docker: false`` opt-out;
* non-mapped third-party credentials keep passing through, and the
  proxy-disabled behavior is unchanged.

No Docker daemon, no proxy binary: ``subprocess`` run/popen and the
docker-availability probes are mocked; only boolean comparisons and env
names are asserted, never real credential values.
"""

from __future__ import annotations

import contextlib
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent.proxy_sources import iron_proxy as ip
from hermes_cli import config as config_module
from tools import env_passthrough
from tools.environments import docker as docker_module

HOST_SECRET = "synthetic-host-secret"
OVERRIDE_VALUE = "synthetic-override"

# Families minted for the tests: canonical names chosen so at least one
# canonical and several aliases exercise every naming shape (an alias like
# TENDERLY_ACCESS_KEY has no _API_KEY/_TOKEN suffix).
ACTIVE_NAMES = [
    "ARKHAM_API_KEY",
    "TENDERLY_ACCESS_KEY",
    "ETHERSCAN_API_KEY",
    "GROK_API_KEY",
    "COINGECKO_API_KEY",
    "FIRECRAWL_API_KEY",
    "OPENROUTER_API_KEY",
]
NON_FAMILY_NAME = "TENOR_API_KEY"


@pytest.fixture
def egress_state(tmp_path, monkeypatch):
    """HERMES_HOME with real minted mappings + CA fixture for the backend."""
    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    for key in list(os.environ):
        if key.endswith(("_API_KEY", "_ACCESS_KEY", "_ACCESS_TOKEN", "_TOKEN")):
            monkeypatch.delenv(key, raising=False)
    mappings = ip.discover_provider_mappings(available_env_names=list(ACTIVE_NAMES))
    assert mappings, "fixture must mint mappings for the active providers"
    ip.write_mappings(mappings)
    ca = ip._proxy_state_dir() / "ca.crt"
    ca.parent.mkdir(parents=True, exist_ok=True)
    ca.write_text("SYNTHETIC PUBLIC CA FIXTURE\n", encoding="utf-8")
    tokens = {
        name: m.proxy_token
        for m in mappings
        for name in (m.real_env_name, *m.alias_env_names)
    }
    return SimpleNamespace(mappings=mappings, tokens=tokens, ca=ca, home=home)


class Build:
    """Result of one mocked DockerEnvironment construction."""

    def __init__(self):
        self.rejected = False
        self.error: Exception | None = None
        self.call_records: list = []
        self.instance = None
        self.exec_calls: list = []

    @property
    def run_envs(self) -> list:
        return [env for cmd, env in self.call_records if cmd[1:2] == ["run"]]

    @property
    def run_calls(self) -> int:
        return len(self.run_envs)


def build_environment(
    egress_state,
    *,
    skill_names=(),
    forward_names=(),
    docker_env=None,
    extra_args=None,
    enforce=True,
    proxy_enabled=True,
    passthrough_override=None,
):
    """Construct a DockerEnvironment with all process IO mocked.

    ``passthrough_override`` forces ``get_all_passthrough`` to report the
    given names — used to prove the resolver's token policy independently
    of whatever the registration gate would allow (late registration and
    residual-path defense in depth).
    """
    env_passthrough.clear_env_passthrough()
    env_passthrough._config_passthrough = frozenset()
    if skill_names:
        env_passthrough.register_env_passthrough(skill_names)

    rec = Build()

    def fake_run(command, **kwargs):
        rec.call_records.append((command, dict(kwargs.get("env") or {})))
        return SimpleNamespace(stdout="synthetic-container-id\n", stderr="", returncode=0)

    config = {
        "proxy": {
            "enabled": proxy_enabled,
            "enforce_on_docker": enforce,
            "allow_public_hosts": True,
            "required_env_names": [m.real_env_name for m in egress_state.mappings],
        }
    }
    status = SimpleNamespace(
        configured=proxy_enabled,
        listening=proxy_enabled,
        pid=123,
        tunnel_port=18080,
        ca_cert_path=egress_state.ca,
    )

    with contextlib.ExitStack() as stack:
        stack.enter_context(
            patch.dict(
                os.environ,
                {n: HOST_SECRET for n in [*ACTIVE_NAMES, NON_FAMILY_NAME]},
            )
        )
        stack.enter_context(patch.object(config_module, "load_config", return_value=config))
        stack.enter_context(patch.object(ip, "get_status", return_value=status))
        stack.enter_context(patch.object(docker_module, "_ensure_docker_available", return_value=None))
        stack.enter_context(patch.object(docker_module, "_cgroup_limits_available", return_value=True))
        stack.enter_context(patch.object(docker_module, "find_docker", return_value="/no-real-docker"))
        stack.enter_context(
            patch.object(docker_module, "_image_uses_init_entrypoint", return_value=False)
        )
        stack.enter_context(patch.object(docker_module.subprocess, "run", side_effect=fake_run))
        stack.enter_context(
            patch.object(docker_module.DockerEnvironment, "init_session", return_value=None)
        )
        if passthrough_override is not None:
            stack.enter_context(
                patch.object(
                    env_passthrough,
                    "get_all_passthrough",
                    return_value=frozenset(passthrough_override),
                )
            )
        try:
            rec.instance = docker_module.DockerEnvironment(
                image="synthetic-never-pulled",
                cwd="/workspace",
                forward_env=list(forward_names),
                env=docker_env,
                extra_args=extra_args,
                persist_across_processes=False,
                persistent_filesystem=False,
            )
        except RuntimeError as error:
            rec.rejected = True
            rec.error = error
        else:
            def fake_popen(command, stdin_data=None, **kwargs):
                end = command.index(rec.instance._container_id)
                names = {command[i + 1] for i in range(2, end) if command[i] == "-e"}
                rec.exec_calls.append((names, dict(kwargs.get("env") or os.environ)))
                return SimpleNamespace()

            with patch.object(docker_module, "_popen_bash", side_effect=fake_popen):
                rec.instance._run_bash("true", login=True)
                rec.instance._run_bash("true", login=False)
            rec.instance._container_id = None
    env_passthrough.clear_env_passthrough()
    return rec


def _all_family_names(egress_state) -> list:
    return sorted(egress_state.tokens)


# ---------------------------------------------------------------------------
# Policy: family names resolve to opaque tokens on every path
# ---------------------------------------------------------------------------


def test_skill_passthrough_of_mapped_families_delivers_only_tokens(egress_state):
    """Reviewed repro: skill-declared passthrough for the frozen families
    must leave creation/init/runtime/exec with the opaque token — never
    the synthetic host value.  Modeled with a forced passthrough set so
    the resolver policy is proven independently of the registration gate.
    """
    rec = build_environment(
        egress_state,
        passthrough_override=ACTIVE_NAMES,
    )
    assert not rec.rejected, rec.error

    family_names = _all_family_names(egress_state)
    for name in ACTIVE_NAMES:
        assert name in egress_state.tokens  # registered providers are families

    # creation client env + creation run args carry tokens only
    run_env = rec.run_envs[0]
    for name in family_names:
        assert run_env.get(name) == egress_state.tokens[name], name
        assert run_env.get(name) != HOST_SECRET, name

    # init env values resolved to tokens …
    for name in family_names:
        if name in rec.instance._init_env_values:
            assert rec.instance._init_env_values[name] == egress_state.tokens[name], name
        assert rec.instance._init_env_values.get(name) != HOST_SECRET, name

    # … runtime args/values too …
    _args, _unset, runtime_values = rec.instance._build_runtime_env_args_with_unsets()
    for name in family_names:
        if name in runtime_values:
            assert runtime_values[name] == egress_state.tokens[name], name
        assert runtime_values.get(name) != HOST_SECRET, name

    # … and the docker exec boundary sees only tokens.  A raw value only
    # matters when the name is actually forwarded via ``-e`` (the docker
    # client env legitimately mirrors the host shell otherwise).
    assert rec.exec_calls
    forwarded_family = set()
    for names, values in rec.exec_calls:
        for name in names:
            assert values.get(name) != HOST_SECRET, name
            if name in egress_state.tokens:
                assert values.get(name) == egress_state.tokens[name], name
                forwarded_family.add(name)
    assert forwarded_family, "family names must be forwarded with tokens"


def test_registration_gate_refuses_mapped_families(egress_state):
    """The registration gate itself is family-aware: mapped canonical and
    alias names are refused; unconfigured third-party names still register."""
    env_passthrough.clear_env_passthrough()
    env_passthrough.register_env_passthrough(
        [*ACTIVE_NAMES, "GROK_API_KEY", NON_FAMILY_NAME],
    )
    allowed = env_passthrough.get_all_passthrough()
    for name in ACTIVE_NAMES:
        assert name not in allowed, name
    # family aliases that were not in ACTIVE_NAMES are refused too
    assert "GROK_API_KEY" not in allowed
    assert NON_FAMILY_NAME in allowed
    env_passthrough.clear_env_passthrough()


def test_late_registration_still_resolves_to_tokens(egress_state):
    """Reviewed repro: registering a family name AFTER construction must
    not leak the host value into later commands."""
    rec = build_environment(egress_state)  # nothing registered at build time
    assert not rec.rejected, rec.error

    with patch.object(
        env_passthrough,
        "get_all_passthrough",
        return_value=frozenset(["ARKHAM_API_KEY"]),
    ):
        _args, _unset, runtime_values = rec.instance._build_runtime_env_args_with_unsets()
        assert runtime_values.get("ARKHAM_API_KEY") == egress_state.tokens["ARKHAM_API_KEY"]
        assert runtime_values.get("ARKHAM_API_KEY") != HOST_SECRET

        def fake_popen(command, stdin_data=None, **kwargs):
            rec.exec_calls.append((command, dict(kwargs.get("env") or os.environ)))
            return SimpleNamespace()

        rec.instance._container_id = "synthetic-container-id"
        with patch.object(docker_module, "_popen_bash", side_effect=fake_popen):
            rec.instance._run_bash("true", login=False)
        rec.instance._container_id = None

    assert rec.exec_calls
    command, values = rec.exec_calls[-1]
    end = command.index("synthetic-container-id")
    names = {command[i + 1] for i in range(2, end) if command[i] == "-e"}
    assert "ARKHAM_API_KEY" in names
    assert values.get("ARKHAM_API_KEY") == egress_state.tokens["ARKHAM_API_KEY"]
    assert values.get("ARKHAM_API_KEY") != HOST_SECRET


def test_non_family_third_party_passthrough_is_preserved(egress_state):
    """Unconfigured third-party credentials keep flowing verbatim —
    the family policy must not break legitimate local-shell use."""
    rec = build_environment(egress_state, skill_names=(NON_FAMILY_NAME,))
    assert not rec.rejected, rec.error
    assert rec.instance._init_env_values.get(NON_FAMILY_NAME) == HOST_SECRET


# ---------------------------------------------------------------------------
# Explicit collisions fail closed before container creation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "TENDERLY_ACCESS_KEY",   # no _API_KEY/_TOKEN suffix — pre-fix slip
        "GROK_API_KEY",
        "XAI_GROK_API_KEY",
        "COINGECKO_API_KEY",
        "ETHERSCAN_API_KEY",
        "ARKHAM_API_KEY",
        "TENDERLY_API_KEY",
    ],
)
def test_explicit_forward_of_family_names_is_rejected(egress_state, name):
    rec = build_environment(egress_state, forward_names=(name,))
    assert rec.rejected, f"{name} forward should fail closed"
    assert rec.run_calls == 0, "no container may be created"
    assert HOST_SECRET not in str(rec.error)


@pytest.mark.parametrize(
    "name",
    ["TENDERLY_ACCESS_KEY", "GROK_API_KEY", "COINGECKO_API_KEY", "ARKHAM_API_KEY"],
)
def test_docker_env_collision_with_family_names_is_rejected(egress_state, name):
    rec = build_environment(egress_state, docker_env={name: OVERRIDE_VALUE})
    assert rec.rejected, f"docker_env {name} should fail closed"
    assert rec.run_calls == 0
    assert OVERRIDE_VALUE not in str(rec.error)


@pytest.mark.parametrize(
    "name",
    ["TENDERLY_ACCESS_KEY", "GROK_API_KEY", "COINGECKO_API_KEY"],
)
def test_docker_extra_args_env_collision_with_family_names_is_rejected(egress_state, name):
    rec = build_environment(egress_state, extra_args=["-e", f"{name}=x"])
    assert rec.rejected, f"extra_args {name} should fail closed"
    assert rec.run_calls == 0


def test_docker_env_collision_control_still_rejects_canonical(egress_state):
    """Existing control: canonical provider key in docker_env stays rejected."""
    rec = build_environment(egress_state, docker_env={"ARKHAM_API_KEY": OVERRIDE_VALUE})
    assert rec.rejected
    assert rec.run_calls == 0


def test_enforce_off_warns_and_keeps_no_raw_value_in_sandbox(egress_state):
    """Documented opt-out: enforce_on_docker=false downgrades to a warning,
    but family values still never enter the sandbox as raw host values."""
    rec = build_environment(
        egress_state,
        forward_names=("TENDERLY_ACCESS_KEY",),
        enforce=False,
    )
    assert not rec.rejected, rec.error
    run_env = rec.run_envs[0]
    assert run_env.get("TENDERLY_ACCESS_KEY") == egress_state.tokens["TENDERLY_ACCESS_KEY"]
    assert run_env.get("TENDERLY_ACCESS_KEY") != HOST_SECRET
    for _names, values in rec.exec_calls:
        assert values.get("TENDERLY_ACCESS_KEY") != HOST_SECRET


def test_proxy_disabled_preserves_legacy_passthrough(egress_state):
    """Proxy disabled → no egress overrides, no family interception: the
    pre-egress passthrough behavior is preserved."""
    rec = build_environment(egress_state, skill_names=(NON_FAMILY_NAME,), proxy_enabled=False)
    assert not rec.rejected, rec.error
    assert rec.instance._egress_family_tokens == {}
    assert rec.instance._init_env_values.get(NON_FAMILY_NAME) == HOST_SECRET


# ---------------------------------------------------------------------------
# Guard-name derivation: complete families, no suffix heuristics
# ---------------------------------------------------------------------------


def test_critical_names_cover_complete_families(egress_state):
    overrides = {
        **{n: t for n, t in egress_state.tokens.items()},
        "HTTPS_PROXY": "http://host.docker.internal:18080",
        "HERMES_EGRESS_PROXY": "1",
        "_HERMES_EGRESS_NODE_OPTIONS_APPEND": "--use-openssl-ca",
        "HERMES_PROXY_TOKEN_ARKHAM_API_KEY": egress_state.tokens["ARKHAM_API_KEY"],
    }
    critical = docker_module._critical_egress_env_names(overrides)
    for name in egress_state.tokens:
        assert name in critical, name
    assert "TENDERLY_ACCESS_KEY" in critical       # no suffix to match on
    assert "TENDERLY_ACCESS_TOKEN" in critical
    assert "HTTPS_PROXY" in critical
    assert "HERMES_PROXY_TOKEN_ARKHAM_API_KEY" not in critical


def test_token_map_derives_families_and_falls_back_to_overrides(egress_state):
    overrides = {n: t for n, t in egress_state.tokens.items()}
    tokens = docker_module._egress_family_token_map(overrides)
    for name, value in egress_state.tokens.items():
        assert tokens.get(name) == value, name
    # Fallback: even a name missing from the mappings stays protected when
    # it is present in the overrides (the mappings-minted shape).
    overrides["TENDERLY_ACCESS_KEY"] = egress_state.tokens["TENDERLY_ACCESS_KEY"]
    with patch.object(ip, "load_mappings", side_effect=OSError("unreadable")):
        fallback = docker_module._egress_family_token_map(
            {"TENDERLY_ACCESS_KEY": "opaque-token-x"}
        )
    assert fallback.get("TENDERLY_ACCESS_KEY") == "opaque-token-x"


def test_blocklist_builder_folds_in_egress_families(egress_state):
    """The derived provider blocklist covers the operator's mapping
    families (canonical + aliases) — the authoritative protected set."""
    from tools.environments import local as local_module

    rebuilt = local_module._build_provider_env_blocklist()
    for name in egress_state.tokens:
        assert name in rebuilt, name
