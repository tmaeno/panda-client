"""Offline unit tests for token_sources and the token handling of Client._HttpClient.

External tools (oidc-add, oidc-token, oidc-gen) and the native device flow are mocked, so
nothing touches the network or the user's oidc-agent.

Run with: python -m unittest pandaclient.tests.test_token_sources
"""

import base64
import json
import os
import subprocess
import tempfile
import time
import unittest
from unittest import mock

# importing Client resolves the cache server's name unless this is set
os.environ.setdefault("PANDA_BEHIND_REAL_LB", "1")

from pandaclient import Client, openidc_utils, token_sources  # noqa: E402

STATIC_TOKEN_ENVS = ("PANDA_AUTH_ID_TOKEN", "OIDC_AUTH_TOKEN_FILE", "OIDC_AUTH_ID_TOKEN")
AUTH_CONFIG = {
    "client_id": "panda-client-id",
    "client_secret": "panda-secret",
    "audience": "https://pandaserver.example.org",
    "oidc_config_url": "https://iam.example.org/.well-known/openid-configuration",
}
ENDPOINT_CONFIG = {"issuer": "https://iam.example.org/"}


def make_token(exp_in=3600, **claims):
    """An unsigned JWT with the given claims, expiring exp_in seconds from now"""

    def encode(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    payload = {"exp": time.time() + exp_in}
    payload.update(claims)
    return f"{encode({'alg': 'none'})}.{encode(payload)}.sig"


def oidc_env(**extra):
    """Environment for PANDA_AUTH=oidc with no pre-supplied token"""
    env = {key: value for key, value in os.environ.items() if key not in STATIC_TOKEN_ENVS}
    env.update({"PANDA_AUTH": "oidc", "PANDA_AUTH_VO": "atlas"})
    for key in (token_sources.TOKEN_SOURCE_ENV, token_sources.OIDC_AGENT_TOKEN_TYPE_ENV):
        env.pop(key, None)
    env.update(extra)
    return env


class FakeCommands:
    """Stand-in for subprocess.run, answering each tool from a table and recording the calls"""

    def __init__(self, accounts=("panda-atlas",), token=None, fail=()):
        self.accounts = list(accounts)
        self.token = token or make_token()
        self.fail = fail
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        tool = args[0]
        if tool in self.fail:
            return subprocess.CompletedProcess(args, 1, stdout="")
        if tool == "oidc-add":
            return subprocess.CompletedProcess(args, 0, stdout="".join(f"{a}\n" for a in self.accounts))
        if tool == "oidc-token":
            return subprocess.CompletedProcess(args, 0, stdout=self.token + "\n")
        if tool == "oidc-gen":
            self.accounts.append(args[1])
            return subprocess.CompletedProcess(args, 0, stdout="")
        raise FileNotFoundError(tool)

    def called(self, tool):
        return [c for c in self.calls if c[0] == tool]


class TestBuildScopes(unittest.TestCase):
    def test_scopes_unchanged(self):
        self.assertEqual(openidc_utils.build_scopes(None), "openid profile email offline_access ")
        self.assertEqual(openidc_utils.build_scopes("wlcg"), "openid profile email offline_access wlcg wlcg.groups ")

    def test_device_code_request_uses_them(self):
        token_dir = tempfile.TemporaryDirectory()
        self.addCleanup(token_dir.cleanup)
        oidc = openidc_utils.OpenIdConnect_Utils("https://x/auth.json", token_dir=token_dir.name, log_stream=mock.MagicMock())
        with mock.patch.object(openidc_utils, "urlopen") as urlopen:
            urlopen.return_value.read.return_value = b"{}"
            oidc.get_device_code("https://iam/device", "cid", "aud", "wlcg")
        sent = urlopen.call_args[0][0].data.decode()
        self.assertIn("scope=openid+profile+email+offline_access+wlcg+wlcg.groups+", sent)


class TestSourceSelection(unittest.TestCase):
    def test_default_is_native(self):
        with mock.patch.dict(os.environ, oidc_env(), clear=True):
            self.assertEqual(token_sources.get_token_source_name(), "native")
            self.assertEqual(Client._HttpClient().token_source, "native")

    def test_oidc_agent(self):
        with mock.patch.dict(os.environ, oidc_env(PANDA_TOKEN_SOURCE="oidc-agent"), clear=True):
            self.assertEqual(Client._HttpClient().token_source, "oidc-agent")

    def test_unknown_source_exits(self):
        with mock.patch.dict(os.environ, oidc_env(PANDA_TOKEN_SOURCE="nosuch"), clear=True):
            with self.assertRaises(SystemExit):
                Client._HttpClient()

    def test_not_checked_without_oidc(self):
        env = oidc_env(PANDA_TOKEN_SOURCE="nosuch")
        env.pop("PANDA_AUTH")
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(Client._HttpClient().auth_mode, "voms")


class TestNativeTokenSource(unittest.TestCase):
    def get_token(self, force_new):
        with mock.patch.object(openidc_utils, "OpenIdConnect_Utils") as utils:
            oidc = utils.return_value
            oidc.run_device_authorization_flow.return_value = (True, "tok")
            source = token_sources.NativeTokenSource("atlas", "https://x/auth.json", mock.MagicMock())
            self.assertEqual(source.get_token(force_new=force_new), (True, "tok"))
        return oidc

    def test_reuses_cached_token(self):
        self.get_token(False).cleanup.assert_not_called()

    def test_force_new_cleans_up_first(self):
        oidc = self.get_token(True)
        oidc.cleanup.assert_called_once_with()
        oidc.run_device_authorization_flow.assert_called_once_with()


class TestOidcAgentTokenSource(unittest.TestCase):
    def setUp(self):
        self.log = mock.MagicMock()
        patcher = mock.patch.dict(os.environ, oidc_env(OIDC_SOCK="/tmp/sock"), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(token_sources.TokenSource, "_get_server_configs", return_value=(True, (dict(AUTH_CONFIG), ENDPOINT_CONFIG)))
        self.server_configs = patcher.start()
        self.addCleanup(patcher.stop)

    def get_token(self, commands, vo="atlas", interactive=True, **kwargs):
        source = token_sources.OidcAgentTokenSource(vo, "https://x/auth.json", self.log)
        with (
            mock.patch.object(token_sources.subprocess, "run", side_effect=commands),
            mock.patch.object(token_sources, "_is_interactive", return_value=interactive),
        ):
            return source.get_token(**kwargs)

    def test_account_name(self):
        self.assertEqual(token_sources.get_oidc_agent_account("atlas"), "panda-atlas")
        self.assertEqual(token_sources.get_oidc_agent_account("atlas:production"), "panda-atlas.production")

    def test_id_token_by_default(self):
        commands = FakeCommands()
        self.assertEqual(self.get_token(commands), (True, commands.token))
        self.assertEqual(commands.called("oidc-token"), [["oidc-token", "--time=300", "--id-token", "panda-atlas"]])
        self.assertEqual(commands.called("oidc-gen"), [])

    def test_access_token(self):
        os.environ[token_sources.OIDC_AGENT_TOKEN_TYPE_ENV] = "access"
        commands = FakeCommands()
        self.get_token(commands)
        self.assertEqual(commands.called("oidc-token"), [["oidc-token", "--time=300", "panda-atlas"]])

    def test_force_new(self):
        commands = FakeCommands()
        self.get_token(commands, force_new=True)
        self.assertIn("--force-new", commands.called("oidc-token")[0])

    def test_invalid_token_type(self):
        os.environ[token_sources.OIDC_AGENT_TOKEN_TYPE_ENV] = "refresh"
        commands = FakeCommands()
        s, o = self.get_token(commands)
        self.assertFalse(s)
        self.assertIn("PANDA_OIDC_AGENT_TOKEN_TYPE=refresh", o)
        self.assertEqual(commands.calls, [])

    def test_not_installed(self):
        s, o = self.get_token(mock.MagicMock(side_effect=FileNotFoundError))
        self.assertFalse(s)
        self.assertIn("oidc-add not found in PATH", o)

    def test_oidc_token_failure_hints(self):
        del os.environ["OIDC_SOCK"]
        s, o = self.get_token(FakeCommands(fail=("oidc-token",)))
        self.assertFalse(s)
        self.assertIn("exit code 1", o)
        self.assertIn("$OIDC_SOCK is not set", o)
        self.assertIn("--always-allow-idtoken panda-atlas", o)

    def test_empty_token(self):
        s, o = self.get_token(FakeCommands(token=" "))
        self.assertFalse(s)

    def test_creates_missing_account(self):
        commands = FakeCommands(accounts=["other"])
        self.assertEqual(self.get_token(commands), (True, commands.token))
        self.assertEqual(
            commands.called("oidc-gen"),
            [
                [
                    "oidc-gen",
                    "panda-atlas",
                    "--manual",
                    "--issuer=https://iam.example.org/",
                    "--client-id=panda-client-id",
                    "--client-secret=panda-secret",
                    "--scope=openid profile email offline_access",
                    "--aud=https://pandaserver.example.org",
                    "--flow=device",
                    "--confirm-default",
                ]
            ],
        )
        # created before the token is asked for
        self.assertEqual([c[0] for c in commands.calls], ["oidc-add", "oidc-gen", "oidc-token"])

    def test_secret_not_logged(self):
        source = token_sources.OidcAgentTokenSource("atlas", "https://x/auth.json", self.log, verbose=True)
        commands = FakeCommands(accounts=[])
        with mock.patch.object(token_sources.subprocess, "run", side_effect=commands), mock.patch.object(token_sources, "_is_interactive", return_value=True):
            source.get_token()
        logged = " ".join(str(c) for c in self.log.method_calls)
        self.assertNotIn("panda-secret", logged)
        self.assertIn("--client-secret=***", logged)

    def test_no_account_without_terminal(self):
        commands = FakeCommands(accounts=[])
        s, o = self.get_token(commands, interactive=False)
        self.assertFalse(s)
        self.assertIn("oidc-gen panda-atlas --manual", o)
        self.assertEqual(commands.called("oidc-gen"), [])
        self.assertEqual(commands.called("oidc-token"), [])

    def test_failed_creation(self):
        s, o = self.get_token(FakeCommands(accounts=[], fail=("oidc-gen",)))
        self.assertFalse(s)
        self.assertIn("failed to create oidc-agent account panda-atlas", o)

    def test_gen_command_wlcg_without_secret(self):
        config = dict(AUTH_CONFIG, jwt_profile="wlcg")
        del config["client_secret"]
        self.server_configs.return_value = (True, (config, ENDPOINT_CONFIG))
        s, args = token_sources.OidcAgentTokenSource("atlas", "https://x/auth.json", self.log).build_gen_command()
        self.assertTrue(s)
        self.assertIn("--scope=openid profile email offline_access wlcg wlcg.groups", args)
        self.assertFalse([a for a in args if a.startswith("--client-secret")])


class FakeSource:
    """Token source handing out the given tokens in turn"""

    def __init__(self, *tokens):
        self.tokens = list(tokens)
        self.calls = []

    def __call__(self, name, auth_vo, auth_config_url, log_stream, verbose=False):
        return self

    def get_token(self, force_new=False):
        self.calls.append(force_new)
        return True, self.tokens.pop(0)


class TestHttpClientToken(unittest.TestCase):
    def setUp(self):
        token_sources._token_cache.clear()
        self.addCleanup(token_sources._token_cache.clear)
        patcher = mock.patch.dict(os.environ, oidc_env(PANDA_TOKEN_SOURCE="oidc-agent"), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def use_source(self, source):
        patcher = mock.patch.object(token_sources, "get_token_source", side_effect=source)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_token_cached_across_clients(self):
        first, second = make_token(), make_token()
        source = FakeSource(first, second)
        self.use_source(source)
        for _ in range(2):
            client = Client._HttpClient()
            client.get_id_token()
            self.assertEqual(client.id_token, first)
        self.assertEqual(source.calls, [False])
        client.get_id_token(force_new=True)
        self.assertEqual(client.id_token, second)
        self.assertEqual(source.calls, [False, True])

    def test_token_near_expiry_renewed(self):
        source = FakeSource(make_token(exp_in=60), make_token())
        self.use_source(source)
        Client._HttpClient().get_id_token()
        Client._HttpClient().get_id_token()
        self.assertEqual(source.calls, [False, False])

    def test_static_token_first(self):
        source = FakeSource(make_token())
        self.use_source(source)
        os.environ["PANDA_AUTH_ID_TOKEN"] = "static"
        client = Client._HttpClient()
        client.get_id_token()
        self.assertEqual(client.id_token, "static")
        self.assertEqual(source.calls, [])

    def test_failure_exits(self):
        source = mock.MagicMock()
        source.get_token.return_value = (False, "no token")
        self.use_source(lambda *args, **kwargs: source)
        with self.assertRaises(SystemExit):
            Client._HttpClient().get_id_token()

    def test_token_info_normalized(self):
        self.use_source(FakeSource(make_token(name="jane doe", **{"wlcg.groups": ["/atlas", "/atlas/production"]})))
        info = Client._HttpClient().get_token_info()
        self.assertEqual(info["groups"], ["atlas", "atlas/production"])

    def test_token_info_failure(self):
        source = mock.MagicMock()
        source.get_token.return_value = (False, "no token")
        self.use_source(lambda *args, **kwargs: source)
        self.assertIsNone(Client._HttpClient().get_token_info())

    def test_user_name(self):
        self.use_source(FakeSource(make_token(name="jane doe", groups=["atlas"], preferred_username="jdoe")))
        self.assertEqual(Client.get_user_name_from_token(), ("Jane Doe", ["atlas"], "jdoe"))

    def test_user_name_missing(self):
        self.use_source(FakeSource(make_token(groups=["atlas"])))
        with mock.patch.object(Client.PLogger, "getPandaLogger") as logger:
            self.assertEqual(Client.get_user_name_from_token(), (None, None, None))
        message = logger.return_value.error.call_args[0][0]
        self.assertIn("IAM_ACCESS_TOKEN_INCLUDE_AUTHN_INFO", message)


class TestNormalizeClaims(unittest.TestCase):
    def test_groups_kept(self):
        claims = {"groups": ["atlas"], "wlcg.groups": ["/other"]}
        self.assertEqual(token_sources.normalize_claims(claims), claims)

    def test_groups_from_wlcg(self):
        claims = {"wlcg.groups": ["/atlas/production"]}
        self.assertEqual(token_sources.normalize_claims(claims)["groups"], ["atlas/production"])
        # the input is left as it was
        self.assertNotIn("groups", claims)

    def test_no_groups(self):
        self.assertEqual(token_sources.normalize_claims({"sub": "x"}), {"sub": "x"})


if __name__ == "__main__":
    unittest.main()
