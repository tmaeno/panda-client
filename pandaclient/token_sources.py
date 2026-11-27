"""
bearer token sources for PANDA_AUTH=oidc

$PANDA_TOKEN_SOURCE selects where the bearer token sent to the PanDA server comes from:
  - "native" (default): panda-client's own device-authorization flow in openidc_utils,
    with the token kept in $PANDA_TOKEN_DIR
  - "oidc-agent": oidc-token from oidc-agent, using the account panda-<VO>. The account is
    created on first use with PanDA's own client (from the server's auth config), so the
    server accepts its tokens like those of the native flow. Without an agent reachable
    through $OIDC_SOCK, one is taken from oidc-agent-service.
    $PANDA_OIDC_AGENT_TOKEN_TYPE picks "id" (default) or "access" tokens.

Each source returns a token string and does not care whether it is an ID or an access token;
callers decode its claims the same way. A new source (e.g. htgettoken) is one more TokenSource
subclass registered in TOKEN_SOURCES.

The module also keeps an in-process cache of the last token per source, since _HttpClient asks
for a token on every request and some sources run an external command for it.
"""

import os
import re
import shlex
import socket
import subprocess
import sys
import time

from . import openidc_utils

TOKEN_SOURCE_ENV = "PANDA_TOKEN_SOURCE"
DEFAULT_TOKEN_SOURCE = "native"
OIDC_AGENT_TOKEN_TYPE_ENV = "PANDA_OIDC_AGENT_TOKEN_TYPE"
OIDC_AGENT_TOKEN_TYPES = ("id", "access")
OIDC_AGENT_ACCOUNT_PREFIX = "panda-"

# a token is renewed when less than this is left before it expires; same margin as
# OpenIdConnect_Utils.check_token
MIN_VALID_SECONDS = 300


class TokenSource:
    """Where a bearer token for PANDA_AUTH=oidc comes from

    args:
       auth_vo: the VO, as in $PANDA_AUTH_VO
       auth_config_url: URL of the server's auth config for the VO
       log_stream: logger
       verbose: True to see debug messages
    """

    name = None

    def __init__(self, auth_vo, auth_config_url, log_stream, verbose=False):
        self.auth_vo = auth_vo
        self.auth_config_url = auth_config_url
        self.log_stream = log_stream
        self.verbose = verbose

    def get_token(self, force_new=False):
        """Get a bearer token

        args:
           force_new: True to ignore any token kept by the source and get a new one
        returns:
           (True, token) or (False, error message)
        """
        raise NotImplementedError

    def _get_server_configs(self):
        """Get the server's auth config for the VO and the OIDC discovery page it points to

        returns:
           (True, (auth_config, endpoint_config)) or (False, error message)
        """
        oidc = openidc_utils.OpenIdConnect_Utils(self.auth_config_url, log_stream=self.log_stream, verbose=self.verbose)
        s, auth_config = oidc.fetch_page(self.auth_config_url)
        if not s:
            return False, f"Failed to get Auth configuration: {auth_config}"
        s, endpoint_config = oidc.fetch_page(auth_config["oidc_config_url"])
        if not s:
            return False, f"Failed to get endpoint configuration: {endpoint_config}"
        return True, (auth_config, endpoint_config)

    def _run_command(self, args, display=None):
        """Run an external tool, keeping the terminal attached so it can talk to the user

        stdout is captured and returned. stdin and stderr stay connected to the terminal, so the
        tool can show URLs and messages and ask for passwords itself.

        args:
           args: the command as a list, run without a shell
           display: the command as shown in debug messages, when args hold something not to log
        returns:
           (True, stdout) or (False, error message)
        """
        if self.verbose:
            self.log_stream.debug(f"run {display or shlex.join(args)}")
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, universal_newlines=True)
        except FileNotFoundError:
            return False, f"{args[0]} not found in PATH"
        except KeyboardInterrupt:
            return False, "aborted"
        except Exception as e:
            return False, f"failed to run {args[0]}: {e}"
        if proc.returncode != 0:
            return False, f"{args[0]} failed with exit code {proc.returncode}"
        return True, proc.stdout


class NativeTokenSource(TokenSource):
    """panda-client's own device-authorization flow, with the token kept in $PANDA_TOKEN_DIR"""

    name = "native"

    def get_token(self, force_new=False):
        oidc = openidc_utils.OpenIdConnect_Utils(self.auth_config_url, log_stream=self.log_stream, verbose=self.verbose)
        if force_new:
            oidc.cleanup()
        return oidc.run_device_authorization_flow()


class OidcAgentTokenSource(TokenSource):
    """Tokens from oidc-agent, through an account made with PanDA's own client

    The account is named panda-<VO>, since oidc-token selects the client by account and the
    server only accepts tokens of the client in its auth config. When the account does not
    exist yet, it is created with oidc-gen from the auth config; existing accounts are never
    changed. When no agent is reachable through $OIDC_SOCK, oidc-agent-service provides one:
    it reuses the agent it started before, e.g. for an earlier run, or starts a new one, which
    keeps running afterwards.
    """

    name = "oidc-agent"

    def __init__(self, auth_vo, auth_config_url, log_stream, verbose=False):
        super().__init__(auth_vo, auth_config_url, log_stream, verbose)
        self.account = get_oidc_agent_account(auth_vo)

    def get_token(self, force_new=False):
        token_type = get_oidc_agent_token_type()
        if token_type not in OIDC_AGENT_TOKEN_TYPES:
            return False, f"{OIDC_AGENT_TOKEN_TYPE_ENV}={token_type} is not one of {', '.join(OIDC_AGENT_TOKEN_TYPES)}"
        s, o = self._ensure_agent()
        if not s:
            return False, o
        # create the account first, so that oidc-token does not complain about it before
        s, o = self._list_accounts()
        if not s:
            return False, f"failed to list oidc-agent accounts: {o}. Is oidc-agent installed?"
        if self.account not in o:
            s, o = self._setup_account()
            if not s:
                return False, o
        args = ["oidc-token", f"--time={MIN_VALID_SECONDS}"]
        if token_type == "id":
            args.append("--id-token")
        if force_new:
            args.append("--force-new")
        args.append(self.account)
        s, o = self._run_command(args)
        if not s:
            return False, f"failed to get a token from oidc-agent: {o}. {self._failure_hint(token_type)}"
        token = o.strip()
        if not token:
            return False, f"oidc-token returned no token for {self.account}"
        return True, token

    def _ensure_agent(self):
        """Make an agent reachable through $OIDC_SOCK, for this process and the tools it runs

        returns:
           (True, None) or (False, error message)
        """
        sock = os.environ.get("OIDC_SOCK")
        if sock and _can_connect(sock):
            return True, None
        # a child cannot set the variable in the user's shell, so the next run asks again and gets the same agent
        s, o = self._run_command(["oidc-agent-service", "use"])
        if s:
            match = re.search(r"OIDC_SOCK=([^;\s]+)", o)
            if not match:
                s, o = False, "no OIDC_SOCK in the output of oidc-agent-service use"
            elif not _can_connect(match.group(1)):
                s, o = False, f"cannot connect to {match.group(1)}"
        if not s:
            return False, (
                f"oidc-agent is not running and could not be started with oidc-agent-service ({o}). "
                "Start it with eval $(oidc-agent-service use), e.g. in ~/.bashrc, and retry"
            )
        os.environ["OIDC_SOCK"] = match.group(1)
        self.log_stream.info(f"using oidc-agent at {match.group(1)} (started or reused by oidc-agent-service)")
        return True, None

    def _list_accounts(self):
        """Get the account configurations saved on this host, loaded into the agent or not

        returns:
           (True, set of account names) or (False, error message)
        """
        s, o = self._run_command(["oidc-add", "--list"])
        if not s:
            return False, o
        # one account per line. Older versions also print a header line, which never matches an account name
        return True, {line.strip() for line in o.splitlines() if line.strip()}

    def build_gen_command(self):
        """Build the oidc-gen command creating the account with PanDA's client

        returns:
           (True, command as a list) or (False, error message)
        """
        s, o = self._get_server_configs()
        if not s:
            return False, o
        auth_config, endpoint_config = o
        args = [
            "oidc-gen",
            self.account,
            "--manual",
            f"--issuer={endpoint_config['issuer']}",
            f"--client-id={auth_config['client_id']}",
        ]
        if auth_config.get("client_secret"):
            args.append(f"--client-secret={auth_config['client_secret']}")
        else:
            args.append("--pub")
        args.append(f"--scope={openidc_utils.build_scopes(auth_config.get('jwt_profile')).strip()}")
        if auth_config.get("audience"):
            args.append(f"--aud={auth_config['audience']}")
        args += ["--flow=device", "--confirm-default", "--redirect-uri=''"]
        return True, args

    def _setup_account(self):
        """Create the account with oidc-gen, which signs the user in and asks for the encryption password

        returns:
           (True, None) or (False, error message)
        """
        s, o = self.build_gen_command()
        if not s:
            return False, f"failed to build the oidc-gen command for {self.account}: {o}"
        args = o
        if not _is_interactive():
            return False, f"oidc-agent account {self.account} does not exist. Please create it by running\n  {shlex.join(args)}"
        self.log_stream.info(f"Creating oidc-agent account {self.account} with the PanDA client")
        # the client secret is public in the auth config, but kept out of the logs anyway
        display = shlex.join(["--client-secret=***" if a.startswith("--client-secret=") else a for a in args])
        s, o = self._run_command(args, display=display)
        if not s:
            return False, f"failed to create oidc-agent account {self.account}: {o}"
        return True, None

    def _failure_hint(self, token_type):
        if token_type == "id":
            return (
                f"ID tokens need your approval unless the account is loaded with oidc-add --always-allow-idtoken {self.account}, "
                f"or set {OIDC_AGENT_TOKEN_TYPE_ENV}=access to use access tokens."
            )
        return ""


TOKEN_SOURCES = {
    NativeTokenSource.name: NativeTokenSource,
    OidcAgentTokenSource.name: OidcAgentTokenSource,
}


def get_token_source_name():
    """Get the name of the token source selected by $PANDA_TOKEN_SOURCE; check it against TOKEN_SOURCES"""
    return os.environ.get(TOKEN_SOURCE_ENV) or DEFAULT_TOKEN_SOURCE


def get_token_source(name, auth_vo, auth_config_url, log_stream, verbose=False):
    """Make the token source registered as name

    returns:
       a TokenSource instance
    """
    return TOKEN_SOURCES[name](auth_vo, auth_config_url, log_stream, verbose)


def get_oidc_agent_account(auth_vo):
    """Get the name of the oidc-agent account panda-client uses for auth_vo"""
    return OIDC_AGENT_ACCOUNT_PREFIX + auth_vo.replace(":", ".")


def get_oidc_agent_token_type():
    """Get the token type requested from oidc-agent, from $PANDA_OIDC_AGENT_TOKEN_TYPE"""
    return os.environ.get(OIDC_AGENT_TOKEN_TYPE_ENV) or "id"


# whether an agent answers on the socket at path; a socket file left by a dead agent does not
def _can_connect(path):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(path)
        return True
    except Exception:
        return False


# whether the user is at a terminal, to answer the prompts of external tools
def _is_interactive():
    return sys.stdin is not None and sys.stdin.isatty() and sys.stderr is not None and sys.stderr.isatty()


# in-process cache of the last token, keyed by (source name, auth config URL)
_token_cache = {}


def _token_expiry(token):
    try:
        return float(openidc_utils.decode_id_token(token)["exp"])
    except Exception:
        return None


def get_cached_token(key):
    """Get the cached token for key if it is valid for at least MIN_VALID_SECONDS more, otherwise None"""
    entry = _token_cache.get(key)
    if entry is not None and entry[1] - time.time() > MIN_VALID_SECONDS:
        return entry[0]
    return None


def cache_token(key, token):
    """Cache a token for key; one whose expiry cannot be read is not cached"""
    expiry = _token_expiry(token)
    if expiry is not None:
        _token_cache[key] = (token, expiry)


def clear_cached_token(key):
    """Drop the cached token for key"""
    _token_cache.pop(key, None)


def normalize_claims(claims):
    """Fill the claims panda-client reads, so ID and access tokens of either JWT profile look the same

    groups: taken from wlcg.groups when missing, without the leading slash, i.e. "vo/role" as in the
    groups claim of the IAM profile.

    args:
       claims: decoded token claims
    returns:
       the claims, with the missing ones filled where possible
    """
    if isinstance(claims, dict) and "groups" not in claims and isinstance(claims.get("wlcg.groups"), list):
        claims = dict(claims)
        claims["groups"] = [str(group).lstrip("/") for group in claims["wlcg.groups"]]
    return claims
