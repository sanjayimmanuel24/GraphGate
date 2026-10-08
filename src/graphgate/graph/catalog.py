"""Sources, sinks and the sanitizer allowlist (BUILD_PLAN 4.3).

Three lists decide which nodes of the graph get a role. They cover the
injection family only (CLAUDE.md, hard scope constraints): SQL, command and
path. Each entry is one of

- a dotted name, matched after imports are resolved (``subprocess.run``);
- a method name, matched only when the receiver's class is unknown
  (``cursor.execute``: nothing says what ``cursor`` is, the name is the signal).

**Where the entries come from.** They were seeded from the Semgrep community
rules pinned in ``data/semgrep_rules.json`` (the taint sources, sinks and
sanitizers of the 63 injection rule files) and from the sink and source
families Pysa ships (user-controlled input, remote code execution, SQL, file
system). Pysa's stub files were not on this machine when the list was written;
check the entries against the pinned stubs when Pysa is set up (BUILD_PLAN 3.3).

**The list is part of the experiment.** It was fixed before the rules were run
on any event. Do not add, drop or reword an entry to change what Condition C
catches; a per-repository extension (proposal 5.1) goes through ``extended``
and is bound by the repository-level holdout (BUILD_PLAN 5.4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Mapping

SQL, COMMAND, PATH = "sql", "command", "path"

# Source kinds (proposal 5.1): request parameters, environment reads, file and
# network input, command-line arguments. "public-api" is not in this list: it
# is added by the linker when GraphConfig.public_api_sources is on.
REQUEST, ENV, CLI, STDIN, FILE, NETWORK = "request", "env", "cli", "stdin", "file", "network"
PUBLIC_API = "public-api"


@dataclass(frozen=True)
class Sink:
    family: str                              # SQL, COMMAND or PATH
    args: tuple[int, ...] | None = (0,)      # positional arguments that reach the sink; None = all
    kwargs: tuple[str, ...] = ()             # keyword arguments that reach it
    receiver: bool = False                   # the object the method is called on reaches it


def _sinks(family: str, names: str, **how) -> dict[str, Sink]:
    return {name: Sink(family, **how) for name in names.split()}


SINKS: dict[str, Sink] = {
    # Command execution (CWE-78, CWE-77).
    **_sinks(COMMAND, "os.system os.popen os.popen2 os.popen3 os.popen4 pty.spawn "
                      "subprocess.getoutput subprocess.getstatusoutput"),
    **_sinks(COMMAND, "subprocess.run subprocess.call subprocess.check_call subprocess.check_output "
                      "subprocess.Popen", kwargs=("args",)),
    **_sinks(COMMAND, "os.execl os.execle os.execlp os.execlpe os.execv os.execve os.execvp os.execvpe "
                      "os.spawnl os.spawnle os.spawnlp os.spawnlpe os.spawnv os.spawnve os.spawnvp "
                      "os.spawnvpe os.posix_spawn os.posix_spawnp asyncio.create_subprocess_exec "
                      "asyncio.create_subprocess_shell asyncio.subprocess.create_subprocess_exec "
                      "asyncio.subprocess.create_subprocess_shell", args=None),
    # SQL (CWE-89): building a statement from text.
    **_sinks(SQL, "sqlalchemy.text sqlalchemy.sql.text sqlalchemy.sql.expression.text "
                  "django.db.models.expressions.RawSQL pandas.read_sql pandas.read_sql_query"),
    # Files and directories (CWE-22).
    **_sinks(PATH, "builtins.open io.open os.open codecs.open os.remove os.unlink os.rmdir os.removedirs "
                   "os.mkdir os.makedirs os.listdir os.scandir os.walk shutil.rmtree flask.send_file",
             kwargs=("file", "path", "name")),
    **_sinks(PATH, "os.rename os.replace shutil.copy shutil.copy2 shutil.copyfile shutil.copytree shutil.move",
             args=(0, 1)),
    **_sinks(PATH, "flask.send_from_directory", args=(0, 1)),
}

# Matched by name alone, on a receiver whose class is not known.
SINK_METHODS: dict[str, Sink] = {
    **_sinks(SQL, "execute executemany executescript mogrify raw"),
    **_sinks(COMMAND, "exec_command"),
    **_sinks(COMMAND, "subprocess_exec subprocess_shell", args=None),
    **_sinks(PATH, "read_text read_bytes write_text write_bytes", args=(), receiver=True),
}

# A dotted name is a source if it starts with one of these.
SOURCES: dict[str, str] = {
    "flask.request": REQUEST,
    "os.environ": ENV, "os.environb": ENV, "os.getenv": ENV, "os.getenvb": ENV,
    "sys.argv": CLI, "getopt.getopt": CLI, "getopt.gnu_getopt": CLI,
    "sys.stdin": STDIN, "builtins.input": STDIN,
    "builtins.open": FILE, "io.open": FILE, "codecs.open": FILE,
    "requests.get": NETWORK, "requests.post": NETWORK, "requests.put": NETWORK, "requests.delete": NETWORK,
    "requests.patch": NETWORK, "requests.head": NETWORK, "requests.request": NETWORK,
    "urllib.request.urlopen": NETWORK, "urllib2.urlopen": NETWORK,
}

SOURCE_METHODS: dict[str, str] = {
    "parse_args": CLI, "parse_known_args": CLI,
    "recv": NETWORK, "recvfrom": NETWORK,
}

# A parameter annotated with one of these classes carries request data.
REQUEST_CLASSES = frozenset({
    "django.http.HttpRequest", "django.http.request.HttpRequest", "rest_framework.request.Request",
    "fastapi.Request", "starlette.requests.Request", "aiohttp.web.Request", "flask.Request",
    "werkzeug.wrappers.Request", "pyramid.request.Request",
})

# A function under one of these decorators receives request data in its
# parameters: by dotted name, or by method name when the decorator is called on
# an object (``@app.route("/x")``).
ROUTE_DECORATORS = frozenset({"rest_framework.decorators.api_view", "pyramid.view.view_config"})
ROUTE_DECORATOR_METHODS = frozenset({"route", "get", "post", "put", "delete", "patch"})

# The allowlist proper: library functions whose result is safe to pass on.
SANITIZERS: dict[str, str] = {
    "shlex.quote": COMMAND, "pipes.quote": COMMAND, "shlex.split": COMMAND, "shlex.join": COMMAND,
    "psycopg2.sql.Identifier": SQL, "psycopg2.sql.Literal": SQL, "psycopg2.extensions.quote_ident": SQL,
    "psycopg2.extensions.adapt": SQL, "MySQLdb.escape_string": SQL, "pymysql.escape_string": SQL,
    "pymysql.converters.escape_string": SQL, "sqlalchemy.bindparam": SQL,
    "sqlalchemy.sql.expression.bindparam": SQL,
    "werkzeug.utils.secure_filename": PATH, "werkzeug.utils.safe_join": PATH,
    "werkzeug.security.safe_join": PATH, "flask.safe_join": PATH, "django.utils._os.safe_join": PATH,
    "os.path.basename": PATH, "posixpath.basename": PATH, "ntpath.basename": PATH,
    # A value coerced to a number or a truth value carries no payload.
    "builtins.int": "cast", "builtins.float": "cast", "builtins.bool": "cast",
}

# Validation wrappers: functions of the project itself, or callees that cannot
# be resolved, recognised by a word of their name. Whole words only, so
# "unsafe" is not "safe".
_VALIDATOR_WORD = re.compile(
    r"^(saniti[sz]e[drs]?|escape[ds]?|quote[ds]?|validat(e[ds]?|or|ion)|valid|verif(y|ied)|"
    r"check(ed|s|er)?|secured?|safe)$")
_NEVER_VALIDATORS = frozenset({"check_output", "check_call"})     # subprocess runners, not checks


def _words(name: str) -> list[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return [w for w in spaced.lower().split("_") if w]


def is_validator_name(name: str) -> bool:
    return name not in _NEVER_VALIDATORS and any(_VALIDATOR_WORD.match(w) for w in _words(name))


@dataclass(frozen=True)
class Catalog:
    sinks: Mapping[str, Sink] = field(default_factory=lambda: SINKS)
    sink_methods: Mapping[str, Sink] = field(default_factory=lambda: SINK_METHODS)
    sources: Mapping[str, str] = field(default_factory=lambda: SOURCES)
    source_methods: Mapping[str, str] = field(default_factory=lambda: SOURCE_METHODS)
    sanitizers: Mapping[str, str] = field(default_factory=lambda: SANITIZERS)
    request_classes: frozenset[str] = REQUEST_CLASSES
    route_decorators: frozenset[str] = ROUTE_DECORATORS
    route_decorator_methods: frozenset[str] = ROUTE_DECORATOR_METHODS

    def source_kind(self, dotted: str) -> tuple[str, str] | None:
        """``(source name, kind)`` if ``dotted`` is a source or reads from one."""
        parts = dotted.split(".")
        for size in range(len(parts), 0, -1):
            prefix = ".".join(parts[:size])
            if prefix in self.sources:
                return prefix, self.sources[prefix]
        return None

    def extended(self, *, sanitizers: Mapping[str, str] | None = None) -> Catalog:
        """This catalog plus a repository's own sanitizers (proposal 5.1)."""
        return replace(self, sanitizers={**self.sanitizers, **(sanitizers or {})})


DEFAULT = Catalog()
