"""The graph layer: code graphs per revision and the rules over their difference.

- ``model``: the graph's vocabulary (node roles, edge kinds).
- ``extract``: one file to plain facts, with tree-sitter (4.1).
- ``catalog``: sources, sinks and the sanitizer allowlist (4.3).
- ``link``: facts of all files to a graph: call resolution (4.2) and taint and
  sanitize edges (4.3).
- ``index``: the stored graph, re-parsing only the files that changed (4.4).
- ``delta``: rules R1 to R4 over two graphs (4.5).
"""
