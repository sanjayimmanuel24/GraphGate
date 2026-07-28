"""GraphGate — a security gate for iterative LLM code refinement.

Blocks security regressions that a diff-only check would miss, by reasoning over
a temporal code-graph delta between successive revisions.

See CLAUDE.md for architecture and scope, BUILD_PLAN.md for the milestone order.
"""

__version__ = "0.1.0"
