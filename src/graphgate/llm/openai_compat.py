"""A :class:`~graphgate.llm.base.CodeGenClient` for open-weight models.

Speaks the chat-completions protocol that local model servers (Ollama,
llama.cpp, vLLM) and most hosting services share, so one client covers a model
run in a notebook and the same model served elsewhere. Uses only the standard
library: no SDK has to be installed where the model runs.

Two differences from the Anthropic client:

- The request carries ``seed``, set to the replication number. These servers
  accept one, so a replication can be regenerated on the same server and model
  build; the response cache and trace replay remain what the study relies on.
- There is no refusal signal. A model that declines does so in prose, which
  the harness then records as an unusable reply.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from graphgate.config import ModelConfig
from graphgate.llm.base import Completion, CompletionError, prompt_hash

PROVIDER = "openai-compatible"
# Optional: a local server needs no key. Read from the environment, never stored.
API_KEY_ENV = "GRAPHGATE_LLM_API_KEY"
# One turn can take many minutes on a small GPU; the wait must outlast it.
REQUEST_TIMEOUT_SECONDS = 3600


class OpenAICompatClient:
    """One request per turn against ``<base_url>/chat/completions``."""

    def __init__(self, config: ModelConfig, opener=urllib.request.urlopen):
        if config.provider != PROVIDER:
            raise ValueError(f"expected provider {PROVIDER!r}, got {config.provider!r}")
        if not config.base_url:
            raise ValueError("an open-weight model needs --base-url, for example http://localhost:11434/v1")
        self.config = config
        self._url = config.base_url.rstrip("/") + "/chat/completions"
        self._open = opener  # injectable so tests never touch the network

    def _request_params(self) -> dict[str, Any]:
        # The server address is part of the hash: the same model name on
        # another server may be another build of the model.
        return {"max_tokens": self.config.max_tokens, "base_url": self.config.base_url, "seed": "replication"}

    def request_hash(self, system: str, user: str) -> str:
        return prompt_hash(system, user, self.config.model, self._request_params())

    def describe_params(self) -> dict[str, Any]:
        return self._request_params()

    def complete(self, system: str, user: str, *, replication: int) -> Completion:
        key = self.request_hash(system, user)
        body = json.dumps({
            "model": self.config.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": self.config.max_tokens,
            "seed": replication,
            "stream": False,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if os.environ.get(API_KEY_ENV):
            headers["Authorization"] = f"Bearer {os.environ[API_KEY_ENV]}"
        request = urllib.request.Request(self._url, data=body, headers=headers, method="POST")

        started = time.perf_counter()
        try:
            with self._open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise CompletionError(f"model server returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise CompletionError(f"model server call failed: {exc}") from exc
        latency_ms = (time.perf_counter() - started) * 1000

        try:
            choice = data["choices"][0]
            text = choice["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise CompletionError(f"unexpected reply from the model server: {str(data)[:300]}") from exc
        if not text.strip():
            raise CompletionError(f"model returned no text (finish_reason={choice.get('finish_reason')}, "
                                  f"prompt_hash={key[:12]})")
        usage = data.get("usage") or {}
        return Completion(
            text=text,
            model=self.config.model,
            resolved_model=data.get("model"),
            # The harness treats a reply cut off at the limit as unusable and
            # looks for this value to know.
            stop_reason="max_tokens" if choice.get("finish_reason") == "length" else choice.get("finish_reason"),
            prompt_hash=key,
            latency_ms=latency_ms,
            usage={"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0)},
        )
