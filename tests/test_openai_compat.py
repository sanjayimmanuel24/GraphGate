"""Tests for the open-weight model client and the provider choice. No network."""

import io
import json
import urllib.error

import pytest

from graphgate.config import ModelConfig
from graphgate.llm.base import CompletionError
from graphgate.llm.factory import ANTHROPIC, OPENAI_COMPATIBLE, make_client, not_ready
from graphgate.llm.openai_compat import OpenAICompatClient

CONFIG = ModelConfig.for_model("qwen2.5-coder:14b", max_tokens=500, provider=OPENAI_COMPATIBLE,
                               base_url="http://localhost:11434/v1/")


class Server:
    """Answers one request the way a chat-completions server does, and keeps it."""

    def __init__(self, reply=None, error=None):
        self.reply = reply if reply is not None else {
            "model": "qwen2.5-coder:14b-q4", "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3}}
        self.error = error
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        if self.error:
            raise self.error
        return io.BytesIO(json.dumps(self.reply).encode())


def test_a_completion_carries_text_usage_and_both_model_names():
    server = Server()

    done = OpenAICompatClient(CONFIG, opener=server).complete("sys", "user", replication=2)

    sent = json.loads(server.requests[0].data)
    assert server.requests[0].full_url == "http://localhost:11434/v1/chat/completions"
    assert sent["messages"] == [{"role": "system", "content": "sys"}, {"role": "user", "content": "user"}]
    assert (sent["model"], sent["max_tokens"], sent["seed"], sent["stream"]) == ("qwen2.5-coder:14b", 500, 2, False)
    assert (done.text, done.model, done.resolved_model) == ("hello", "qwen2.5-coder:14b", "qwen2.5-coder:14b-q4")
    assert done.usage == {"input_tokens": 11, "output_tokens": 3} and done.stop_reason == "stop"


def test_no_thinking_or_effort_is_sent_to_an_open_model():
    assert (CONFIG.thinking, CONFIG.effort) == (None, None)
    server = Server()
    OpenAICompatClient(CONFIG, opener=server).complete("s", "u", replication=0)

    assert set(json.loads(server.requests[0].data)) == {"model", "messages", "max_tokens", "seed", "stream"}


def test_the_hash_is_the_same_for_every_replication_and_differs_by_server():
    client = OpenAICompatClient(CONFIG, opener=Server())
    elsewhere = OpenAICompatClient(ModelConfig.for_model("qwen2.5-coder:14b", max_tokens=500,
                                                         provider=OPENAI_COMPATIBLE, base_url="http://other/v1"))

    assert client.complete("s", "u", replication=0).prompt_hash == client.request_hash("s", "u")
    assert client.request_hash("s", "u") != elsewhere.request_hash("s", "u")
    assert client.describe_params()["seed"] == "replication"   # the cache keeps replications apart


def test_a_reply_cut_off_at_the_limit_is_marked_as_such():
    server = Server({"choices": [{"message": {"content": "### FILE: a.py"}, "finish_reason": "length"}]})

    assert OpenAICompatClient(CONFIG, opener=server).complete("s", "u", replication=0).stop_reason == "max_tokens"


@pytest.mark.parametrize("server, message", [
    (Server(error=urllib.error.URLError("connection refused")), "call failed"),
    (Server(error=urllib.error.HTTPError("u", 500, "boom", {}, io.BytesIO(b"model not found"))), "HTTP 500: model not found"),
    (Server({"error": "bad"}), "unexpected reply"),
    (Server({"choices": [{"message": {"content": "  "}, "finish_reason": "stop"}]}), "no text"),
])
def test_failures_are_completion_errors(server, message):
    with pytest.raises(CompletionError, match=message):
        OpenAICompatClient(CONFIG, opener=server).complete("s", "u", replication=0)


def test_a_key_is_sent_only_when_the_environment_has_one(monkeypatch):
    server = Server()
    monkeypatch.delenv("GRAPHGATE_LLM_API_KEY", raising=False)
    OpenAICompatClient(CONFIG, opener=server).complete("s", "u", replication=0)
    monkeypatch.setenv("GRAPHGATE_LLM_API_KEY", "not-a-real-key")
    OpenAICompatClient(CONFIG, opener=server).complete("s", "u", replication=0)

    assert server.requests[0].get_header("Authorization") is None
    assert server.requests[1].get_header("Authorization") == "Bearer not-a-real-key"


def test_the_provider_decides_the_client_and_what_it_needs(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert isinstance(make_client(CONFIG), OpenAICompatClient) and not_ready(CONFIG) is None
    assert "ANTHROPIC_API_KEY" in not_ready(ModelConfig())
    assert "--base-url" in not_ready(ModelConfig.for_model("m", provider=OPENAI_COMPATIBLE))
    assert ModelConfig().provider == ANTHROPIC
    with pytest.raises(ValueError, match="unknown provider"):
        make_client(ModelConfig(provider="other"))
