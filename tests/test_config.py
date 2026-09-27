"""Per-model request presets.

Regression source: the first Haiku 4.5 run sent the Opus defaults (adaptive
thinking, effort) and every turn failed with HTTP 400 — the §9 ablation model
could not run at all.
"""

import logging
from types import SimpleNamespace

import pytest
from anthropic.types import Message

from graphgate.cli import build_parser
from graphgate.config import OMIT, USE_PRESET, ModelConfig
from graphgate.llm.anthropic_client import AnthropicCodeGenClient


def captured_request(config: ModelConfig) -> dict:
    """Run one completion and return the kwargs the SDK actually received."""
    sent = {}

    def create(**kwargs):
        sent.update(kwargs)
        return Message.model_validate({
            "id": "msg", "type": "message", "role": "assistant",
            "model": config.model,
            "content": [{"type": "text", "text": "### FILE: a.py\n```python\nx = 1\n```\n"}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        })

    fake_sdk = SimpleNamespace(messages=SimpleNamespace(create=create))
    AnthropicCodeGenClient(config, client=fake_sdk).complete("sys", "user", replication=0)
    return sent


def test_haiku_request_omits_the_settings_it_rejects():
    sent = captured_request(ModelConfig.for_model("claude-haiku-4-5"))

    assert "thinking" not in sent
    assert "output_config" not in sent
    assert sent["model"] == "claude-haiku-4-5"


def test_opus_5_request_is_unchanged_by_the_presets():
    """The exact shape matters: it is hashed, so any change would make every
    existing trace fail replay's hash check and every cache entry miss."""
    config = ModelConfig.for_model("claude-opus-5")
    client = AnthropicCodeGenClient(config, client=SimpleNamespace())

    assert client.describe_params() == {
        "max_tokens": 16_000,
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "medium"},
    }


@pytest.mark.parametrize("model", ["claude-opus-5-5", "claude-opus-5", "claude-opus-4-8"])
def test_every_opus_candidate_has_a_preset(model, caplog):
    """The code-generation model is still being chosen between these; each
    must run with known settings, not the unknown-model fallback."""
    with caplog.at_level(logging.WARNING, logger="graphgate.config"):
        config = ModelConfig.for_model(model)
    assert (config.thinking, config.effort) == ("adaptive", "medium")
    assert caplog.text == ""


def test_opus_4_8_asks_for_thinking_explicitly():
    """Opus 4.8 does not think unless asked, unlike Opus 5."""
    sent = captured_request(ModelConfig.for_model("claude-opus-4-8"))
    assert sent["thinking"] == {"type": "adaptive"}


def test_an_explicit_setting_overrides_the_preset():
    config = ModelConfig.for_model("claude-opus-5", effort="high", thinking="disabled")
    assert (config.effort, config.thinking) == ("high", "disabled")


def test_none_leaves_the_field_out_of_the_request():
    sent = captured_request(ModelConfig.for_model("claude-opus-5", effort=OMIT))
    assert "output_config" not in sent
    assert sent["thinking"] == {"type": "adaptive"}


def test_unknown_model_falls_back_to_opus_defaults_with_a_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="graphgate.config"):
        config = ModelConfig.for_model("claude-some-future-model")

    assert (config.thinking, config.effort) == ("adaptive", "medium")
    assert "no request preset" in caplog.text


def test_unknown_model_with_every_setting_explicit_does_not_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="graphgate.config"):
        ModelConfig.for_model("claude-some-future-model", thinking=OMIT, effort=OMIT)
    assert caplog.text == ""


def test_cli_defaults_to_the_model_preset():
    args = build_parser().parse_args(
        ["--out", "o", "--snapshot", "s", "--prompts", "p", "--trace-id", "t",
         "--model", "claude-haiku-4-5"]
    )
    assert args.thinking == USE_PRESET
    assert args.effort == USE_PRESET


@pytest.mark.parametrize("flag", ["--thinking", "--effort"])
def test_cli_accepts_none_to_omit(flag):
    args = build_parser().parse_args(
        ["--out", "o", "--snapshot", "s", "--prompts", "p", "--trace-id", "t", flag, "none"]
    )
    assert getattr(args, flag.lstrip("-")) == OMIT


def test_real_client_keeps_requested_and_reported_model_apart():
    """The hash must cover the ID we sent; the paper needs the snapshot served."""
    config = ModelConfig.for_model("claude-haiku-4-5")
    message = Message.model_validate({
        "id": "msg", "type": "message", "role": "assistant",
        "model": "claude-haiku-4-5-20251001",
        "content": [{"type": "text", "text": "### FILE: a.py\n```python\nx = 1\n```\n"}],
        "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    })
    fake_sdk = SimpleNamespace(messages=SimpleNamespace(create=lambda **_: message))
    client = AnthropicCodeGenClient(config, client=fake_sdk)

    completion = client.complete("sys", "user", replication=0)

    assert completion.model == "claude-haiku-4-5"
    assert completion.resolved_model == "claude-haiku-4-5-20251001"
    assert completion.prompt_hash == client.request_hash("sys", "user")
