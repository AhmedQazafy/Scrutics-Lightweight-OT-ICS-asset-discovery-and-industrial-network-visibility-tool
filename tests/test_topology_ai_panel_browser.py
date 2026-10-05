"""
The topology page's assistant panel in a headless browser.

fetch is replaced before the page loads and every other request is blocked, so no key leaves the
browser and nothing reaches the network. Skipped when Playwright is not installed.
"""

import json
import os

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

from scrutics.ai.config import (  # noqa: E402
    DEFAULT_ANTHROPIC_MODEL, DEFAULT_GEMINI_MODEL, DEFAULT_OPENAI_MODEL,
)
from scrutics.db.inventory import Asset  # noqa: E402
from scrutics.topology import build_graph_data, generate_topology_html  # noqa: E402

KEY = "test-key-not-real"
QUESTION = "Which devices speak Modbus?"
REPLY = "stub reply"
# Connection line the page puts in the assistant's context for the sample graph
CONNECTION = "10.0.0.20 -> 10.0.0.10 [Modbus TCP]"

# Provider-shaped replies returned by the fetch stub
_STUB_FETCH = """
(() => {
  window.__fetchCalls = [];
  window.__storageWrites = [];
  const replies = {
    "api.openai.com": {choices: [{message: {content: "%(reply)s"}}]},
    "api.anthropic.com": {content: [{type: "text", text: "%(reply)s"}]},
    "generativelanguage.googleapis.com": {candidates: [{content: {parts: [{text: "%(reply)s"}]}}]},
  };
  window.fetch = function (url, init) {
    window.__fetchCalls.push({url: String(url), method: init.method, headers: init.headers,
                              body: JSON.parse(init.body)});
    const host = new URL(String(url)).host;
    return Promise.resolve(new Response(JSON.stringify(replies[host] || {}),
                                        {status: 200, headers: {"Content-Type": "application/json"}}));
  };
  const setItem = Storage.prototype.setItem;
  Storage.prototype.setItem = function (k, v) {
    window.__storageWrites.push([k, v]);
    return setItem.call(this, k, v);
  };
})();
""" % {"reply": REPLY}


class _Inventory:
    def __init__(self, assets):
        self._assets = assets

    def get_all(self):
        return list(self._assets)


@pytest.fixture(scope="module")
def page_path(tmp_path_factory):
    plc = Asset(ip="10.0.0.10", mac="00:0e:8c:00:00:10", protocols=["Modbus TCP"])
    hmi = Asset(ip="10.0.0.20", mac="00:0c:26:00:00:20")
    edges = {(hmi.primary_key, plc.primary_key): {"protocols": {"Modbus TCP"}, "count": 5}}
    path = tmp_path_factory.mktemp("topology") / "topology.html"
    path.write_text(generate_topology_html(build_graph_data(_Inventory([plc, hmi]), edges)),
                    encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        executable = os.environ.get("SCRUTICS_CHROMIUM") or (
            "/opt/pw-browsers/chromium" if os.path.exists("/opt/pw-browsers/chromium") else None
        )
        try:
            b = p.chromium.launch(executable_path=executable) if executable else p.chromium.launch()
        except sync_api.Error as exc:
            pytest.skip(f"Chromium could not be launched: {exc}")
        yield b
        b.close()


def _open(browser, page_path):
    context = browser.new_context()
    context.route("**/*", lambda route: route.continue_()
                  if route.request.url.startswith("file:") else route.abort())
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.add_init_script(_STUB_FETCH)
    page.goto(page_path.as_uri())
    return context, page, errors


def _hidden(page, selector):
    return page.eval_on_selector(selector, "el => el.classList.contains('hidden')")


def test_button_opens_panel_and_tabs_switch(browser, page_path):
    context, page, errors = _open(browser, page_path)
    try:
        assert not page.eval_on_selector("#ai-panel", "el => el.classList.contains('open')")
        page.click("#ai-unified-btn")
        assert page.eval_on_selector("#ai-panel", "el => el.classList.contains('open')")

        for tab, pane in (("chat", "#ai-chat-pane"), ("launch", "#ai-launch-pane"),
                          ("configure", "#ai-configure-pane")):
            page.click(f".ai-tab[data-tab='{tab}']")
            assert not _hidden(page, pane)
            others = {"#ai-chat-pane", "#ai-launch-pane", "#ai-configure-pane"} - {pane}
            assert all(_hidden(page, other) for other in others)

        page.click("#ai-panel-close")
        assert not page.eval_on_selector("#ai-panel", "el => el.classList.contains('open')")
        assert errors == []
    finally:
        context.close()


def _send(browser, page_path, provider):
    context, page, errors = _open(browser, page_path)
    try:
        page.click("#ai-unified-btn")
        page.select_option("#ai-provider-select", provider)
        page.fill("#ai-key-input", KEY)
        page.click("#ai-connect-btn")
        assert not _hidden(page, "#ai-chat-pane")
        assert page.input_value("#ai-key-input") == ""
        page.fill("#ai-chat-input", QUESTION)
        page.click("#ai-chat-send")
        page.wait_for_function(
            "() => [...document.querySelectorAll('.ai-msg.assistant')]"
            f".some(el => el.textContent === {json.dumps(REPLY)})"
        )
        calls = page.evaluate("window.__fetchCalls")
        storage = page.evaluate(
            "() => ({local: localStorage.length, session: sessionStorage.length,"
            " writes: window.__storageWrites, cookie: document.cookie})"
        )
        assert errors == []
        return calls, storage
    finally:
        context.close()


def _assert_key_not_stored(storage):
    assert storage["local"] == 0 and storage["session"] == 0
    assert storage["writes"] == []
    assert KEY not in storage["cookie"]


def test_openai_request_shape(browser, page_path):
    calls, storage = _send(browser, page_path, "openai")
    assert len(calls) == 1
    call = calls[0]
    assert call["url"] == "https://api.openai.com/v1/chat/completions"
    assert call["method"] == "POST"
    assert call["headers"]["Authorization"] == f"Bearer {KEY}"
    body = call["body"]
    assert body["model"] == DEFAULT_OPENAI_MODEL
    assert body["messages"][0]["role"] == "system"
    assert CONNECTION in body["messages"][0]["content"]
    assert body["messages"][-1] == {"role": "user", "content": QUESTION}
    _assert_key_not_stored(storage)


def test_anthropic_request_shape(browser, page_path):
    calls, storage = _send(browser, page_path, "anthropic")
    assert len(calls) == 1
    call = calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["method"] == "POST"
    assert call["headers"]["x-api-key"] == KEY
    assert call["headers"]["anthropic-version"] == "2023-06-01"
    assert call["headers"]["anthropic-dangerous-direct-browser-access"] == "true"
    body = call["body"]
    assert body["model"] == DEFAULT_ANTHROPIC_MODEL
    assert CONNECTION in body["system"]
    assert all(m["role"] != "system" for m in body["messages"])
    assert body["messages"][-1] == {"role": "user", "content": QUESTION}
    _assert_key_not_stored(storage)


def test_gemini_request_shape(browser, page_path):
    calls, storage = _send(browser, page_path, "gemini")
    assert len(calls) == 1
    call = calls[0]
    assert call["url"] == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{DEFAULT_GEMINI_MODEL}:generateContent?key={KEY}"
    )
    assert call["method"] == "POST"
    body = call["body"]
    assert CONNECTION in body["systemInstruction"]["parts"][0]["text"]
    assert body["contents"][-1] == {"role": "user", "parts": [{"text": QUESTION}]}
    _assert_key_not_stored(storage)
