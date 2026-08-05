from __future__ import annotations

import json
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, validate_json

MODERN_PROTOCOL_VERSION = "2026-07-28"


class RuntimeMcpError(RuntimeError):
    """Runtime MCP transport or contract failure."""


def _parse_response(content_type: str, body: bytes) -> JsonObject:
    text = body.decode("utf-8")
    if "text/event-stream" in content_type:
        events = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        if not events:
            raise RuntimeMcpError("Runtime MCP returned an empty event stream")
        text = events[-1]
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeMcpError("Runtime MCP returned invalid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeMcpError("Runtime MCP response is not an object")
    validate_json(value)
    return cast(JsonObject, value)


def read_runtime_token(path: Path) -> str:
    resolved = path.resolve()
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Runtime token source must be a regular file")
    if metadata.st_mode & 0o077:
        raise ValueError("Runtime token source must not be group- or world-readable")
    text = resolved.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() != "ORDIVON_BEARER_TOKEN":
            continue
        token = value.strip()
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
            token = token[1:-1]
        if not token or token != token.strip():
            raise ValueError("Runtime bearer token is empty or malformed")
        return token
    raise ValueError("Runtime token source lacks ORDIVON_BEARER_TOKEN")


@dataclass(slots=True)
class RuntimeMcpClient:
    endpoint: str
    token: str
    client_name: str
    timeout_seconds: float = 30.0
    request_id: int = 0

    def __post_init__(self) -> None:
        if not self.endpoint.startswith("http://127.0.0.1:"):
            raise ValueError("P0-C Runtime endpoint must be loopback HTTP")
        if not self.token:
            raise ValueError("Runtime MCP bearer token cannot be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("Runtime MCP timeout must be positive")

    def _metadata(self) -> JsonObject:
        return {
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": self.client_name,
                "version": "1",
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }

    def _exchange(self, method: str, params: JsonObject | None = None) -> JsonObject:
        self.request_id += 1
        request_id = self.request_id
        request_params: JsonObject = {} if params is None else dict(params)
        request_params["_meta"] = self._metadata()
        payload: JsonObject = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": request_params,
        }
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
            "Mcp-Method": method,
        }
        if method == "tools/call" and params is not None:
            name = params.get("name")
            if isinstance(name, str):
                headers["Mcp-Name"] = name
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                message = _parse_response(response.headers.get("Content-Type", ""), response.read())
                status = int(response.status)
        except urllib.error.HTTPError as error:
            message = _parse_response(error.headers.get("Content-Type", ""), error.read())
            status = int(error.code)
        except urllib.error.URLError as error:
            raise RuntimeMcpError(
                f"Runtime MCP transport failed: {type(error.reason).__name__}"
            ) from error
        if message.get("id") != request_id:
            raise RuntimeMcpError("Runtime MCP response identity differs from request")
        remote_error = message.get("error")
        if status >= 400 or isinstance(remote_error, dict):
            raise RuntimeMcpError(f"Runtime MCP {method} failed with HTTP {status}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise RuntimeMcpError("Runtime MCP response lacks an object result")
        return result

    def discover_tool_catalog_digest(self) -> str:
        result = self._exchange("server/discover", {})
        metadata = result.get("_meta")
        if not isinstance(metadata, dict):
            raise RuntimeMcpError("Runtime discovery lacks metadata")
        digest = metadata.get("com.ordivon/runtime/toolCatalogDigest")
        if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:"):
            raise RuntimeMcpError("Runtime discovery lacks Tool catalog digest")
        return digest

    def call_tool(self, name: str, arguments: JsonObject) -> JsonObject:
        result = self._exchange("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError") is True:
            raise RuntimeMcpError(f"Runtime Tool {name} returned an error")
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise RuntimeMcpError(f"Runtime Tool {name} omitted structured content")
        validate_json(structured)
        return structured


__all__ = [
    "MODERN_PROTOCOL_VERSION",
    "RuntimeMcpClient",
    "RuntimeMcpError",
    "read_runtime_token",
]
