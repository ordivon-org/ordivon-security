"""Process adapters for the first live Link/Edge/Runtime composition.

These adapters consume component-owned command surfaces. They do not copy Link
World state, Edge Node lifecycle state, or Runtime Job semantics into Security.
"""

from __future__ import annotations

import json
import os
import selectors
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .bindings import ResidualCheck
from .campaign import canonical_bytes, digest
from .coordinator import AmbiguousOperationError, ObserverUnavailableError


class ComponentProcessError(RuntimeError):
    """A component-owned control process rejected or failed an operation."""


def _json_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ComponentProcessError(f"{label} did not return a JSON object")
    canonical_bytes(value)
    return value


def _bounded(value: str, maximum: int = 2048) -> str:
    return (value.strip() or "component process failed")[:maximum]


@dataclass(frozen=True, slots=True)
class LinkPortPaths:
    manifest: Path
    authority_root: Path
    observer_root: Path
    actor_root: Path
    operation_root: Path
    reconstruction_root: Path


class LinkCliPort:
    project = "link"

    def __init__(
        self,
        executable: str | Path,
        paths: LinkPortPaths,
        *,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.executable = str(Path(executable).resolve())
        self.paths = paths
        self.timeout_seconds = timeout_seconds

    def snapshot(self, campaign_id: str, world_id: str) -> dict[str, Any]:
        del campaign_id, world_id
        return self._run(["snapshot"])

    def execute(self, operation: str, operation_id: str) -> dict[str, Any]:
        return self._normalize_operation(
            operation, self._run(["execute", operation, operation_id])
        )

    def reconcile(self, operation: str, operation_id: str) -> dict[str, Any]:
        return self._normalize_operation(
            operation, self._run(["reconcile", operation, operation_id])
        )

    @staticmethod
    def _normalize_operation(operation: str, result: dict[str, Any]) -> dict[str, Any]:
        if operation != "reconstruct" or "snapshot" in result:
            return result
        detail = result.get("detail")
        if isinstance(detail, dict) and isinstance(detail.get("snapshot"), dict):
            return {**result, "snapshot": detail["snapshot"]}
        return result

    def residual_checks(self) -> Sequence[ResidualCheck]:
        payload = self._run(["residual"])
        checks = payload.get("checks")
        if not isinstance(checks, list):
            raise ComponentProcessError("Link residual response lacks checks")
        return tuple(ResidualCheck.from_dict(item) for item in checks)

    def _base_command(self) -> list[str]:
        return [
            self.executable,
            "--manifest",
            str(self.paths.manifest),
            "--authority-root",
            str(self.paths.authority_root),
            "--observer-root",
            str(self.paths.observer_root),
            "--actor-root",
            str(self.paths.actor_root),
            "--operation-root",
            str(self.paths.operation_root),
            "--reconstruction-root",
            str(self.paths.reconstruction_root),
        ]

    def _run(self, arguments: list[str]) -> dict[str, Any]:
        completed = subprocess.run(
            [*self._base_command(), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        if completed.returncode != 0:
            detail = _bounded(completed.stderr or completed.stdout)
            if "observer" in detail.lower() and (
                "unavailable" in detail.lower() or "no such file" in detail.lower()
            ):
                raise ObserverUnavailableError(detail)
            if "response loss" in detail.lower() or "does not prove" in detail.lower():
                raise AmbiguousOperationError(detail)
            raise ComponentProcessError(detail)
        try:
            return _json_object(json.loads(completed.stdout), "Link control process")
        except json.JSONDecodeError as exc:
            raise ComponentProcessError(f"Link emitted invalid JSON: {exc}") from exc


class EdgeJsonLinePort:
    project = "edge"

    def __init__(
        self,
        command: Sequence[str],
        *,
        cwd: str | Path,
        root: str | Path,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.command = tuple(command)
        self.cwd = str(Path(cwd).resolve())
        self.root = str(Path(root).resolve())
        self.timeout_seconds = timeout_seconds
        self._sequence = 0
        self._process = subprocess.Popen(
            [*self.command, "--root", self.root],
            cwd=self.cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        if self._process.stdin is None or self._process.stdout is None:
            self.close()
            raise ComponentProcessError("Edge control process pipes are unavailable")

    def declare(self, input_value: dict[str, Any], entrypoint: bytes) -> dict[str, Any]:
        payload = self._request(
            {
                "schema_version": 1,
                "request_id": self._request_id("declare"),
                "action": "declare",
                "input": input_value,
                "entrypoint_base64": __import__("base64").b64encode(entrypoint).decode("ascii"),
            }
        )
        return _json_object(payload, "Edge declaration")

    def snapshot(self, campaign_id: str, world_id: str) -> dict[str, Any]:
        del campaign_id, world_id
        result = self._request(
            {
                "schema_version": 1,
                "request_id": self._request_id("snapshot"),
                "action": "snapshot",
            }
        )
        snapshot = result.get("snapshot")
        return _json_object(snapshot, "Edge binding snapshot")

    def execute(self, operation: str, operation_id: str) -> dict[str, Any]:
        result = self._request(
            {
                "schema_version": 1,
                "request_id": self._request_id(f"execute-{operation}"),
                "action": "execute",
                "operation": operation,
                "operation_id": operation_id,
            }
        )
        return self._normalize_operation(operation, result)

    def reconcile(self, operation: str, operation_id: str) -> dict[str, Any]:
        result = self._request(
            {
                "schema_version": 1,
                "request_id": self._request_id(f"reconcile-{operation}"),
                "action": "reconcile",
                "operation": operation,
                "operation_id": operation_id,
            }
        )
        return self._normalize_operation(operation, result)

    @staticmethod
    def _normalize_operation(operation: str, result: dict[str, Any]) -> dict[str, Any]:
        if operation != "reconstruct" or "snapshot" in result:
            return result
        detail = result.get("detail")
        if isinstance(detail, dict) and isinstance(detail.get("snapshot"), dict):
            return {**result, "snapshot": detail["snapshot"]}
        return result

    def residual_checks(self) -> Sequence[ResidualCheck]:
        result = self._request(
            {
                "schema_version": 1,
                "request_id": self._request_id("residual"),
                "action": "residual",
            }
        )
        checks = result.get("checks")
        if not isinstance(checks, list):
            raise ComponentProcessError("Edge residual response lacks checks")
        return tuple(ResidualCheck.from_dict(item) for item in checks)

    def close(self) -> None:
        process = getattr(self, "_process", None)
        if process is None or process.poll() is not None:
            return
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def __enter__(self) -> "EdgeJsonLinePort":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request_id(self, label: str) -> str:
        self._sequence += 1
        return f"security-{self._sequence:04d}-{label}"[:128]

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._process.poll() is not None:
            raise ComponentProcessError(self._process_failure("Edge control process exited"))
        assert self._process.stdin is not None
        assert self._process.stdout is not None
        self._process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self._process.stdin.flush()

        selector = selectors.DefaultSelector()
        selector.register(self._process.stdout, selectors.EVENT_READ)
        try:
            events = selector.select(self.timeout_seconds)
        finally:
            selector.close()
        if not events:
            raise AmbiguousOperationError("Edge control response timed out")
        line = self._process.stdout.readline()
        if not line:
            raise ComponentProcessError(self._process_failure("Edge control response closed"))
        try:
            response = _json_object(json.loads(line), "Edge control process")
        except json.JSONDecodeError as exc:
            raise ComponentProcessError(f"Edge emitted invalid JSON: {exc}") from exc
        if response.get("ok") is True:
            return _json_object(response.get("result"), "Edge control result")
        error = response.get("error")
        if not isinstance(error, dict):
            raise ComponentProcessError("Edge failure response lacks an error object")
        code = error.get("code")
        message = _bounded(str(error.get("message", "Edge operation failed")))
        if code == "operation_unknown":
            raise AmbiguousOperationError(message)
        if code == "observer_unavailable":
            raise ObserverUnavailableError(message)
        raise ComponentProcessError(message)

    def _process_failure(self, prefix: str) -> str:
        stderr = ""
        if self._process.stderr is not None:
            try:
                stderr = self._process.stderr.read(2048)
            except OSError:
                pass
        return f"{prefix}: {_bounded(stderr)}"


class RuntimeFixturePort:
    """Acceptance bridge that keeps the Link fixture under one Runtime Job.

    This is not a new Runtime protocol. The surrounding Ordivon Runtime Job is
    the real execution substrate; this object only controls its child fixture.
    """

    project = "runtime"

    def __init__(
        self,
        *,
        link_world_executable: str | Path,
        link_paths: LinkPortPaths,
        world_id: str,
        fixture_addresses: Iterable[str],
        runtime_workspace_id: str,
        runtime_source_revision: str,
        runtime_client_request_id: str,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.link_world_executable = str(Path(link_world_executable).resolve())
        self.link_paths = link_paths
        self.world_id = world_id
        self.fixture_addresses = tuple(fixture_addresses)
        self.runtime_workspace_id = runtime_workspace_id
        self.runtime_source_revision = runtime_source_revision
        self.runtime_client_request_id = runtime_client_request_id
        self.timeout_seconds = timeout_seconds
        self._process: subprocess.Popen[str] | None = None
        material = {
            "workspace_id": runtime_workspace_id,
            "source_revision": runtime_source_revision,
            "client_request_id": runtime_client_request_id,
            "role": "link-fixture-holder",
        }
        self._root_digest = digest(material)

    def snapshot(self, campaign_id: str, world_id: str) -> dict[str, Any]:
        return {
            "native_id": f"runtime-workspace:{self.runtime_workspace_id}",
            "revision": self.runtime_source_revision,
            "root_digest": self._root_digest,
            "metadata": {
                "schema_version": 1,
                "client_request_id": self.runtime_client_request_id,
                "role": "link-fixture-holder",
                "binding_scope": "acceptance-runtime-workspace",
            },
        }

    def execute(self, operation: str, operation_id: str) -> dict[str, Any]:
        if operation == "start":
            self._start_fixture()
        elif operation in {"freeze", "reset", "destroy"}:
            self._stop_fixture()
        elif operation not in {"prepare", "reconstruct", "verify"}:
            raise ComponentProcessError(f"Runtime acceptance operation is unsupported: {operation}")
        return self._receipt(operation, operation_id)

    def reconcile(self, operation: str, operation_id: str) -> dict[str, Any]:
        running = self._process is not None and self._process.poll() is None
        if operation == "start" and not running:
            raise AmbiguousOperationError("Runtime fixture is not running")
        if operation in {"freeze", "reset", "destroy"} and running:
            raise AmbiguousOperationError("Runtime fixture is still running")
        return self._receipt(operation, operation_id, reconciled=True)

    def residual_checks(self) -> Sequence[ResidualCheck]:
        running = self._process is not None and self._process.poll() is None
        checks = [
            ResidualCheck(
                component="runtime",
                subject_id=f"runtime-workspace:{self.runtime_workspace_id}:fixture-process",
                status="unexpected_residual" if running else "clean",
                detail=(
                    "Link fixture process remains alive"
                    if running
                    else "Link fixture process is terminal"
                ),
            )
        ]
        for address in self.fixture_addresses:
            host, port_text = address.rsplit(":", 1)
            try:
                with socket.create_connection((host, int(port_text)), timeout=0.25):
                    status = "unexpected_residual"
                    detail = "fixture listener still accepts connections"
            except ConnectionRefusedError:
                status = "clean"
                detail = "fixture listener explicitly refuses connections"
            except OSError:
                status = "unknown"
                detail = "fixture listener state could not be independently inspected"
            checks.append(
                ResidualCheck(
                    component="runtime",
                    subject_id=f"runtime-workspace:{self.runtime_workspace_id}:listener:{address}",
                    status=status,
                    detail=detail,
                )
            )
        return tuple(checks)

    def close(self) -> None:
        self._stop_fixture()

    def _start_fixture(self) -> None:
        if self._process is not None and self._process.poll() is None:
            return
        command = [
            self.link_world_executable,
            "--authority-root",
            str(self.link_paths.authority_root),
            "--observer-root",
            str(self.link_paths.observer_root),
            "--actor-root",
            str(self.link_paths.actor_root),
            "fixture",
            self.world_id,
            "--poll-ms",
            "25",
        ]
        self._process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        deadline = time.monotonic() + self.timeout_seconds
        last_error = "fixture did not become reachable"
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise ComponentProcessError(self._process_error("Link fixture exited"))
            try:
                for address in self.fixture_addresses:
                    host, port_text = address.rsplit(":", 1)
                    with socket.create_connection((host, int(port_text)), timeout=0.25) as stream:
                        response = stream.recv(4096)
                        if self.world_id.encode("utf-8") not in response:
                            raise ComponentProcessError("Link fixture response lacks World identity")
                return
            except (OSError, ComponentProcessError) as exc:
                last_error = str(exc)
                time.sleep(0.05)
        self._stop_fixture()
        raise ComponentProcessError(_bounded(last_error))

    def _stop_fixture(self) -> None:
        if self._process is None:
            return
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)
        self._process = None

    def _receipt(
        self, operation: str, operation_id: str, *, reconciled: bool = False
    ) -> dict[str, Any]:
        running = self._process is not None and self._process.poll() is None
        return {
            "schema_version": 1,
            "project": "runtime",
            "operation": operation,
            "operation_id": operation_id,
            "runtime_workspace_id": self.runtime_workspace_id,
            "runtime_client_request_id": self.runtime_client_request_id,
            "fixture_running": running,
            "reconciled": reconciled,
            **(
                {"snapshot": self.snapshot("bound-campaign", "bound-world")}
                if operation == "reconstruct"
                else {}
            ),
        }

    def _process_error(self, prefix: str) -> str:
        stderr = ""
        if self._process is not None and self._process.stderr is not None:
            stderr = self._process.stderr.read(2048)
        return f"{prefix}: {_bounded(stderr)}"
