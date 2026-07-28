"""Fixed lifecycle coordination for disposable Security campaigns."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence

from .bindings import ComponentBinding, ResidualCheck, ResidualReport, SUPPORTED_COMPONENTS
from .bundle import BundleReceipt, EvidenceAttachment, export_evidence_bundle
from .campaign import ContractError, canonical_bytes, digest
from .ledger import CampaignLedger, CampaignProjection

FIXED_ORDERS: dict[str, tuple[str, ...]] = {
    "prepare": ("link", "edge", "runtime", "game", "host"),
    "start": ("link", "edge", "runtime", "game", "host"),
    "freeze": ("edge", "link", "runtime", "game", "host"),
    "reset": ("runtime", "edge", "link", "game", "host"),
    "destroy": ("runtime", "edge", "link", "game", "host"),
    "reconstruct": ("link", "edge", "game", "runtime", "host"),
    "verify": ("link", "edge", "runtime", "game", "host"),
}
PHASE_BEFORE = {"prepare": "preparing"}
PHASE_AFTER = {
    "prepare": "ready",
    "start": "running",
    "freeze": "frozen",
    "reset": "ready",
    "destroy": "destroyed",
}


class CoordinatorError(ContractError):
    """A lifecycle operation could not be admitted or completed."""


class AmbiguousOperationError(RuntimeError):
    """The component may have accepted an operation whose response was lost."""


class ObserverUnavailableError(RuntimeError):
    """Independent observation is unavailable."""


class ComponentPort(Protocol):
    project: str

    def snapshot(self, campaign_id: str, world_id: str) -> dict[str, Any]: ...

    def execute(self, operation: str, operation_id: str) -> dict[str, Any]: ...

    def reconcile(self, operation: str, operation_id: str) -> dict[str, Any]: ...

    def residual_checks(self) -> Sequence[ResidualCheck]: ...


@dataclass(frozen=True, slots=True)
class OperationResult:
    operation_id: str
    operation: str
    component: str
    state: str
    receipt: dict[str, Any] | None
    detail: str


@dataclass(frozen=True, slots=True)
class LifecycleRun:
    operation: str
    results: tuple[OperationResult, ...]
    projection: CampaignProjection


class CampaignCoordinator:
    def __init__(self, ledger: CampaignLedger, ports: Sequence[ComponentPort]) -> None:
        self.ledger = ledger
        self.ports: dict[str, ComponentPort] = {}
        for port in ports:
            if port.project not in SUPPORTED_COMPONENTS:
                raise CoordinatorError([f"unsupported component {port.project!r}"])
            if port.project in self.ports:
                raise CoordinatorError([f"duplicate component {port.project!r}"])
            self.ports[port.project] = port

    def bind_components(self, *, recorded_at: str) -> CampaignProjection:
        projection = self.ledger.projection()
        for project in FIXED_ORDERS["prepare"]:
            port = self.ports.get(project)
            if port is None:
                continue
            snapshot = port.snapshot(projection.campaign_id, projection.world_id)
            expected = {"native_id", "revision", "root_digest", "metadata"}
            if not isinstance(snapshot, dict) or set(snapshot) != expected:
                raise CoordinatorError([f"{project} snapshot has an invalid shape"])
            binding = ComponentBinding.create(
                project=project,
                campaign_id=projection.campaign_id,
                world_id=projection.world_id,
                native_id=snapshot["native_id"],
                revision=snapshot["revision"],
                root_digest=snapshot["root_digest"],
                metadata=snapshot["metadata"],
            )
            projection = self.ledger.bind_component(binding, recorded_at=recorded_at)
        return projection

    def run_fixed(self, operation: str, *, recorded_at: str) -> LifecycleRun:
        if operation not in FIXED_ORDERS:
            raise CoordinatorError([f"unsupported fixed operation {operation!r}"])
        target_before = PHASE_BEFORE.get(operation)
        projection = self.ledger.projection()
        if target_before is not None and projection.phase != target_before:
            projection = self.ledger.set_phase(
                target_before,
                reason=f"begin fixed {operation} lifecycle",
                recorded_at=recorded_at,
            )
        results: list[OperationResult] = []
        for project in FIXED_ORDERS[operation]:
            if project not in self.ports:
                continue
            result = self.run_component(operation, project, recorded_at=recorded_at)
            results.append(result)
            if result.state != "succeeded":
                return LifecycleRun(operation, tuple(results), self.ledger.projection())
        target_after = PHASE_AFTER.get(operation)
        if target_after is not None and self.ledger.projection().phase != target_after:
            projection = self.ledger.set_phase(
                target_after,
                reason=f"completed fixed {operation} lifecycle",
                recorded_at=recorded_at,
            )
        else:
            projection = self.ledger.projection()
        return LifecycleRun(operation, tuple(results), projection)

    def run_component(
        self,
        operation: str,
        project: str,
        *,
        recorded_at: str,
        operation_id: str | None = None,
    ) -> OperationResult:
        if operation not in FIXED_ORDERS:
            raise CoordinatorError([f"unsupported fixed operation {operation!r}"])
        port = self.ports.get(project)
        if port is None:
            raise CoordinatorError([f"no component port for {project!r}"])
        projection = self.ledger.projection()
        operation_id = operation_id or self._operation_id(projection, operation, project)
        existing = projection.operations.get(operation_id)
        if existing is not None:
            return self._stored_result(operation_id, existing)
        self.ledger.transition_operation(
            operation_id=operation_id,
            operation=operation,
            component=project,
            state="prepared",
            recorded_at=recorded_at,
            detail="intent persisted before component call",
        )
        self.ledger.transition_operation(
            operation_id=operation_id,
            operation=operation,
            component=project,
            state="dispatched",
            recorded_at=recorded_at,
            detail="component boundary crossed",
        )
        try:
            native = port.execute(operation, operation_id)
            if operation == "reconstruct":
                self._validate_reconstruction(project, projection, native)
            receipt = self._receipt(project, operation, operation_id, native)
        except ObserverUnavailableError as exc:
            self._mark_observer(project, exc, recorded_at)
            projection = self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="unknown",
                recorded_at=recorded_at,
                detail="independent observer unavailable",
            )
        except AmbiguousOperationError as exc:
            projection = self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="unknown",
                recorded_at=recorded_at,
                detail=self._bounded_detail(exc),
            )
        except Exception as exc:
            projection = self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="failed",
                recorded_at=recorded_at,
                detail=self._bounded_detail(exc),
            )
        else:
            projection = self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="succeeded",
                recorded_at=recorded_at,
                receipt=receipt,
                detail="component receipt admitted",
            )
        return self._stored_result(operation_id, projection.operations[operation_id])

    def reconcile(self, operation_id: str, *, recorded_at: str) -> OperationResult:
        projection = self.ledger.projection()
        existing = projection.operations.get(operation_id)
        if existing is None:
            raise CoordinatorError(["unknown Campaign operation identity"])
        if existing["state"] not in {"unknown", "reconciling"}:
            return self._stored_result(operation_id, existing)
        operation = existing["operation"]
        project = existing["component"]
        port = self.ports.get(project)
        if port is None:
            raise CoordinatorError([f"no component port for {project!r}"])
        if existing["state"] == "unknown":
            self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="reconciling",
                recorded_at=recorded_at,
                detail="querying native identity before any new dispatch",
            )
        try:
            native = port.reconcile(operation, operation_id)
            if operation == "reconstruct":
                self._validate_reconstruction(project, projection, native)
            receipt = self._receipt(project, operation, operation_id, native)
        except ObserverUnavailableError as exc:
            self._mark_observer(project, exc, recorded_at)
            projection = self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="unknown",
                recorded_at=recorded_at,
                detail="reconciliation observer unavailable",
            )
        except AmbiguousOperationError as exc:
            projection = self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="unknown",
                recorded_at=recorded_at,
                detail=self._bounded_detail(exc),
            )
        except Exception as exc:
            projection = self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="failed",
                recorded_at=recorded_at,
                detail=self._bounded_detail(exc),
            )
        else:
            projection = self.ledger.transition_operation(
                operation_id=operation_id,
                operation=operation,
                component=project,
                state="succeeded",
                recorded_at=recorded_at,
                receipt=receipt,
                detail="native reconciliation proved occurrence",
            )
        return self._stored_result(operation_id, projection.operations[operation_id])

    def reconcile_all(self, *, recorded_at: str) -> tuple[OperationResult, ...]:
        projection = self.ledger.projection()
        return tuple(
            self.reconcile(operation_id, recorded_at=recorded_at)
            for operation_id, operation in sorted(projection.operations.items())
            if operation["state"] in {"unknown", "reconciling"}
        )

    def assess_residuals(self, *, recorded_at: str) -> ResidualReport:
        projection = self.ledger.projection()
        checks: list[ResidualCheck] = []
        for project in FIXED_ORDERS["destroy"]:
            port = self.ports.get(project)
            if port is None:
                continue
            try:
                checks.extend(port.residual_checks())
            except ObserverUnavailableError as exc:
                self._mark_observer(project, exc, recorded_at)
                checks.append(
                    ResidualCheck(
                        component=project,
                        subject_id=f"{project}:residual-observer",
                        status="observer_unavailable",
                        detail=self._bounded_detail(exc),
                    )
                )
            except Exception as exc:
                checks.append(
                    ResidualCheck(
                        component=project,
                        subject_id=f"{project}:residual-inspection",
                        status="unknown",
                        detail=self._bounded_detail(exc),
                    )
                )
        report = ResidualReport.create(
            campaign_id=projection.campaign_id,
            world_id=projection.world_id,
            checks=checks,
        )
        self.ledger.record_residual_report(report, recorded_at=recorded_at)
        return report

    def export(
        self,
        destination: str,
        *,
        bundle_id: str,
        recorded_at: str,
        residual_report: ResidualReport | None = None,
        attachments: Sequence[EvidenceAttachment] = (),
    ) -> BundleReceipt:
        projection = self.ledger.projection()
        operation_id = self._operation_id(projection, "export", "security")
        self.ledger.transition_operation(
            operation_id=operation_id,
            operation="export",
            component="security",
            state="prepared",
            recorded_at=recorded_at,
            detail="bundle export intent persisted",
        )
        self.ledger.transition_operation(
            operation_id=operation_id,
            operation="export",
            component="security",
            state="dispatched",
            recorded_at=recorded_at,
            detail="writing bounded staging bundle",
        )
        try:
            receipt = export_evidence_bundle(
                self.ledger,
                destination,
                bundle_id=bundle_id,
                residual_report=residual_report,
                attachments=attachments,
            )
        except Exception as exc:
            self.ledger.transition_operation(
                operation_id=operation_id,
                operation="export",
                component="security",
                state="failed",
                recorded_at=recorded_at,
                detail=self._bounded_detail(exc),
            )
            raise
        receipt_payload = receipt.to_dict()
        self.ledger.transition_operation(
            operation_id=operation_id,
            operation="export",
            component="security",
            state="succeeded",
            recorded_at=recorded_at,
            receipt=self._receipt("security", "export", operation_id, receipt_payload),
            detail="sealed bundle committed by atomic rename",
        )
        self.ledger.record_evidence_export(
            bundle_id=receipt.bundle_id,
            bundle_digest=receipt.bundle_digest,
            file_count=receipt.file_count,
            total_bytes=receipt.total_bytes,
            recorded_at=recorded_at,
        )
        return receipt

    def finalize_infrastructure_outcome(
        self, *, recorded_at: str, evidence_refs: list[str]
    ) -> CampaignProjection:
        projection = self.ledger.projection()
        unresolved = [
            identity
            for identity, operation in projection.operations.items()
            if operation["state"] in {"unknown", "reconciling"}
        ]
        failed = [
            identity
            for identity, operation in projection.operations.items()
            if operation["state"] == "failed"
        ]
        residual = projection.residual_report
        if projection.observer_status == "unavailable":
            classification, quality = "observer_loss", "inconclusive"
            reasons = ["independent-observer-unavailable"]
        elif residual is not None and residual["classification"] == "residual_failure":
            classification, quality = "containment_failure", "invalid"
            reasons = ["unexpected-residual-state"]
        elif failed:
            classification, quality = "invalid_run", "invalid"
            reasons = ["lifecycle-operation-failed"]
        elif unresolved:
            classification, quality = "inconclusive_evidence", "inconclusive"
            reasons = ["operation-outcome-unresolved"]
        else:
            classification, quality, reasons = "success", "conclusive", []
        return self.ledger.record_outcome(
            classification=classification,
            evidence_quality=quality,
            reason_codes=reasons,
            evidence_refs=evidence_refs,
            recorded_at=recorded_at,
        )

    def _validate_reconstruction(
        self,
        project: str,
        projection: CampaignProjection,
        native: dict[str, Any],
    ) -> None:
        snapshot = native.get("snapshot") if isinstance(native, dict) else None
        expected_fields = {"native_id", "revision", "root_digest", "metadata"}
        if not isinstance(snapshot, dict) or set(snapshot) != expected_fields:
            raise CoordinatorError([f"{project} reconstruction lacks a complete snapshot"])
        candidate = ComponentBinding.create(
            project=project,
            campaign_id=projection.campaign_id,
            world_id=projection.world_id,
            native_id=snapshot["native_id"],
            revision=snapshot["revision"],
            root_digest=snapshot["root_digest"],
            metadata=snapshot["metadata"],
        )
        originals = [
            ComponentBinding.from_dict(value)
            for value in projection.bindings.values()
            if value["project"] == project
        ]
        if len(originals) != 1:
            raise CoordinatorError([f"{project} reconstruction requires one original binding"])
        if candidate.binding_digest != originals[0].binding_digest:
            raise CoordinatorError([f"{project} reconstructed identity differs from admission"])

    def _mark_observer(
        self, project: str, error: BaseException, recorded_at: str
    ) -> None:
        manifest = self.ledger.manifest()
        self.ledger.mark_observer_unavailable(
            observer_actor_id=manifest["authority"]["observer_actor_ids"][0],
            component=project,
            reason=self._bounded_detail(error),
            recorded_at=recorded_at,
        )

    @staticmethod
    def _stored_result(operation_id: str, stored: dict[str, Any]) -> OperationResult:
        return OperationResult(
            operation_id=operation_id,
            operation=stored["operation"],
            component=stored["component"],
            state=stored["state"],
            receipt=stored["receipt"],
            detail=stored["detail"],
        )

    @staticmethod
    def _operation_id(
        projection: CampaignProjection, operation: str, component: str
    ) -> str:
        material = {
            "campaign_id": projection.campaign_id,
            "world_id": projection.world_id,
            "operation": operation,
            "component": component,
            "next_revision": projection.revision + 1,
        }
        token = digest(material).removeprefix("sha256:")[:32]
        return f"urn:ordivon:security:operation:{operation}:{component}:{token}"

    @staticmethod
    def _receipt(
        project: str,
        operation: str,
        operation_id: str,
        native: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(native, dict):
            raise CoordinatorError(["component receipt must be an object"])
        canonical_bytes(native)
        material = {
            "schema_version": 1,
            "project": project,
            "operation": operation,
            "operation_id": operation_id,
            "native": native,
        }
        return {**material, "receipt_digest": digest(material)}

    @staticmethod
    def _bounded_detail(error: BaseException) -> str:
        text = str(error).strip() or error.__class__.__name__
        return text[:2048]
