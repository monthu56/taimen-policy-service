"""Проекция структурных отношений из журналов resource servers.

Pull-воркеры с durable-курсором: Control Plane (`GET /api/v1/events`, курсор
непрозрачный) и IAM (`GET /api/v1/events?after=<sequence>`). Каждое событие
применяется идемпотентно (`apply_relations` дедуплицирует по ключу tuple),
курсор продвигается после успешного применения.
"""

from policy_service.projection.control_plane import ControlPlaneSource
from policy_service.projection.iam import IamSource
from policy_service.projection.runner import ProjectionRunner, ProjectionSource

__all__ = ["ControlPlaneSource", "IamSource", "ProjectionRunner", "ProjectionSource"]
