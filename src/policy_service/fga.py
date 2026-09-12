"""HTTP-клиент OpenFGA.

Engine — deployment profile (ADR-0025 п. 5): его API наружу не публикуется,
все обращения идут отсюда. Клиент намеренно узкий: stores, модели, запись
tuples, `check`, `batch-check`, `list-objects`, `list-users`, `read`.

Идемпотентность записи: OpenFGA отвечает 400 на повторную запись существующего
tuple и на удаление отсутствующего. Проекция журналов at-least-once поэтому
пишет через `write_idempotent`, который на конфликте батча повторяет запись
по одному tuple и пропускает уже применённые.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

Consistency = Literal["default", "strong"]


class FgaError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message

    @property
    def retriable(self) -> bool:
        return self.status >= 500


@dataclass(frozen=True)
class Tuple:
    object: str
    relation: str
    subject: str
    condition: dict[str, Any] | None = None

    def key(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "user": self.subject,
            "relation": self.relation,
            "object": self.object,
        }
        if self.condition:
            body["condition"] = self.condition
        return body

    def bare(self) -> dict[str, str]:
        return {"user": self.subject, "relation": self.relation, "object": self.object}


@dataclass(frozen=True)
class CheckItem:
    subject: str
    relation: str
    object: str
    contextual: tuple[Tuple, ...] = ()
    context: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = ""


class FgaClient:
    def __init__(
        self,
        base_url: str,
        *,
        preshared_key: str = "",
        timeout_seconds: float = 3.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"content-type": "application/json"}
        if preshared_key:
            self._headers["Authorization"] = f"Bearer {preshared_key}"
        self._client = client
        self._owns_client = client is None
        self._timeout = timeout_seconds

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        try:
            response = await self._http().request(
                method, f"{self._base_url}{path}", json=body, headers=self._headers
            )
        except httpx.HTTPError as exc:
            raise FgaError(503, "transport", str(exc)) from exc
        if response.status_code >= 400:
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            raise FgaError(
                response.status_code,
                str(payload.get("code", "error")),
                str(payload.get("message", response.text[:200])),
            )
        if not response.content:
            return {}
        return response.json()

    # --- stores и модели -----------------------------------------------------

    async def healthy(self) -> bool:
        try:
            await self._request("GET", "/healthz")
        except FgaError:
            return False
        return True

    async def create_store(self, name: str) -> str:
        data = await self._request("POST", "/stores", {"name": name})
        return str(data["id"])

    async def delete_store(self, store_id: str) -> None:
        await self._request("DELETE", f"/stores/{store_id}")

    async def write_model(self, store_id: str, model: dict[str, Any]) -> str:
        data = await self._request("POST", f"/stores/{store_id}/authorization-models", model)
        return str(data["authorization_model_id"])

    # --- tuples --------------------------------------------------------------

    async def write(
        self,
        store_id: str,
        *,
        writes: Iterable[Tuple] = (),
        deletes: Iterable[Tuple] = (),
        model_id: str = "",
    ) -> None:
        body: dict[str, Any] = {}
        write_keys = [t.key() for t in writes]
        delete_keys = [t.bare() for t in deletes]
        if write_keys:
            body["writes"] = {"tuple_keys": write_keys}
        if delete_keys:
            body["deletes"] = {"tuple_keys": delete_keys}
        if not body:
            return
        if model_id:
            body["authorization_model_id"] = model_id
        await self._request("POST", f"/stores/{store_id}/write", body)

    async def write_idempotent(
        self,
        store_id: str,
        *,
        writes: Iterable[Tuple] = (),
        deletes: Iterable[Tuple] = (),
        model_id: str = "",
    ) -> None:
        writes = list(writes)
        deletes = list(deletes)
        try:
            await self.write(store_id, writes=writes, deletes=deletes, model_id=model_id)
            return
        except FgaError as exc:
            if exc.status != 400 or exc.code != "write_failed_due_to_invalid_input":
                raise
        for tup in writes:
            try:
                await self.write(store_id, writes=[tup], model_id=model_id)
            except FgaError as exc:
                if not _already_applied(exc):
                    raise
        for tup in deletes:
            try:
                await self.write(store_id, deletes=[tup], model_id=model_id)
            except FgaError as exc:
                if not _already_applied(exc):
                    raise

    async def read(
        self,
        store_id: str,
        *,
        object: str = "",
        relation: str = "",
        subject: str = "",
        page_size: int = 100,
    ) -> list[Tuple]:
        result: list[Tuple] = []
        token = ""
        while True:
            body: dict[str, Any] = {"page_size": page_size}
            key: dict[str, str] = {}
            if object:
                key["object"] = object
            if relation:
                key["relation"] = relation
            if subject:
                key["user"] = subject
            if key:
                body["tuple_key"] = key
            if token:
                body["continuation_token"] = token
            data = await self._request("POST", f"/stores/{store_id}/read", body)
            for item in data.get("tuples", []):
                k = item.get("key", {})
                result.append(
                    Tuple(
                        object=str(k.get("object", "")),
                        relation=str(k.get("relation", "")),
                        subject=str(k.get("user", "")),
                        condition=k.get("condition"),
                    )
                )
            token = str(data.get("continuation_token") or "")
            if not token:
                return result

    # --- решения -------------------------------------------------------------

    async def check(
        self,
        store_id: str,
        item: CheckItem,
        *,
        model_id: str = "",
        consistency: Consistency = "default",
    ) -> bool:
        body: dict[str, Any] = {
            "tuple_key": {"user": item.subject, "relation": item.relation, "object": item.object}
        }
        if item.contextual:
            body["contextual_tuples"] = {"tuple_keys": [t.key() for t in item.contextual]}
        if item.context:
            body["context"] = item.context
        if model_id:
            body["authorization_model_id"] = model_id
        if consistency == "strong":
            body["consistency"] = "HIGHER_CONSISTENCY"
        data = await self._request("POST", f"/stores/{store_id}/check", body)
        return bool(data.get("allowed"))

    async def batch_check(
        self,
        store_id: str,
        items: list[CheckItem],
        *,
        model_id: str = "",
        consistency: Consistency = "default",
    ) -> list[bool]:
        if not items:
            return []
        checks = []
        for index, item in enumerate(items):
            entry: dict[str, Any] = {
                "tuple_key": {
                    "user": item.subject,
                    "relation": item.relation,
                    "object": item.object,
                },
                "correlation_id": item.correlation_id or f"c{index}",
            }
            if item.contextual:
                entry["contextual_tuples"] = {"tuple_keys": [t.key() for t in item.contextual]}
            if item.context:
                entry["context"] = item.context
            checks.append(entry)
        body: dict[str, Any] = {"checks": checks}
        if model_id:
            body["authorization_model_id"] = model_id
        if consistency == "strong":
            body["consistency"] = "HIGHER_CONSISTENCY"
        try:
            data = await self._request("POST", f"/stores/{store_id}/batch-check", body)
        except FgaError as exc:
            if exc.status not in {404, 501}:
                raise
            # Старый engine без batch-check: последовательные check.
            return [
                await self.check(store_id, item, model_id=model_id, consistency=consistency)
                for item in items
            ]
        results = data.get("result", {})
        out: list[bool] = []
        for index, item in enumerate(items):
            cid = item.correlation_id or f"c{index}"
            entry = results.get(cid, {})
            if entry.get("error"):
                raise FgaError(500, "batch_item_error", str(entry["error"]))
            out.append(bool(entry.get("allowed")))
        return out

    async def list_objects(
        self,
        store_id: str,
        *,
        subject: str,
        relation: str,
        object_type: str,
        contextual: Iterable[Tuple] = (),
        context: dict[str, Any] | None = None,
        model_id: str = "",
        consistency: Consistency = "default",
    ) -> list[str]:
        body: dict[str, Any] = {"user": subject, "relation": relation, "type": object_type}
        contextual = list(contextual)
        if contextual:
            body["contextual_tuples"] = {"tuple_keys": [t.key() for t in contextual]}
        if context:
            body["context"] = context
        if model_id:
            body["authorization_model_id"] = model_id
        if consistency == "strong":
            body["consistency"] = "HIGHER_CONSISTENCY"
        data = await self._request("POST", f"/stores/{store_id}/list-objects", body)
        return [str(o) for o in data.get("objects", [])]

    async def list_users(
        self,
        store_id: str,
        *,
        object: str,
        relation: str,
        subject_type: str = "principal",
        context: dict[str, Any] | None = None,
        model_id: str = "",
        consistency: Consistency = "default",
    ) -> list[str]:
        obj_type, _, obj_id = object.partition(":")
        body: dict[str, Any] = {
            "object": {"type": obj_type, "id": obj_id},
            "relation": relation,
            "user_filters": [{"type": subject_type}],
        }
        if context:
            body["context"] = context
        if model_id:
            body["authorization_model_id"] = model_id
        if consistency == "strong":
            body["consistency"] = "HIGHER_CONSISTENCY"
        data = await self._request("POST", f"/stores/{store_id}/list-users", body)
        users: list[str] = []
        for entry in data.get("users", []):
            obj = entry.get("object")
            if obj:
                users.append(f"{obj.get('type')}:{obj.get('id')}")
        return users


def _already_applied(exc: FgaError) -> bool:
    if exc.status != 400:
        return False
    text = exc.message.lower()
    return "already exists" in text or "does not exist" in text or "not found" in text
