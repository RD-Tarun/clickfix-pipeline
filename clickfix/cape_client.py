"""Thin client for CAPE's local REST API (apiv2): submit a .ps1, poll for
completion, and pull back the report + IOC summary.
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests

from config import CapeConfig

log = logging.getLogger("clickfix.cape")

_TERMINAL_STATUSES = {"reported", "failed_analysis", "failed_processing", "failed_reporting"}


class CapeError(Exception):
    pass


@dataclass
class SubmitOutcome:
    task_id: int
    raw_response: dict


class CapeClient:
    def __init__(self, cfg: CapeConfig):
        self.cfg = cfg
        self._headers = {}
        if cfg.api_token:
            self._headers["Authorization"] = f"Token {cfg.api_token}"

    def _url(self, path: str) -> str:
        return f"{self.cfg.base_url.rstrip('/')}/apiv2/{path.lstrip('/')}"

    def submit_payload(self, filename: str, content: bytes, package: str,
                       custom: str = "", machine: str = "") -> SubmitOutcome:
        """Submit one recovered payload as a file, under an explicit package.

        `package` comes from the classifier, not from config: a cmd.exe
        command line must run under `batch`, a script body under `ps1`.
        """
        files = {"file": (filename, content)}
        data = {
            "package": package,
            "route": self.cfg.route,
            "timeout": self.cfg.timeout,
            "priority": self.cfg.priority,
            "custom": custom,
        }
        machine = machine or self.cfg.machine
        if machine:
            data["machine"] = machine
        if self.cfg.tags:
            data["tags"] = self.cfg.tags
        resp = requests.post(
            self._url("tasks/create/file/"), files=files, data=data,
            headers=self._headers, timeout=60,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("error"):
            raise CapeError(f"submission rejected: {payload.get('error_value')}")
        task_ids = payload.get("data", {}).get("task_ids") or payload.get("task_ids")
        if not task_ids:
            raise CapeError(f"no task_ids in response: {payload}")
        return SubmitOutcome(task_id=task_ids[0], raw_response=payload)

    def pcap_info(self, task_id: int) -> dict:
        """Whether a PCAP exists for this task, and how big -- without
        downloading it."""
        try:
            resp = requests.get(
                self._url(f"tasks/get/pcap/{task_id}/"), headers=self._headers,
                timeout=60, stream=True,
            )
        except requests.RequestException as exc:
            return {"available": False, "error": str(exc)}
        if resp.status_code != 200:
            body = ""
            try:
                body = resp.text[:200]
            except Exception:
                pass
            resp.close()
            return {"available": False, "http_status": resp.status_code, "detail": body}
        size = 0
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > 50 * 1024 * 1024:
                break
        resp.close()
        ctype = resp.headers.get("Content-Type", "")
        return {"available": size > 0, "bytes": size, "content_type": ctype}

    def submit_ps1(self, filename: str, content: bytes, custom: str = "") -> SubmitOutcome:
        files = {"file": (filename, content)}
        data = {
            "package": self.cfg.package,
            "route": self.cfg.route,
            "timeout": self.cfg.timeout,
            "priority": self.cfg.priority,
            "custom": custom,
        }
        # Target the analysis VM by label. CAPE validates this against the
        # machinery conf and rejects unknown labels outright.
        if self.cfg.machine:
            data["machine"] = self.cfg.machine
        # Only send tags when explicitly configured: CAPE requires every
        # non-arch task tag to also be present on the machine, so a stray tag
        # leaves the task permanently unschedulable (pending forever).
        if self.cfg.tags:
            data["tags"] = self.cfg.tags
        resp = requests.post(
            self._url("tasks/create/file/"), files=files, data=data, headers=self._headers, timeout=60
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("error"):
            raise CapeError(f"submission rejected: {payload.get('error_value')}")
        task_ids = payload.get("data", {}).get("task_ids") or payload.get("task_ids")
        if not task_ids:
            raise CapeError(f"no task_ids in response: {payload}")
        return SubmitOutcome(task_id=task_ids[0], raw_response=payload)

    def list_machines(self) -> list:
        """Machine labels CAPE knows about -- used by the preflight check.

        Raises CapeError when the endpoint is administratively disabled
        ([machinelist] enabled = no in api.conf), which is the default. That
        is a soft condition: the pipeline never needs this endpoint at
        runtime, only preflight uses it to verify the configured label.
        """
        resp = requests.get(self._url("machines/list/"), headers=self._headers, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("error"):
            raise CapeError(payload.get("error_value") or "machine list unavailable")
        machines = payload.get("data") or payload.get("machines") or []
        return [m.get("name") or m.get("label") for m in machines if isinstance(m, dict)]

    def get_status(self, task_id: int) -> str:
        resp = requests.get(self._url(f"tasks/status/{task_id}/"), headers=self._headers, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        return payload.get("data") or payload.get("status") or "unknown"

    def wait_for_report(self, task_id: int) -> str:
        waited = 0
        while waited < self.cfg.max_wait:
            status = self.get_status(task_id)
            log.info("task %s status=%s (waited %ss)", task_id, status, waited)
            if status in _TERMINAL_STATUSES:
                return status
            time.sleep(self.cfg.poll_interval)
            waited += self.cfg.poll_interval
        raise CapeError(f"task {task_id} did not reach a terminal status within {self.cfg.max_wait}s")

    def get_report(self, task_id: int) -> dict:
        resp = requests.get(
            self._url(f"tasks/get/report/{task_id}/json/"), headers=self._headers, timeout=120
        )
        resp.raise_for_status()
        return resp.json()

    def get_iocs(self, task_id: int) -> dict:
        resp = requests.get(
            self._url(f"tasks/get/iocs/{task_id}/detailed/"), headers=self._headers, timeout=60
        )
        resp.raise_for_status()
        return resp.json()
