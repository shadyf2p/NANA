from __future__ import annotations

import os
import time
from pathlib import Path

from PyQt6.QtCore import QThread, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QIcon
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from workflows.A_workflow_generate_image import GenerateImageWorkflow
from workflows.A_workflow_image_to_video import ImageToVideoWorkflow
from workflows.A_workflow_sync_chactacter import CharacterSyncWorkflow
from workflows.A_workflow_text_to_video import TextToVideoWorkflow
from branding_config import OWNER_ZALO_URL, WINDOW_TITLE
from workflows.idea_to_video import idea_to_video_workflow
from .settings_manager import SettingsManager, WORKFLOWS_DIR, get_icon_path
from workflows.worker_run_workflow_grok import GrokImageToVideoWorker, GrokTextToVideoWorker

try:
    from qt_ui.status_help_view import build_status_help_view, get_status_help_file_path
except Exception:
    from status_help_view import build_status_help_view, get_status_help_file_path


def _icon(name: str) -> QIcon:
    path = get_icon_path(name)
    if path and os.path.isfile(path):
        return QIcon(path)
    return QIcon()


class _IdeaToVideoWorker(QThread):
    log_message = pyqtSignal(str)
    finished_ok = pyqtSignal(list)
    finished_error = pyqtSignal(str)

    def __init__(self, project_name: str, settings: dict, parent: QWidget | None = None):
        super().__init__(parent)
        self._project_name = str(project_name or "idea_to_video")
        self._settings = dict(settings or {})
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        try:
            result = idea_to_video_workflow(
                project_name=self._project_name,
                idea=str(self._settings.get("idea") or "").strip(),
                scene_count=int(self._settings.get("scene_count") or 1),
                style=str(self._settings.get("style") or "3d_Pixar"),
                language=str(self._settings.get("dialogue_language") or "Tiếng Việt (vi-VN)"),
                log_callback=lambda m: self.log_message.emit(str(m or "")),
                stop_check=lambda: bool(self._stop),
            )
            if not isinstance(result, dict) or not result.get("success"):
                self.finished_error.emit(str((result or {}).get("message") or "Idea to Video thất bại."))
                return
            prompts = [str((i or {}).get("prompt") or "").strip() for i in (result.get("prompts") or [])]
            self.finished_ok.emit([p for p in prompts if p])
        except Exception as exc:
            self.finished_error.emit(f"Idea to Video lỗi: {exc}")


class StatusPanel(QWidget):
    requestStop = pyqtSignal()
    runStateChanged = pyqtSignal(bool)
    titleChanged = pyqtSignal(str)
    queueJobsRequested = pyqtSignal(list)

    COL_ID = 0
    COL_MODE = 1
    COL_PROMPT = 2
    COL_STATUS = 3
    COL_OUTPUT = 4

    def __init__(self, config, parent: QWidget | None = None):
        super().__init__(parent)
        self._cfg = config
        self._running = False
        self._stopping = False
        self._worker = None
        self._idea_worker = None
        self._current_rows: list[int] = []

        self._row_counter = 0
        self._rows: dict[int, dict] = {}
        self._table_row_by_id: dict[int, int] = {}

        self._init_ui()
        self._refresh_account_info()
        self._emit_title()

    def _init_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        box = QGroupBox("Trạng thái workflow")
        box_l = QVBoxLayout(box)
        box_l.setContentsMargins(10, 10, 10, 10)
        box_l.setSpacing(8)

        header = QHBoxLayout()
        self.lbl_account = QLabel("Tài khoản: --")
        self.lbl_account.setStyleSheet("font-weight:600; color:#d7e3ff;")
        header.addWidget(self.lbl_account, 1)

        self.btn_open_output = QPushButton("Mở thư mục output")
        self.btn_open_output.setIcon(_icon("folder_icon.png"))
        self.btn_open_output.clicked.connect(self._open_output_folder)
        header.addWidget(self.btn_open_output)

        self.btn_help = QPushButton("Mở hướng dẫn")
        self.btn_help.clicked.connect(self._open_usage_guide_file)
        header.addWidget(self.btn_help)

        self.btn_zalo = QPushButton("Nhóm Zalo")
        self.btn_zalo.clicked.connect(self._open_zalo_group)
        header.addWidget(self.btn_zalo)
        box_l.addLayout(header)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Mode", "Prompt", "Trạng thái", "Output"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setColumnWidth(self.COL_ID, 56)
        self.table.setColumnWidth(self.COL_MODE, 150)
        self.table.setColumnWidth(self.COL_STATUS, 180)
        self.table.setColumnWidth(self.COL_OUTPUT, 220)
        self.table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.table)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        splitter.addWidget(self.log)
        splitter.setSizes([420, 180])
        box_l.addWidget(splitter, 1)

        try:
            box_l.addWidget(build_status_help_view(), 0)
        except Exception:
            pass

        root.addWidget(box, 1)

    def _emit_title(self) -> None:
        c = self.get_running_video_count()
        self.titleChanged.emit(f"{WINDOW_TITLE}{f' | Running: {c}' if c > 0 else ''}")

    def _next_row_id(self) -> int:
        self._row_counter += 1
        return int(self._row_counter)

    def _mode_label(self, mode_key: str) -> str:
        return {
            "text_to_video": "Text to Video",
            "grok_text_to_video": "GROK Text to Video",
            "image_to_video": "Image to Video",
            "grok_image_to_video": "GROK Image to Video",
            "generate_image_prompt": "Tạo ảnh từ prompt",
            "generate_image_reference": "Tạo ảnh tham chiếu",
            "character_sync": "Đồng bộ nhân vật",
        }.get(str(mode_key or ""), str(mode_key or "workflow"))

    def _add_table_row(self, item: dict) -> None:
        row_id = int(item["row_id"])
        row = self.table.rowCount()
        self.table.insertRow(row)
        self._table_row_by_id[row_id] = row
        self.table.setItem(row, self.COL_ID, QTableWidgetItem(str(row_id)))
        self.table.setItem(row, self.COL_MODE, QTableWidgetItem(self._mode_label(item.get("mode_key", ""))))
        self.table.setItem(row, self.COL_PROMPT, QTableWidgetItem(str(item.get("prompt", ""))))
        self.table.setItem(row, self.COL_STATUS, QTableWidgetItem("QUEUED"))
        self.table.setItem(row, self.COL_OUTPUT, QTableWidgetItem(""))

    def _set_row_text(self, row_id: int, col: int, text: str) -> None:
        r = self._table_row_by_id.get(int(row_id), -1)
        if r < 0:
            return
        it = self.table.item(r, col)
        if it is None:
            it = QTableWidgetItem()
            self.table.setItem(r, col, it)
        it.setText(str(text or ""))

    def _set_row_status(self, row_id: int, status: str) -> None:
        self._set_row_text(row_id, self.COL_STATUS, status)
        if row_id in self._rows:
            self._rows[row_id]["status"] = str(status or "")
        self._emit_title()

    def _set_running(self, running: bool) -> None:
        self._running = bool(running)
        self.runStateChanged.emit(self._running)
        self._emit_title()

    def _project_name(self, mode_key: str) -> str:
        return f"{mode_key}_{int(time.time())}"

    def _common_project_data(self, mode_key: str) -> dict:
        return {
            "project_name": self._project_name(mode_key),
            "_use_project_prompts": True,
            "_worker_controls_lifecycle": True,
            "output_count": int(getattr(self._cfg, "output_count", 1) or 1),
            "aspect_ratio": str(getattr(self._cfg, "video_aspect_ratio", "9:16") or "9:16"),
            "veo_model": str(getattr(self._cfg, "veo_model", "Veo 3.1 - Fast") or "Veo 3.1 - Fast"),
            "video_output_dir": str(getattr(self._cfg, "video_output_dir", "") or "").strip(),
        }

    def _entries_for_rows(self, mode_key: str, rows: list[int]) -> list[dict]:
        out = []
        for rid in rows or []:
            entry = self._rows.get(int(rid))
            if entry and str(entry.get("mode_key")) == str(mode_key):
                out.append(entry)
        return out

    def _bind_worker(self, worker) -> None:
        self._worker = worker
        if hasattr(worker, "log_message"):
            worker.log_message.connect(self.append_run_log)
        if hasattr(worker, "video_updated"):
            worker.video_updated.connect(self._on_worker_video_updated)
        if hasattr(worker, "status_updated"):
            worker.status_updated.connect(self._on_worker_status_updated)
        if hasattr(worker, "automation_complete"):
            worker.automation_complete.connect(self._on_worker_completed)

    def _start_by_mode(self, mode_key: str, entries: list[dict]) -> bool:
        if mode_key == "text_to_video":
            prompts = [{"id": str(e["row_id"]), "description": str(e.get("prompt", ""))} for e in entries]
            pdata = self._common_project_data(mode_key)
            pdata["prompts"] = {"text_to_video": prompts}
            w = TextToVideoWorkflow(project_name=pdata["project_name"], project_data=pdata, parent=self)
            self._bind_worker(w)
            w.start()
            return True

        if mode_key == "image_to_video":
            items = []
            for e in entries:
                d = dict(e.get("data") or {})
                d["id"] = str(e["row_id"])
                d["description"] = str(e.get("prompt", ""))
                items.append(d)
            image_mode = "start_end" if any(str((i or {}).get("_image_mode")) == "start_end" for i in items) else "single"
            bucket = "image_to_video_start_end" if image_mode == "start_end" else "image_to_video"
            pdata = self._common_project_data(mode_key)
            pdata["i2v_mode"] = image_mode
            pdata["prompts"] = {bucket: items}
            w = ImageToVideoWorkflow(project_name=pdata["project_name"], project_data=pdata, parent=self)
            self._bind_worker(w)
            w.start()
            return True

        if mode_key in {"generate_image_prompt", "generate_image_reference"}:
            items = [{"id": str(e["row_id"]), "description": str(e.get("prompt", ""))} for e in entries]
            pdata = self._common_project_data(mode_key)
            pdata["prompts"] = {"text_to_video": items}
            w = GenerateImageWorkflow(project_name=pdata["project_name"], project_data=pdata, parent=self)
            self._bind_worker(w)
            w.start()
            return True

        if mode_key == "character_sync":
            prompts = [{"id": str(e["row_id"]), "description": str(e.get("prompt", ""))} for e in entries]
            characters = list((entries[0].get("extra") or {}).get("characters") or []) if entries else []
            pdata = self._common_project_data(mode_key)
            pdata["prompts"] = {"character_sync": prompts}
            pdata["characters"] = characters
            w = CharacterSyncWorkflow(project_name=pdata["project_name"], project_data=pdata, parent=self)
            self._bind_worker(w)
            w.start()
            return True

        if mode_key == "grok_text_to_video":
            w = GrokTextToVideoWorker(
                prompts=[str(e.get("prompt", "")) for e in entries],
                prompt_ids=[str(e["row_id"]) for e in entries],
                aspect_ratio=str(getattr(self._cfg, "video_aspect_ratio", "9:16") or "9:16"),
                video_length_seconds=int(getattr(self._cfg, "grok_video_length_seconds", 6) or 6),
                resolution_name=str(getattr(self._cfg, "grok_video_resolution", "480p") or "480p"),
                output_dir=str(getattr(self._cfg, "video_output_dir", "") or ""),
                max_concurrency=max(1, int(getattr(self._cfg, "grok_multi_video", 1) or 1)),
                offscreen_chrome=bool(getattr(self._cfg, "offscreen_chrome", True)),
                parent=self,
            )
            self._bind_worker(w)
            w.start()
            return True

        if mode_key == "grok_image_to_video":
            w = GrokImageToVideoWorker(
                items=[dict(e.get("data") or {}) for e in entries],
                prompt_ids=[str(e["row_id"]) for e in entries],
                aspect_ratio=str(getattr(self._cfg, "video_aspect_ratio", "9:16") or "9:16"),
                video_length_seconds=int(getattr(self._cfg, "grok_video_length_seconds", 6) or 6),
                resolution_name=str(getattr(self._cfg, "grok_video_resolution", "480p") or "480p"),
                output_dir=str(getattr(self._cfg, "video_output_dir", "") or ""),
                max_concurrency=max(1, int(getattr(self._cfg, "grok_multi_video", 1) or 1)),
                offscreen_chrome=bool(getattr(self._cfg, "offscreen_chrome", True)),
                parent=self,
            )
            self._bind_worker(w)
            w.start()
            return True

        return False

    def _enqueue(self, mode_key: str, prompts: list[str], rows_data: list[dict] | None = None, extra: dict | None = None) -> dict:
        rows = []
        rows_data = rows_data or [{} for _ in prompts]
        for idx, prompt in enumerate(prompts):
            txt = str(prompt or "").strip()
            if not txt:
                continue
            row_id = self._next_row_id()
            item = {
                "row_id": row_id,
                "mode_key": str(mode_key),
                "prompt": txt,
                "data": dict(rows_data[idx] if idx < len(rows_data) else {}),
                "extra": dict(extra or {}),
                "status": "QUEUED",
            }
            self._rows[row_id] = item
            rows.append(row_id)
            self._add_table_row(item)
        return {"mode_key": str(mode_key), "rows": rows, "label": self._mode_label(mode_key)}

    def enqueue_text_to_video(self, prompts: list[str]) -> dict:
        return self._enqueue("text_to_video", [str(p or "") for p in prompts or []])

    def enqueue_grok_text_to_video(self, prompts: list[str]) -> dict:
        return self._enqueue("grok_text_to_video", [str(p or "") for p in prompts or []])

    def enqueue_image_to_video(self, items: list[dict], mode: str = "single") -> dict:
        prompts, rows_data = [], []
        for i, it in enumerate(items or [], start=1):
            prompt = str((it or {}).get("prompt") or (it or {}).get("description") or "").strip() or f"Prompt {i}"
            d = dict(it or {})
            d["_image_mode"] = "start_end" if str(mode or "").strip() == "start_end" else "single"
            prompts.append(prompt)
            rows_data.append(d)
        return self._enqueue("image_to_video", prompts, rows_data=rows_data)

    def enqueue_grok_image_to_video(self, items: list[dict]) -> dict:
        prompts, rows_data = [], []
        for i, it in enumerate(items or [], start=1):
            prompt = str((it or {}).get("prompt") or (it or {}).get("description") or "").strip() or f"GROK image job {i}"
            prompts.append(prompt)
            rows_data.append(dict(it or {}))
        return self._enqueue("grok_image_to_video", prompts, rows_data=rows_data)

    def enqueue_generate_image_from_prompts(self, items: list[dict]) -> dict:
        prompts = [str((it or {}).get("description") or (it or {}).get("prompt") or "").strip() for it in items or []]
        return self._enqueue("generate_image_prompt", prompts)

    def enqueue_generate_image_from_references(self, prompts: list[str], characters: list[dict]) -> dict:
        return self._enqueue("generate_image_reference", [str(p or "") for p in prompts or []], extra={"characters": characters or []})

    def enqueue_character_sync(self, prompts: list[str], characters: list[dict]) -> dict:
        return self._enqueue("character_sync", [str(p or "") for p in prompts or []], extra={"characters": characters or []})

    def start_queued_job(self, mode_key: str, rows: list[int]) -> bool:
        if self.isRunning():
            self.append_run_log("⚠️ Đang có workflow chạy, chưa thể start job mới.")
            return False
        entries = self._entries_for_rows(mode_key, rows)
        if not entries:
            return False
        if not self._start_by_mode(str(mode_key), entries):
            self.append_run_log(f"❌ Không thể khởi động mode: {mode_key}")
            return False
        self._current_rows = [int(e["row_id"]) for e in entries]
        for e in entries:
            self._set_row_status(int(e["row_id"]), "ACTIVE")
        self._stopping = False
        self._set_running(True)
        return True

    def start_idea_to_video(self, idea_settings: dict) -> None:
        if self.isRunning():
            self.append_run_log("⚠️ Đang chạy workflow, chưa thể chạy Idea to Video.")
            return
        settings = dict(idea_settings or {})
        idea = str(settings.get("idea") or "").strip()
        if not idea:
            raise ValueError("Thiếu nội dung ý tưởng.")
        self._idea_worker = _IdeaToVideoWorker(f"idea_{int(time.time())}", settings, self)
        self._idea_worker.log_message.connect(self.append_run_log)
        self._idea_worker.finished_ok.connect(self._on_idea_finished_ok)
        self._idea_worker.finished_error.connect(self._on_idea_finished_error)
        self._set_running(True)
        self._idea_worker.start()

    def _on_idea_finished_ok(self, prompts: list) -> None:
        self._idea_worker = None
        self._set_running(False)
        if not prompts:
            self.append_run_log("⚠️ Idea to Video không tạo được prompt.")
            return
        payload = self.enqueue_text_to_video([str(p or "") for p in prompts])
        if payload.get("rows"):
            self.queueJobsRequested.emit([payload])
            self.append_run_log(f"✅ Idea to Video tạo {len(payload['rows'])} prompt và đã đưa vào hàng chờ.")

    def _on_idea_finished_error(self, message: str) -> None:
        self._idea_worker = None
        self._set_running(False)
        self.append_run_log(f"❌ {message}")

    def _on_worker_status_updated(self, payload: dict) -> None:
        prompt_id = str((payload or {}).get("prompt_id") or "").strip()
        if not prompt_id:
            return
        try:
            row_id = int(prompt_id)
        except Exception:
            return
        if "progress" in payload:
            self._set_row_status(row_id, f"ACTIVE ({int(payload.get('progress') or 0)}%)")
        elif payload.get("status_text"):
            self._set_row_status(row_id, f"ACTIVE - {str(payload.get('status_text') or '').strip()}")

    def _on_worker_video_updated(self, payload: dict) -> None:
        data = dict(payload or {})
        prompt_id = str(data.get("_prompt_id") or "").strip()
        if not prompt_id:
            idx = str(data.get("prompt_idx") or "").strip()
            if idx and "_" in idx:
                prompt_id = idx.split("_", 1)[0]
        if not prompt_id:
            return
        try:
            row_id = int(prompt_id)
        except Exception:
            return
        status = str(data.get("status") or "").strip().upper() or "ACTIVE"
        if status in {"SUCCESSFUL", "DONE", "COMPLETED"}:
            status = "SUCCESSFUL"
        elif status in {"FAILED", "ERROR"}:
            status = "FAILED"
        elif status == "DOWNLOADING":
            status = "DOWNLOADING"
        else:
            status = "ACTIVE"
        self._set_row_status(row_id, status)
        output = str(data.get("video_path") or data.get("image_path") or "").strip()
        if output:
            self._set_row_text(row_id, self.COL_OUTPUT, output)

    def _on_worker_completed(self) -> None:
        for row_id in list(self._current_rows):
            current = str(self._rows.get(row_id, {}).get("status") or "")
            if "ACTIVE" in current or current == "DOWNLOADING":
                self._set_row_status(row_id, "SUCCESSFUL")
        self._current_rows = []
        self._worker = None
        self._stopping = False
        self._set_running(False)

    def _refresh_account_info(self) -> None:
        try:
            cfg = SettingsManager.load_config()
            account = (cfg or {}).get("account1", {})
            raw_type = str(account.get("TYPE_ACCOUNT") or account.get("type_account") or "").strip().upper()
            user = str(account.get("USER") or account.get("user") or "").strip() or "--"
            self.lbl_account.setText(f"Tài khoản: {user} | Loại: {raw_type or 'NORMAL'}")
        except Exception:
            self.lbl_account.setText("Tài khoản: --")

    def _open_output_folder(self) -> None:
        path = str(getattr(self._cfg, "video_output_dir", "") or "").strip()
        if not path:
            path = str((WORKFLOWS_DIR / "downloads").resolve())
        try:
            os.makedirs(path, exist_ok=True)
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        except Exception:
            pass

    def _open_zalo_group(self) -> None:
        try:
            QDesktopServices.openUrl(QUrl(OWNER_ZALO_URL))
        except Exception:
            pass

    def _open_usage_guide_file(self) -> None:
        try:
            p = get_status_help_file_path()
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(p).resolve())))
        except Exception as exc:
            QMessageBox.warning(self, "Không mở được file", str(exc))

    def append_run_log(self, message: str) -> None:
        txt = str(message or "").strip()
        if txt:
            self.log.appendPlainText(f"[{time.strftime('%H:%M:%S')}] {txt}")

    def isRunning(self) -> bool:
        return bool(self._running)

    def get_running_video_count(self) -> int:
        c = 0
        for row_id in self._current_rows:
            status = str(self._rows.get(int(row_id), {}).get("status") or "").upper()
            if any(k in status for k in ("ACTIVE", "DOWNLOADING", "PENDING", "QUEUED")):
                c += 1
        return c

    def get_auto_retry_rows_for_worker(self, mode_key: str, rows: list[int], retry_round: int) -> list[int]:
        _ = mode_key
        _ = rows
        _ = retry_round
        return []

    def stop(self) -> None:
        self.requestStop.emit()
        self._stopping = True
        if self._idea_worker is not None:
            try:
                self._idea_worker.stop()
            except Exception:
                pass
        if self._worker is not None:
            if hasattr(self._worker, "stop"):
                try:
                    self._worker.stop()
                except Exception:
                    pass
            elif hasattr(self._worker, "requestInterruption"):
                try:
                    self._worker.requestInterruption()
                except Exception:
                    pass

    def shutdown(self, timeout_ms: int = 2000) -> None:
        self.stop()
        deadline = time.time() + max(0.1, float(timeout_ms or 0) / 1000.0)
        while self.isRunning() and time.time() < deadline:
            time.sleep(0.02)
