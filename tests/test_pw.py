"""Команда pw.py list: номера и комментарии строк для запроса; с доступом — ещё сервис и ключ одобренных."""

import base64
import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pw  # noqa: E402
from pw_storage.client import BrokerUnavailable, NeedsAccess, PwClient, TokenConflict  # noqa: E402

PREVIEW = {"project": "DEMO_A", "state": "fresh", "unnamed": 0,
           "own": [{"id": "a0000001", "comment": "Логин Такси", "all": False}],
           "common": [{"id": "a0000002", "comment": "Общий ключ погоды", "all": True}]}


class FakeClient:
    def __init__(self, rows=None, error=None, preview=PREVIEW):
        self._rows, self._error, self._preview = rows, error, preview

    def rows(self):
        if self._error:
            raise self._error
        return self._rows

    def preview(self):
        return self._preview


def output(client):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        pw.print_list(client)
    return out.getvalue()


class ListTest(unittest.TestCase):
    def test_without_access_prints_ids_and_comments(self):
        text = output(FakeClient(error=NeedsAccess("нет доступа")))
        self.assertIn("Доступа нет", text)
        self.assertIn("a0000001  Логин Такси", text)
        self.assertIn("Из ALL (одобрение добавит DEMO_A в список записи):\n  a0000002  Общий ключ погоды", text)
        self.assertIn('pw.py open --why "зачем"', text)

    def test_without_broker_prints_comments(self):
        self.assertIn("a0000001  Логин Такси", output(FakeClient(error=BrokerUnavailable("не запущен"))))

    def test_with_access_prints_granted_and_the_rest(self):
        rows = [{"id": "a0000001", "service": "Такси", "key": "login", "comment": "Логин Такси", "all": False}]
        text = output(FakeClient(rows=rows))
        self.assertIn("Одобрено всем сессиям проекта:", text)
        self.assertIn("a0000001  Такси / login — Логин Такси (есть доступ)", text)
        rest = text.split("Можно запросить ещё:")[1]
        self.assertNotIn("a0000001", rest)
        self.assertIn("a0000002  Общий ключ погоды", rest)

    def test_empty_group_says_so(self):
        text = output(FakeClient(error=NeedsAccess("нет"), preview={**PREVIEW, "common": []}))
        self.assertIn("нет строк", text)

    def test_unnamed_rows_are_counted(self):
        text = output(FakeClient(error=NeedsAccess("нет"), preview={**PREVIEW, "unnamed": 2}))
        self.assertIn("Строк без комментария: 2", text)

    def test_stale_is_marked(self):
        text = output(FakeClient(error=NeedsAccess("нет доступа"), preview={**PREVIEW, "state": "stale"}))
        self.assertIn("устарел", text)
        self.assertIn("Логин Такси", text)

    def test_missing_says_how_to_rebuild(self):
        text = output(FakeClient(error=NeedsAccess("нет доступа"), preview={**PREVIEW, "state": "missing", "own": []}))
        self.assertIn("Перечня строк нет", text)
        self.assertIn("без номеров", text)


class OpenArgsTest(unittest.TestCase):
    """Проверки разбора до обращения к посреднику: отдельный процесс, посредник не запускается."""

    def run_main(self, *args):
        run = subprocess.run([sys.executable, str(Path(pw.__file__)), *args, "--profile", "test"],
                             capture_output=True, text=True, encoding="utf-8", timeout=60)
        return run.returncode, run.stderr

    def test_open_needs_why(self):
        code, err = self.run_main("open", "a0000001")
        self.assertEqual(code, 2)
        self.assertIn("--why", err)

    def test_rows_only_for_open(self):
        code, err = self.run_main("status", "a0000001")
        self.assertEqual(code, 2)

    def test_rows_after_options_are_accepted(self):
        # Раньше argparse брал номера только до --why: задокументированный вызов падал с unrecognized arguments.
        # Пустое --why останавливает разбор до обращения к посреднику.
        code, err = self.run_main("open", "--why", "   ", "a0000001")
        self.assertEqual(code, 2)
        self.assertNotIn("unrecognized arguments", err)
        self.assertIn("--why", err)

    def test_rows_after_options_are_rejected_for_other_commands(self):
        code, err = self.run_main("status", "--why", "x", "a0000001")
        self.assertEqual(code, 2)
        self.assertNotIn("unrecognized arguments", err)
        self.assertIn("номера строк нужны только для open", err)


class ClientOperationsTest(unittest.TestCase):
    def test_attachment_decodes_bytes_without_printing_contents(self):
        client = PwClient()
        data = b"TEST-jks\x00\xff\x80\n"
        encoded = base64.b64encode(data).decode("ascii")
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(client, "_call", return_value={"ok": True, "id": "a1", "data": encoded}) as call:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(client.get_attachment("Android", "storePassword", "release.jks"), data)
        call.assert_called_once_with("get_attachment", service="Android", key="storePassword", name="release.jks")
        self.assertEqual(output.getvalue(), "")
        self.assertIn("release.jks", errors.getvalue())
        self.assertNotIn("TEST-jks", errors.getvalue())
        self.assertNotIn(encoded, errors.getvalue())

    def test_save_token_sends_expected_and_returns_commit_warnings(self):
        client = PwClient()
        reply = {"ok": True, "id": "a1", "warnings": ["Перечень не обновлён"]}
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(client, "_call", return_value=reply) as call:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(client.save_token("ZONT", "token", "TEST-new-token", expected="TEST-old-token"), reply)
        call.assert_called_once_with("save_token", service="ZONT", key="token", value="TEST-new-token",
                                     expected="TEST-old-token")
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("TEST-new-token", errors.getvalue())
        self.assertNotIn("TEST-old-token", errors.getvalue())

    def test_attachment_survives_unavailable_diagnostic_stream(self):
        client = PwClient()
        data = b"TEST-jks\x00\xff\x80\n"
        encoded = base64.b64encode(data).decode("ascii")
        for mode in ("ascii", "closed", "broken"):
            with self.subTest(mode=mode):
                stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
                if mode == "closed":
                    stream.close()
                write = mock.Mock(wraps=stream.write, side_effect=BrokenPipeError() if mode == "broken" else None)
                try:
                    with mock.patch.object(client, "_call", return_value={"ok": True, "id": "a1", "data": encoded}), \
                         mock.patch.object(stream, "write", write), contextlib.redirect_stderr(stream):
                        self.assertEqual(client.get_attachment("Андроид", "password", "release.jks"), data)
                    self.assertTrue(write.called)
                    for call in write.call_args_list:
                        self.assertNotIn("TEST-jks", call.args[0])
                        self.assertNotIn(encoded, call.args[0])
                finally:
                    stream.close()

    def test_token_success_survives_unavailable_diagnostic_stream(self):
        client = PwClient()
        for mode in ("ascii", "closed", "broken"):
            with self.subTest(mode=mode):
                stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
                if mode == "closed":
                    stream.close()
                write = mock.Mock(wraps=stream.write, side_effect=BrokenPipeError() if mode == "broken" else None)
                reply = {"ok": True, "id": "a1", "warnings": ["Перечень не обновлён"]}
                try:
                    with mock.patch.object(client, "_call", return_value=reply) as call, \
                         mock.patch.object(stream, "write", write), contextlib.redirect_stderr(stream):
                        answer = client.save_token("Такси", "token", "TEST-new-token", expected="TEST-old-token")
                    self.assertIs(answer, reply)
                    self.assertTrue(answer["ok"])
                    self.assertEqual(len(answer["warnings"]), 2)
                    self.assertIn("диагностический вывод", answer["warnings"][-1])
                    call.assert_called_once_with("save_token", service="Такси", key="token",
                                                 value="TEST-new-token", expected="TEST-old-token")
                    for call in write.call_args_list:
                        self.assertNotIn("TEST-new-token", call.args[0])
                        self.assertNotIn("TEST-old-token", call.args[0])
                    self.assertNotIn("TEST-new-token", json.dumps(answer))
                    self.assertNotIn("TEST-old-token", json.dumps(answer))
                finally:
                    stream.close()

    def test_save_token_requires_expected_before_contacting_broker(self):
        client = PwClient()
        with mock.patch.object(client, "_call") as call, self.assertRaises(TypeError):
            client.save_token("ZONT", "token", "TEST-new-token")
        call.assert_not_called()

    def test_token_conflict_has_a_distinct_exception(self):
        client = PwClient()
        conn = mock.MagicMock()
        conn.recv_bytes.return_value = json.dumps({"ok": False, "error": "token_conflict",
                                                   "message": "Токен уже изменился"}).encode("utf-8")
        with mock.patch.object(client, "_connect", return_value=conn), self.assertRaises(TokenConflict):
            client.save_token("ZONT", "token", "TEST-new-token", expected="TEST-old-token")
        request = json.loads(conn.send_bytes.call_args.args[0].decode("utf-8"))
        self.assertEqual(request["op"], "save_token")
        self.assertEqual(request["expected"], "TEST-old-token")


if __name__ == "__main__":
    unittest.main()
