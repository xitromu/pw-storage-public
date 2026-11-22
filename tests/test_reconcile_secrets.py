import contextlib
import hashlib
import io
import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from pw_storage.vault import Kdf, Row, Vault, file_hash
from tools import reconcile_secrets as review


class FakeVault:
    def __init__(self, path, rows, values):
        self.path = path
        self.source_hash = file_hash(path)
        self._rows = rows
        self._values = values
        self.reads = []

    def rows(self):
        return self._rows

    def value(self, uid):
        self.reads.append(uid)
        return self._values[uid]


def row(uid="1234abcd", key="TOKEN", projects=("DEMO_A",), group="DEMO_A", shared=False):
    return Row(uid, group, "Service", key, "Synthetic comment", projects, shared, "private-value-digest")


class ReconcileTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pw-reconcile-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.vault_path = self.root / "vault.kdbx"
        self.vault_path.write_bytes(b"synthetic encrypted snapshot")
        self.secret = "TEST-" + secrets.token_urlsafe(24)

    def source(self, project="DEMO_A", name="secrets.env", text=None):
        folder = self.root / project
        folder.mkdir(exist_ok=True)
        path = folder / name
        path.write_text(f"TOKEN={self.secret}\n" if text is None else text, encoding="utf-8", newline="")
        return review.Source(project, path)

    def vault(self, rows=None, values=None):
        return FakeVault(self.vault_path, [row()] if rows is None else rows,
                         {"1234abcd": self.secret} if values is None else values)

    def test_matching_different_and_unmatched_are_metadata_only(self):
        source = self.source(text=f"TOKEN={self.secret}\nCHANGED=TEST-new\nNEW=TEST-unmatched\n")
        vault = self.vault([row(), row("1234abce", "CHANGED")],
                           {"1234abcd": self.secret, "1234abce": "TEST-old"})
        findings = review.compare(vault, [review.read_source(source)], {})
        self.assertEqual({item.key: item.status for item in findings},
                         {"TOKEN": "same", "CHANGED": "different", "NEW": "unmatched"})
        text = review.render(findings) + repr(findings)
        for value in (self.secret, "TEST-new", "TEST-old", "TEST-unmatched", "private-value-digest",
                      hashlib.sha256(self.secret.encode()).hexdigest()):
            self.assertNotIn(value, text)
        self.assertEqual(set(vault.reads), {"1234abcd", "1234abce"})

    def test_source_snapshot_repr_excludes_contents(self):
        snapshot = review.read_source(self.source())
        self.assertNotIn(self.secret, repr(snapshot))
        self.assertNotIn("TOKEN=", repr(snapshot))

    def test_matching_uses_project_tags_not_group_or_all(self):
        vault = self.vault([row(group="COMMON")])
        self.assertEqual(review.compare(vault, [review.read_source(self.source())], {})[0].status, "same")
        vault = self.vault([row(projects=("OTHER",), shared=True)])
        self.assertEqual(review.compare(vault, [review.read_source(self.source())], {})[0].status, "unmatched")
        self.assertEqual(vault.reads, [])

    def test_duplicate_candidates_do_not_choose_by_value(self):
        vault = self.vault([row(), row("1234abce")], {"1234abcd": self.secret, "1234abce": "TEST-other"})
        finding = review.compare(vault, [review.read_source(self.source())], {})[0]
        self.assertEqual(finding.status, "ambiguous")
        self.assertEqual(finding.row_ids, ("1234abcd", "1234abce"))
        self.assertEqual(vault.reads, [])

    def test_explicit_alias_requires_existing_project_permission(self):
        source = self.source(text=f"ALIAS={self.secret}\n")
        snapshot = review.read_source(source)
        mappings = {("DEMO_A", "ALIAS"): "1234abcd"}
        self.assertEqual(review.compare(self.vault(), [snapshot], mappings)[0].status, "same")
        for vault in (self.vault([]), self.vault([row(projects=("OTHER",), shared=True)])):
            with self.subTest(rows=len(vault.rows())), self.assertRaises(review.ReviewError):
                review.compare(vault, [snapshot], mappings)
            self.assertEqual(vault.reads, [])

    def test_mapping_to_absent_source_key_is_rejected(self):
        with self.assertRaises(review.ReviewError):
            review.compare(self.vault(), [review.read_source(self.source())], {("DEMO_A", "MISSING"): "1234abcd"})

    def test_shared_sources_that_disagree_require_resolution(self):
        snapshots = [review.read_source(self.source()),
                     review.read_source(self.source("DEMO_B", text="TOKEN=TEST-conflict\n"))]
        vault = self.vault([row(projects=("DEMO_A", "DEMO_B"))])
        findings = review.compare(vault, snapshots, {})
        self.assertEqual([item.status for item in findings], ["source_conflict", "source_conflict"])
        self.assertNotIn(self.secret, review.render(findings))
        self.assertNotIn("TEST-conflict", review.render(findings))

    def test_shared_sources_that_agree_remain_separate_findings(self):
        snapshots = [review.read_source(self.source()), review.read_source(self.source("DEMO_B"))]
        vault = self.vault([row(projects=("DEMO_A", "DEMO_B"))])
        findings = review.compare(vault, snapshots, {})
        self.assertEqual([item.status for item in findings], ["same", "same"])
        self.assertEqual([item.project for item in findings], ["DEMO_A", "DEMO_B"])

    def test_empty_source_value_never_suggests_replacement(self):
        vault = self.vault()
        findings = review.compare(vault, [review.read_source(self.source(text="TOKEN=\n"))], {})
        self.assertEqual(findings[0].status, "empty")
        self.assertEqual(vault.reads, [])

    def test_literal_parser_preserves_equals_quotes_and_dollar_text(self):
        source = self.source(text='\ufeff# comment\n\nTOKEN="${UNEXPANDED}=a=b"\n')
        snapshot = review.read_source(source)
        self.assertEqual(snapshot.values, {"TOKEN": '"${UNEXPANDED}=a=b"'})

    def test_edge_whitespace_is_not_silently_removed(self):
        source = self.source(text=f"TOKEN=  {self.secret} \t\r\nSPACE=   \n")
        snapshot = review.read_source(source)
        self.assertEqual(snapshot.values["TOKEN"], f"  {self.secret} \t")
        self.assertEqual(snapshot.values["SPACE"], "   ")
        findings = review.compare(self.vault(), [snapshot], {})
        self.assertEqual(next(item for item in findings if item.key == "TOKEN").status, "different")

    def test_invalid_utf8_exception_does_not_retain_content_in_repr(self):
        source = self.source()
        source.path.write_bytes(self.secret.encode() + b"\xff")
        with self.assertRaises(review.ReviewError) as caught:
            review.read_source(source)
        self.assertNotIn(self.secret, repr(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)

    def test_retargeted_open_handle_is_rejected_before_reading_content(self):
        source = self.source()
        outside = self.root / "OTHER" / "private.env"
        with mock.patch.object(Path, "open") as opened, \
             mock.patch.object(review, "_opened_path", return_value=outside):
            stream = opened.return_value.__enter__.return_value
            with self.assertRaisesRegex(review.ReviewError, "Путь источника изменился"):
                review.read_source(source)
        stream.read.assert_not_called()

    def test_duplicate_or_malformed_lines_fail_without_content(self):
        for text in (f"TOKEN={self.secret}\nTOKEN=other\n", self.secret,
                     f"BAD NAME={self.secret}\n"):
            with self.subTest(text_length=len(text)):
                with self.assertRaises(review.ReviewError) as caught:
                    review.read_source(self.source(text=text))
                self.assertNotIn(self.secret, str(caught.exception))

    def test_sources_must_be_explicit_unique_files_inside_project(self):
        source = self.source()
        self.assertEqual(review.selected_sources([f"DEMO_A={source.path}"], self.root),
                         [review.Source(source.project, source.path.resolve())])
        for specs in ([f"OTHER={source.path}"], ["DEMO_A=secrets.env"],
                      [f"DEMO_A={source.path}"] * 2, [f"ALL={source.path}"],
                      [f"DEMO_A={source.path.parent}"], [f"DEMO_A={source.path.parent / 'missing.env'}"]):
            with self.subTest(specs=specs), self.assertRaises(review.ReviewError):
                review.selected_sources(specs, self.root)

    def test_mapping_syntax_and_duplicates_fail_closed(self):
        sources = [self.source()]
        self.assertEqual(review.selected_mappings(["DEMO_A/TOKEN=1234abcd"], sources),
                         {("DEMO_A", "TOKEN"): "1234abcd"})
        for specs in (["DEMO_A/TOKEN=bad"], ["OTHER/TOKEN=1234abcd"],
                      ["DEMO_A/TOKEN=1234abcd", "DEMO_A/TOKEN=1234abce"]):
            with self.subTest(specs=specs), self.assertRaises(review.ReviewError):
                review.selected_mappings(specs, sources)

    def test_source_change_during_comparison_refuses_report(self):
        source = self.source()
        snapshot = review.read_source(source)
        vault = self.vault()
        original = vault.value

        def changed(uid):
            source.path.write_text("TOKEN=TEST-concurrent\n", encoding="utf-8")
            return original(uid)

        vault.value = changed
        with self.assertRaisesRegex(review.ReviewError, "Источник изменился"):
            review.compare(vault, [snapshot], {})

    def test_vault_change_or_transaction_refuses_report_without_recovery(self):
        snapshots = [review.read_source(self.source())]
        vault = self.vault()
        self.vault_path.write_bytes(b"changed encrypted snapshot")
        with self.assertRaisesRegex(review.ReviewError, "Хранилище изменилось"):
            review.compare(vault, snapshots, {})
        vault = self.vault()
        transaction = self.vault_path.with_name(self.vault_path.name + ".transaction")
        transaction.write_bytes(b"untouched synthetic transaction")
        with self.assertRaises(review.ReviewError):
            review.compare(vault, snapshots, {})
        self.assertEqual(transaction.read_bytes(), b"untouched synthetic transaction")

    def test_vault_change_during_final_source_check_is_rejected(self):
        snapshots = [review.read_source(self.source())]
        vault = self.vault()
        check = review.ensure_sources_unchanged

        def changed(items):
            check(items)
            self.vault_path.write_bytes(b"new encrypted snapshot")

        with mock.patch.object(review, "ensure_sources_unchanged", side_effect=changed):
            with self.assertRaisesRegex(review.ReviewError, "Хранилище изменилось"):
                review.compare(vault, snapshots, {})

    def test_csv_escapes_formula_prefixes(self):
        text = review.render([review.Finding("-PROJECT", "=source", "TOKEN", "unmatched")])
        self.assertIn("'-PROJECT;", text)
        self.assertIn("'=source;", text)

    def run_cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = review.main(args)
        return code, out.getvalue(), err.getvalue()

    def test_inventory_does_not_open_vault_and_only_reports_names(self):
        source = self.source()
        profile = SimpleNamespace(projects_root=self.root)
        with mock.patch.dict(review.PROFILES, {"unit": profile}), \
             mock.patch.object(review.Vault, "open_readonly", create=True) as opened:
            code, out, err = self.run_cli(["inventory", "--profile", "unit", "--source", f"DEMO_A={source.path}"])
        self.assertEqual(code, 0)
        self.assertIn("TOKEN", out)
        self.assertNotIn(self.secret, out + err)
        opened.assert_not_called()

    def test_report_is_metadata_only_and_never_overwrites_existing_file(self):
        source = self.source()
        report_path = self.root / "review.csv"
        profile = SimpleNamespace(projects_root=self.root)
        args = ["inventory", "--profile", "unit", "--source", f"DEMO_A={source.path}", "--report", str(report_path)]
        with mock.patch.dict(review.PROFILES, {"unit": profile}):
            code, out, err = self.run_cli(args)
            self.assertEqual(code, 0)
            before = report_path.read_bytes()
            self.assertNotIn(self.secret, before.decode("utf-8-sig") + out + err)
            with mock.patch.object(review, "read_source") as read:
                code, out, err = self.run_cli(args)
            self.assertEqual(code, 1)
            self.assertIn("перезапись запрещена", err)
            read.assert_not_called()
        self.assertEqual(report_path.read_bytes(), before)

    def test_report_creation_race_does_not_overwrite_other_file(self):
        source = self.source()
        report_path = self.root / "review.csv"
        profile = SimpleNamespace(projects_root=self.root)
        render = review.render

        def concurrent_report(findings):
            report_path.write_bytes(b"other report")
            return render(findings)

        with mock.patch.dict(review.PROFILES, {"unit": profile}), \
             mock.patch.object(review, "render", side_effect=concurrent_report):
            code, out, err = self.run_cli(["inventory", "--profile", "unit", "--source", f"DEMO_A={source.path}",
                                           "--report", str(report_path)])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(report_path.read_bytes(), b"other report")

    def test_compare_refuses_noninteractive_password_before_any_content_read(self):
        source = self.source()
        profile = SimpleNamespace(name="unit", projects_root=self.root, vault=self.vault_path)
        with mock.patch.dict(review.PROFILES, {"unit": profile}), \
             mock.patch.object(review.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(review, "read_source") as read, \
             mock.patch.object(review.Vault, "open_readonly", create=True) as opened:
            code, out, err = self.run_cli(["compare", "--profile", "unit", "--source", f"DEMO_A={source.path}"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("видимой консоли", err)
        read.assert_not_called()
        opened.assert_not_called()

    def test_compare_cli_uses_readonly_open_and_never_prints_password(self):
        source = self.source()
        profile = SimpleNamespace(name="unit", projects_root=self.root, vault=self.vault_path)
        password = "TEST-password-" + secrets.token_urlsafe(12)
        with mock.patch.dict(review.PROFILES, {"unit": profile}), \
             mock.patch.object(review.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(review.getpass, "getpass", return_value=password), \
             mock.patch.object(review.Vault, "open_readonly", return_value=self.vault()) as opened:
            code, out, err = self.run_cli(["compare", "--profile", "unit", "--source", f"DEMO_A={source.path}"])
        self.assertEqual(code, 0)
        opened.assert_called_once_with(self.vault_path, password)
        self.assertIn("Совпадает", out)
        self.assertNotIn(password, out + err)
        self.assertNotIn(self.secret, out + err)

    def test_getpass_warning_does_not_fall_back_to_echoed_input(self):
        source = self.source()
        profile = SimpleNamespace(name="unit", projects_root=self.root, vault=self.vault_path)

        def password():
            review.warnings.warn("synthetic unsafe console", review.getpass.GetPassWarning)
            raise AssertionError("must stop before reading echoed input")

        with mock.patch.dict(review.PROFILES, {"unit": profile}), \
             mock.patch.object(review.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(review.getpass, "getpass", side_effect=lambda prompt: password()), \
             mock.patch.object(review.Vault, "open_readonly") as opened:
            code, out, err = self.run_cli(["compare", "--profile", "unit", "--source", f"DEMO_A={source.path}"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("GetPassWarning", err)
        self.assertNotIn("synthetic unsafe console", err)
        opened.assert_not_called()

    def test_unexpected_error_does_not_disclose_exception_details(self):
        source = self.source()
        profile = SimpleNamespace(projects_root=self.root)
        with mock.patch.dict(review.PROFILES, {"unit": profile}), \
             mock.patch.object(review, "read_source", side_effect=ValueError(self.secret)):
            code, out, err = self.run_cli(["inventory", "--profile", "unit", "--source", f"DEMO_A={source.path}"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertNotIn(self.secret, err)

    def test_password_and_apply_arguments_are_not_supported_or_echoed(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            review.main(["compare", "--profile", "main", "--source", "DEMO_A=unused", "--apply", "--password", self.secret])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn(self.secret, out.getvalue() + err.getvalue())


class ReadOnlyComparisonIntegrationTest(unittest.TestCase):
    def test_real_encrypted_snapshot_is_only_read(self):
        with tempfile.TemporaryDirectory(prefix="pw-reconcile-vault-") as folder:
            root = Path(folder).resolve()
            path = root / "vault.kdbx"
            password = secrets.token_urlsafe(24)
            value = "TEST-" + secrets.token_urlsafe(24)
            vault = Vault.create(path, password, Kdf(16, 1, 1))
            vault.put("DEMO_A", "Service", "TOKEN", value, "Synthetic comment")
            vault.save()
            source_path = root / "source.env"
            source_path.write_text(f"TOKEN={value}\n", encoding="utf-8")
            before = {item.name: item.read_bytes() for item in root.iterdir()}
            with mock.patch.object(Vault, "save", side_effect=AssertionError("comparison must not write")), \
                 mock.patch.object(Vault, "resume", side_effect=AssertionError("comparison must not resume")):
                snapshot = Vault.open_readonly(path, password)
                findings = review.compare(snapshot, [review.read_source(review.Source("DEMO_A", source_path))], {})
            self.assertEqual(findings[0].status, "same")
            self.assertNotIn(value, review.render(findings))
            self.assertEqual({item.name: item.read_bytes() for item in root.iterdir()}, before)


if __name__ == "__main__":
    unittest.main()
