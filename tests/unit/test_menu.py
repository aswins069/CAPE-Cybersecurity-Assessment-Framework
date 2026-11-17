"""Unit tests for cli/menu.py — the interactive guided menu.

These tests focus on what's actually unit-testable about a menu built
on console input(): the logic that resolves Typer parameter defaults
and calls command functions correctly, NOT the raw interactive prompts
themselves (those are covered by manual/scripted-stdin verification).

The critical regression these guard against: calling a Typer command
function directly (bypassing app()'s own argument parsing) leaves any
parameter the caller didn't explicitly supply holding a raw
typer.models.OptionInfo/ArgumentInfo object instead of its real default
value. If that object reaches engine code (e.g. a SQL query), it fails
in confusing ways. _call_command must resolve every default correctly.
"""
from __future__ import annotations

import typer

from cape.cli.menu import _call_command, _resolve_default


class TestResolveDefault:
    """Tests for _resolve_default - the core fix for direct Typer calls."""

    def test_resolves_option_with_simple_default(self) -> None:
        """A typer.Option(0.0, ...) parameter must resolve to 0.0, not the OptionInfo object."""
        import inspect

        def fn(min_score: float = typer.Option(0.0, "--min-score")) -> None:
            pass

        sig = inspect.signature(fn)
        resolved = _resolve_default(sig.parameters["min_score"])
        assert resolved == 0.0
        assert not isinstance(resolved, type(sig.parameters["min_score"].default))

    def test_resolves_option_with_none_default(self) -> None:
        """A typer.Option(None, ...) parameter must resolve to None."""
        import inspect

        def fn(scope: object = typer.Option(None, "--scope")) -> None:
            pass

        sig = inspect.signature(fn)
        resolved = _resolve_default(sig.parameters["scope"])
        assert resolved is None

    def test_resolves_option_with_string_default(self) -> None:
        """A typer.Option('rich', ...) parameter must resolve to the string 'rich'."""
        import inspect

        def fn(fmt: str = typer.Option("rich", "--format")) -> None:
            pass

        sig = inspect.signature(fn)
        resolved = _resolve_default(sig.parameters["fmt"])
        assert resolved == "rich"

    def test_resolves_option_with_false_default(self) -> None:
        """A typer.Option(False, ...) boolean flag must resolve to False."""
        import inspect

        def fn(deep: bool = typer.Option(False, "--deep")) -> None:
            pass

        sig = inspect.signature(fn)
        resolved = _resolve_default(sig.parameters["deep"])
        assert resolved is False

    def test_required_argument_resolves_to_none_safe_default(self) -> None:
        """A required typer.Argument(...) (Ellipsis default) must not crash the
        resolver - it resolves to Ellipsis, since callers always supply
        required arguments explicitly and never rely on this path for them."""
        import inspect

        def fn(target: str = typer.Argument(...)) -> None:
            pass

        sig = inspect.signature(fn)
        resolved = _resolve_default(sig.parameters["target"])
        assert resolved is ...

    def test_plain_python_default_passes_through_unchanged(self) -> None:
        """A parameter with an ordinary Python default (no typer wrapper)
        must be returned as-is."""
        import inspect

        def fn(x: int = 5) -> None:
            pass

        sig = inspect.signature(fn)
        resolved = _resolve_default(sig.parameters["x"])
        assert resolved == 5


class TestCallCommand:
    """Tests for _call_command - calling Typer functions directly from the menu."""

    def test_fills_in_unsupplied_parameters_with_real_defaults(self) -> None:
        """Regression test for the original bug: calling a function while
        omitting most of its Typer-decorated parameters must not leave
        OptionInfo objects sitting in the function's actual arguments."""
        received = {}

        def fake_command(
            target: str = typer.Argument(...),
            min_score: float = typer.Option(0.0, "--min-score"),
            fmt: str = typer.Option("rich", "--format"),
            deep: bool = typer.Option(False, "--deep"),
        ) -> None:
            received["min_score"] = min_score
            received["fmt"] = fmt
            received["deep"] = deep

        # Only 'target' supplied, exactly like a partial menu call.
        ok = _call_command(fake_command, target="10.0.0.1")

        assert ok is True
        assert received["min_score"] == 0.0
        assert received["fmt"] == "rich"
        assert received["deep"] is False

    def test_explicit_kwargs_override_resolved_defaults(self) -> None:
        """Parameters the menu DOES pass explicitly must win over the
        resolved default, not be silently overwritten."""
        received = {}

        def fake_command(
            target: str = typer.Argument(...),
            deep: bool = typer.Option(False, "--deep"),
        ) -> None:
            received["deep"] = deep

        _call_command(fake_command, target="10.0.0.1", deep=True)
        assert received["deep"] is True

    def test_typer_exit_zero_is_treated_as_success(self) -> None:
        """A command calling typer.Exit(0) (e.g. 'nothing to do') must not
        be treated as a crash by the menu."""
        def fake_command() -> None:
            raise typer.Exit(0)

        ok = _call_command(fake_command)
        assert ok is True

    def test_typer_exit_nonzero_is_treated_as_failure(self) -> None:
        """A command calling typer.Exit(1) (e.g. an actual error) must be
        reported as not-ok, so the menu can decide not to chain a follow-up
        action (like offering to view results after a failed scan)."""
        def fake_command() -> None:
            raise typer.Exit(1)

        ok = _call_command(fake_command)
        assert ok is False

    def test_unexpected_exception_does_not_crash_the_menu(self) -> None:
        """Any other exception from a command function must be caught and
        reported, never propagate up and kill the whole menu process."""
        def fake_command() -> None:
            raise RuntimeError("boom")

        ok = _call_command(fake_command)
        assert ok is False


class TestAttackNeedsNoAuthorizationSetup:
    """The scope-file/acknowledgment/expiry authorization system has been
    removed. Calling the real 'attack' command function (as the menu
    does) must not require any scope file or prompt - it should get as
    far as looking for findings on the target and fail closed *there*
    (no findings for a target that's never been scanned), not on any
    authorization step."""

    def test_attack_fails_closed_on_missing_findings_not_authorization(self, tmp_path, monkeypatch) -> None:
        import cape.core.config as config_module
        config_module._config_instance = None
        monkeypatch.setenv("CAPE_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
        monkeypatch.setenv("CAPE_DB_URL", f"sqlite:///{tmp_path / 'test.db'}")

        from cape.cli.commands.attack import attack as attack_fn

        # No scope file, no --force, no --skip-ack needed anymore - the
        # command runs straight through to "no findings for this target"
        # (a clean exit, not an authorization failure) since it's never
        # been scanned.
        ok = _call_command(attack_fn, target="203.0.113.99")
        assert ok is True

        config_module._config_instance = None
