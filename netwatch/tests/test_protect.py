import pytest

from netwatch.protect import (
    apply_permanent_neighbor,
    delete_permanent_neighbor,
    linux_lock_command,
    linux_unlock_command,
)


def test_rejects_bad_input_without_running_a_command(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("command should not run")

    monkeypatch.setattr("netwatch.protect.subprocess.run", boom)
    with pytest.raises(ValueError):
        apply_permanent_neighbor("not-an-ip", "aa:bb:cc:dd:ee:ff", "eth0")
    with pytest.raises(ValueError):
        apply_permanent_neighbor("192.168.1.1", "nope", "eth0")
    with pytest.raises(ValueError):
        apply_permanent_neighbor("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0;rm")
    with pytest.raises(ValueError):
        apply_permanent_neighbor("127.0.0.1", "aa:bb:cc:dd:ee:ff", "eth0")


def test_linux_lock_uses_argument_list_without_shell(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["shell"] = kwargs.get("shell", False)

        class Result:
            returncode = 0
            stderr = b""
            stdout = b""

        return Result()

    monkeypatch.setattr("netwatch.protect._linux_tool", lambda: ("ip", "/sbin/ip"))
    monkeypatch.setattr("netwatch.protect.subprocess.run", fake_run)
    result = apply_permanent_neighbor("192.168.1.1", "AA-BB-CC-DD-EE-FF", "eth0")
    assert result.applied is True
    assert seen["shell"] is False
    assert seen["cmd"] == linux_lock_command(
        "ip", "/sbin/ip", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0"
    )
    assert "rm" not in seen["cmd"]


def test_missing_tool_does_not_run_and_shows_a_command(monkeypatch):
    monkeypatch.setattr("netwatch.protect._linux_tool", lambda: None)

    def boom(*_args, **_kwargs):
        raise AssertionError("command should not run")

    monkeypatch.setattr("netwatch.protect.subprocess.run", boom)
    result = apply_permanent_neighbor("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")
    assert result.applied is False
    assert result.reason == "unsupported"
    assert "ip neigh replace" in result.command
    assert "192.168.1.1" in result.command


def test_unlock_command_targets_only_that_neighbor(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd

        class Result:
            returncode = 1
            stderr = b"Operation not permitted"
            stdout = b""

        return Result()

    monkeypatch.setattr("netwatch.protect._linux_tool", lambda: ("ip", "/sbin/ip"))
    monkeypatch.setattr("netwatch.protect.subprocess.run", fake_run)
    result = delete_permanent_neighbor("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")
    assert result.applied is False
    assert seen["cmd"] == linux_unlock_command("ip", "/sbin/ip", "192.168.1.1", "eth0")
    assert "not permitted" in result.message
