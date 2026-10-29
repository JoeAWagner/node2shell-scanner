from n2scan.checks.base import Status
from n2scan.ssh import SSHConfig, build_ssh_argv, classify_node_output, _NO_NODE


def test_build_argv_batchmode_and_dest():
    cfg = SSHConfig(user="secops", port=2222, identity="/k", connect_timeout=5)
    argv = build_ssh_argv("h.sbu.edu", cfg)
    assert argv[0] == "ssh"
    assert "BatchMode=yes" in argv
    assert "ConnectTimeout=5" in argv
    assert "-p" in argv and "2222" in argv
    assert "-i" in argv and "/k" in argv
    assert "secops@h.sbu.edu" in argv
    # remote command is the last arg and reads the node version
    assert "node --version" in argv[-1]


def test_build_argv_no_login_shell():
    cfg = SSHConfig(login_shell=False, batch_mode=False)
    argv = build_ssh_argv("h", cfg)
    assert "BatchMode=yes" not in argv
    assert not argv[-1].startswith("sh -lc")


def test_classify_vulnerable():
    f = classify_node_output("h", 0, "v24.22.0\n", "")
    assert f.status == Status.VULNERABLE
    assert f.detail["node_version"] == "24.22.0"


def test_classify_patched():
    f = classify_node_output("h", 0, "v24.22.1\n", "")
    assert f.status == Status.NOT_VULNERABLE


def test_classify_no_node():
    f = classify_node_output("h", 0, _NO_NODE + "\n", "")
    assert f.status == Status.INCONCLUSIVE
    assert f.detail["node_version"] is None


def test_classify_ssh_failure():
    f = classify_node_output("h", 255, "", "Permission denied (publickey).")
    assert f.status == Status.ERROR
    assert f.detail["error_kind"] == "ssh"


def test_classify_connection_refused():
    f = classify_node_output("h", 255, "", "ssh: connect to host h port 22: Connection refused")
    assert f.status == Status.ERROR
    assert f.detail["error_kind"] == "ssh"
