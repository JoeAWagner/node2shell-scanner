from n2scan.versions import node_patch_status, parse_version


def test_parse_version():
    assert parse_version("v24.22.0") == (24, 22, 0)
    assert parse_version("node/22.23.4") == (22, 23, 4)
    assert parse_version("nothing here") is None


def test_affected_versions():
    # below the fix on each supported train => affected
    assert node_patch_status("22.23.3") is True
    assert node_patch_status("24.22.0") is True
    assert node_patch_status("26.12.0") is True


def test_patched_versions():
    # at or above the fix => patched
    assert node_patch_status("22.23.4") is False
    assert node_patch_status("24.22.1") is False
    assert node_patch_status("26.12.1") is False
    assert node_patch_status("26.13.0") is False


def test_known_affected_and_eol_majors():
    assert node_patch_status("23.5.0") is True   # odd/EOL but affected
    assert node_patch_status("18.19.0") is True   # old LTS, upgrade regardless


def test_unknown_major_is_none():
    # a future major past all fixed trains we can't reason about precisely
    assert node_patch_status("99.0.0") is None
