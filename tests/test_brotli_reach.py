from n2scan.checks import ALL_CHECKS, DEFAULT_CHECK_NAMES
from n2scan.checks.brotli_reach import _PLAINTEXT, _VALID_BROTLI, BrotliReachabilityCheck
from n2scan.targets import Target


def test_registered_but_opt_in():
    assert "brotli-reach" in ALL_CHECKS
    assert "brotli-reach" not in DEFAULT_CHECK_NAMES


def test_embedded_payload_is_valid_brotli():
    # Only assert decode if a brotli lib is present; the payload must always be
    # non-empty bytes regardless so the check can send it.
    assert isinstance(_VALID_BROTLI, bytes) and _VALID_BROTLI
    try:
        import brotli
    except ImportError:
        return
    assert brotli.decompress(_VALID_BROTLI) == _PLAINTEXT


def test_probe_target_builds_path():
    check = BrotliReachabilityCheck(path="api/upload")
    t = Target(raw="h.sbu.edu", url="https://h.sbu.edu", host="h.sbu.edu", scheme_explicit=False)
    probe = check._probe_target(t)
    assert probe.url == "https://h.sbu.edu/api/upload"
    # scheme-fallback metadata is preserved so http:// is still a candidate
    assert probe.scheme_explicit is False
