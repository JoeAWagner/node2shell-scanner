import httpx

from n2scan.http import classify_error, is_tls_verify_error
from n2scan.targets import Target


def test_classify_tls_verify():
    exc = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate")
    assert is_tls_verify_error(exc)
    assert classify_error(exc) == "tls-verify"


def test_classify_timeout_and_connect():
    assert classify_error(httpx.ConnectTimeout("slow")) == "timeout"
    assert classify_error(httpx.ConnectError("Connection refused")) == "connect"


def test_candidate_urls_bare_host_tries_both():
    t = Target(raw="h.sbu.edu", url="https://h.sbu.edu", host="h.sbu.edu", scheme_explicit=False)
    assert t.candidate_urls() == ["https://h.sbu.edu", "http://h.sbu.edu"]


def test_candidate_urls_explicit_scheme_honoured():
    t = Target(raw="http://h.sbu.edu", url="http://h.sbu.edu", host="h.sbu.edu", scheme_explicit=True)
    assert t.candidate_urls() == ["http://h.sbu.edu"]
