import pytest

from vbeye.cookies import is_csrf_token_cookie, is_likely_session_cookie, parse_set_cookie


def test_parse_basic_attributes():
    name, value, attrs = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert name == "sid"
    assert value == "abc"
    assert attrs == {"path": "/", "secure": None, "httponly": None, "samesite": "Lax"}


def test_parse_value_containing_flag_words_is_not_an_attribute():
    name, value, attrs = parse_set_cookie("pref=secure-httponly-samesite=strict; Path=/")
    assert name == "pref"
    assert value == "secure-httponly-samesite=strict"
    assert "secure" not in attrs
    assert "httponly" not in attrs
    assert "samesite" not in attrs


def test_parse_name_containing_secure_is_not_an_attribute():
    name, _, attrs = parse_set_cookie("secure_session=x; HttpOnly")
    assert name == "secure_session"
    assert "secure" not in attrs
    assert "httponly" in attrs


def test_parse_value_with_equals_and_empty_parts():
    name, value, attrs = parse_set_cookie("t=a=b==;;  ; Max-Age=60")
    assert name == "t"
    assert value == "a=b=="
    assert attrs == {"max-age": "60"}


def test_parse_cookie_without_value():
    name, value, attrs = parse_set_cookie("flag; Secure")
    assert name == "flag"
    assert value == ""
    assert "secure" in attrs


@pytest.mark.parametrize("name", [
    "sessionid", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "connect.sid",
    "laravel_session", "auth_token", "user_sid", "wordpress_logged_in_abc123",
    "authToken", "my-session", "SESS0123456789abcdef0123456789abcdef",
    "0123456789abcdef0123456789abcdef", "ASPSESSIONIDQASDFGHJ", "remember_me",
])
def test_session_cookie_names(name):
    assert is_likely_session_cookie(name)


@pytest.mark.parametrize("name", [
    "author_pref", "consent", "inside", "_ga", "theme", "lang", "cookielawinfo",
    "tokenizer_pref", "authority", "sidebar_state", "",
])
def test_non_session_cookie_names(name):
    assert not is_likely_session_cookie(name)


@pytest.mark.parametrize("name", ["XSRF-TOKEN", "csrftoken", "_csrf", "__RequestVerificationToken"])
def test_csrf_cookie_names(name):
    assert is_csrf_token_cookie(name)


def test_csrf_matcher_requires_exact_name():
    assert not is_csrf_token_cookie("my_csrf_session")
