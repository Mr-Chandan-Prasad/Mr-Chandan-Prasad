from dataclasses import dataclass
from typing import Iterable, List


AUTH_COOKIE_HINTS = ("session", "auth", "token", "jwt", "sid", "login")


@dataclass
class CookieObservation:
    name: str
    value: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str
    has_expiry: bool


def extract_cookies(cookie_jar: Iterable) -> List[CookieObservation]:
    observations: List[CookieObservation] = []
    for cookie in cookie_jar:
        observations.append(
            CookieObservation(
                name=cookie.name,
                value=cookie.value or "",
                domain=cookie.domain or "",
                path=cookie.path or "",
                secure=bool(cookie.secure),
                http_only=bool(cookie._rest.get("HttpOnly") or cookie._rest.get("httponly")),
                same_site=str(cookie._rest.get("SameSite") or cookie._rest.get("samesite") or ""),
                has_expiry=bool(cookie.expires),
            )
        )
    return observations


def is_auth_cookie(cookie: CookieObservation) -> bool:
    name_lower = cookie.name.lower()
    if any(hint in name_lower for hint in AUTH_COOKIE_HINTS):
        return True
    if len(cookie.value) >= 32:
        return True
    return False
