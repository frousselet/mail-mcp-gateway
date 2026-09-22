"""A small in-process CalDAV server, enough to drive CalDavClient for real.

It speaks the subset the gateway uses: PROPFIND for discovery and calendar
listing, REPORT for time-range and UID queries, GET, conditional PUT and
DELETE. Mounted as an ASGI app in the tests, so no socket is involved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

USERNAME = "ada@example.test"
PASSWORD = "app-specific-password"
PRINCIPAL = "/principals/ada/"
HOME = "/calendars/ada/"

_MULTISTATUS_OPEN = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" '
    'xmlns:a="http://apple.com/ns/ical/">'
)


@dataclass
class FakeCalendar:
    href: str
    name: str
    read_only: bool = False
    component: str = "VEVENT"
    entries: dict[str, tuple[bytes, str]] = field(default_factory=dict)  # href -> (ics, etag)
    _seq: int = 0

    def put(self, href: str, ics: bytes) -> str:
        self._seq += 1
        etag = f'"etag-{self._seq}"'
        self.entries[href] = (ics, etag)
        return etag


class FakeCalDAVState:
    def __init__(self) -> None:
        self.username = USERNAME
        self.password = PASSWORD
        self.calendars: dict[str, FakeCalendar] = {
            f"{HOME}personal/": FakeCalendar(f"{HOME}personal/", "Personal"),
            f"{HOME}work/": FakeCalendar(f"{HOME}work/", "Work"),
            f"{HOME}shared/": FakeCalendar(f"{HOME}shared/", "Team (read-only)", read_only=True),
            f"{HOME}reminders/": FakeCalendar(
                f"{HOME}reminders/", "Reminders", component="VTODO"
            ),
        }
        self.requests: list[tuple[str, str]] = []  # (method, path), for assertions
        # Servers do not all behave. These reproduce two real ones:
        # stale_report_etags: a calendar-query hands out validators that do not
        # match the resource's current ETag (observed on iCloud), so a write
        # conditional on the REPORT's ETag is rejected with 412.
        self.stale_report_etags = False
        # conflict_puts: the next N conditional writes lose a race.
        self.conflict_puts = 0

    def calendar_of(self, path: str) -> FakeCalendar | None:
        for href, calendar in self.calendars.items():
            if path.startswith(href):
                return calendar
        return None

    def seed(self, calendar_href: str, ics: bytes, name: str = "event") -> str:
        calendar = self.calendars[calendar_href]
        href = f"{calendar_href}{name}.ics"
        calendar.put(href, ics)
        return href


def _unauthorized() -> Response:
    return Response(
        "Unauthorized", status_code=401, headers={"WWW-Authenticate": "Basic"}
    )


def _time_range(body: str) -> tuple[str, str] | None:
    match = re.search(r'<c:time-range start="([^"]+)" end="([^"]+)"', body)
    return (match.group(1), match.group(2)) if match else None


def _uid_filter(body: str) -> str | None:
    match = re.search(r"<c:text-match[^>]*>([^<]+)</c:text-match>", body)
    return match.group(1) if match else None


def _event_window(ics: bytes) -> tuple[str, str]:
    """The event's DTSTART/DTEND as basic UTC stamps, for range filtering."""
    text = ics.decode("utf-8", errors="replace")
    start = re.search(r"DTSTART[^:]*:(\d{8}T?\d{0,6})", text)
    end = re.search(r"DTEND[^:]*:(\d{8}T?\d{0,6})", text)
    first = (start.group(1) if start else "00000000").ljust(15, "0")
    last = (end.group(1) if end else first).ljust(15, "0")
    return first.replace("T", ""), last.replace("T", "")


def build_app(state: FakeCalDAVState) -> Starlette:
    def authorised(request: Request) -> bool:
        import base64

        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode()
        except Exception:
            return False
        user, _, password = decoded.partition(":")
        return user == state.username and password == state.password

    async def handler(request: Request) -> Response:
        path = "/" + request.path_params.get("path", "")
        state.requests.append((request.method, path))
        if not authorised(request):
            return _unauthorized()
        body = (await request.body()).decode("utf-8", errors="replace")

        if request.method == "PROPFIND":
            return _propfind(state, path, body, request.headers.get("depth", "0"))
        if request.method == "REPORT":
            return _report(state, path, body)
        if request.method == "GET":
            return _get(state, path)
        if request.method == "PUT":
            return _put(state, path, await request.body(), request.headers)
        if request.method == "DELETE":
            return _delete(state, path, request.headers)
        return PlainTextResponse("Not implemented", status_code=405)

    return Starlette(
        routes=[
            Route(
                "/{path:path}",
                handler,
                methods=["GET", "PUT", "DELETE", "PROPFIND", "REPORT"],
            )
        ]
    )


def _propfind(state: FakeCalDAVState, path: str, body: str, depth: str) -> Response:
    if "current-user-principal" in body:
        xml = (
            f"{_MULTISTATUS_OPEN}<d:response><d:href>{path}</d:href><d:propstat><d:prop>"
            f"<d:current-user-principal><d:href>{PRINCIPAL}</d:href>"
            "</d:current-user-principal></d:prop>"
            "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
        )
        return Response(xml, status_code=207, media_type="application/xml")

    if "calendar-home-set" in body:
        xml = (
            f"{_MULTISTATUS_OPEN}<d:response><d:href>{PRINCIPAL}</d:href><d:propstat><d:prop>"
            f"<c:calendar-home-set><d:href>{HOME}</d:href></c:calendar-home-set>"
            "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
            "</d:response></d:multistatus>"
        )
        return Response(xml, status_code=207, media_type="application/xml")

    # Calendar listing: the home collection itself, then each calendar.
    parts = [
        _MULTISTATUS_OPEN,
        f"<d:response><d:href>{HOME}</d:href><d:propstat><d:prop>"
        "<d:resourcetype><d:collection/></d:resourcetype>"
        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
    ]
    for calendar in state.calendars.values():
        privileges = "<d:privilege><d:read/></d:privilege>"
        if not calendar.read_only:
            privileges += "<d:privilege><d:write/></d:privilege>"
        parts.append(
            f"<d:response><d:href>{calendar.href}</d:href><d:propstat><d:prop>"
            "<d:resourcetype><d:collection/><c:calendar/></d:resourcetype>"
            f"<d:displayname>{calendar.name}</d:displayname>"
            "<c:supported-calendar-component-set>"
            f'<c:comp name="{calendar.component}"/>'
            "</c:supported-calendar-component-set>"
            f"<d:current-user-privilege-set>{privileges}</d:current-user-privilege-set>"
            '<a:calendar-color>#FF2968</a:calendar-color>'
            "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        )
    parts.append("</d:multistatus>")
    return Response("".join(parts), status_code=207, media_type="application/xml")


def _report(state: FakeCalDAVState, path: str, body: str) -> Response:
    calendar = state.calendars.get(path if path.endswith("/") else path + "/")
    if calendar is None:
        return PlainTextResponse("No such calendar", status_code=404)

    window = _time_range(body)
    uid = _uid_filter(body)
    parts = [_MULTISTATUS_OPEN]
    for href, (ics, etag) in calendar.entries.items():
        if uid and f"UID:{uid}".encode() not in ics:
            continue
        if window:
            start, end = _event_window(ics)
            if end < window[0].replace("T", "") or start > window[1].replace("T", ""):
                continue
        data = ics.decode().replace("&", "&amp;").replace("<", "&lt;")
        reported = f'"{etag.strip(chr(34))}-from-report"' if state.stale_report_etags else etag
        parts.append(
            f"<d:response><d:href>{href}</d:href><d:propstat><d:prop>"
            f"<d:getetag>{reported}</d:getetag>"
            f"<c:calendar-data>{data}</c:calendar-data>"
            "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        )
    parts.append("</d:multistatus>")
    return Response("".join(parts), status_code=207, media_type="application/xml")


def _get(state: FakeCalDAVState, path: str) -> Response:
    calendar = state.calendar_of(path)
    if calendar is None or path not in calendar.entries:
        return PlainTextResponse("Not found", status_code=404)
    ics, etag = calendar.entries[path]
    return Response(ics, media_type="text/calendar", headers={"ETag": etag})


def _put(state: FakeCalDAVState, path: str, ics: bytes, headers) -> Response:
    calendar = state.calendar_of(path)
    if calendar is None:
        return PlainTextResponse("No such calendar", status_code=404)
    if calendar.read_only:
        return PlainTextResponse("Forbidden", status_code=403)

    existing = calendar.entries.get(path)
    if headers.get("if-none-match") == "*" and existing is not None:
        return PlainTextResponse("Already exists", status_code=412)
    if_match = headers.get("if-match")
    if if_match:
        if existing is None:
            return PlainTextResponse("Gone", status_code=404)
        if state.conflict_puts > 0:
            state.conflict_puts -= 1
            calendar.put(path, existing[0])  # someone else wrote first
            return PlainTextResponse("Precondition failed", status_code=412)
        if if_match != existing[1]:
            return PlainTextResponse("Precondition failed", status_code=412)

    etag = calendar.put(path, ics)
    return Response(
        status_code=201 if existing is None else 204, headers={"ETag": etag}
    )


def _delete(state: FakeCalDAVState, path: str, headers) -> Response:
    calendar = state.calendar_of(path)
    if calendar is None or path not in calendar.entries:
        return PlainTextResponse("Not found", status_code=404)
    if calendar.read_only:
        return PlainTextResponse("Forbidden", status_code=403)
    if_match = headers.get("if-match")
    if if_match and if_match != calendar.entries[path][1]:
        return PlainTextResponse("Precondition failed", status_code=412)
    calendar.entries.pop(path)
    return Response(status_code=204)
