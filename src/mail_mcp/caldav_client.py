"""CalDAV client: discovery, reading, and writing calendar entries.

CalDAV (RFC 4791) is WebDAV with calendar verbs: ``PROPFIND`` to walk the
hierarchy, ``REPORT`` to query events in a time range, and plain ``PUT`` and
``DELETE`` to write. Discovery follows RFC 6764: from an entry point, find the
``current-user-principal``, then that principal's ``calendar-home-set``, then
the calendars inside it.

Writes are conditional. A ``PUT`` that replaces an existing event carries
``If-Match`` with the ETag the event was read with, so a change made elsewhere
between the read and the write is rejected (412) instead of being silently
overwritten. New events use ``If-None-Match: *`` so two agents cannot create
the same one twice.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from typing import Any
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

import httpx

from mail_mcp import netguard
from mail_mcp.calendars import CalendarAccount
from mail_mcp.events import (
    EventRecord,
    caldav_stamp,
    expand_events,
    master_of,
    parse_events,
    zone,
)

logger = logging.getLogger("mail-mcp.caldav")

DAV = "DAV:"
CALDAV = "urn:ietf:params:xml:ns:caldav"
APPLE = "http://apple.com/ns/ical/"
NS = {"d": DAV, "c": CALDAV, "a": APPLE}

for prefix, uri in (("d", DAV), ("c", CALDAV), ("a", APPLE)):
    ET.register_namespace(prefix, uri)

_PROPFIND_PRINCIPAL = """<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>"""

_PROPFIND_HOME = """<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><c:calendar-home-set/></d:prop></d:propfind>"""

_PROPFIND_CALENDARS = """<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
            xmlns:a="http://apple.com/ns/ical/">
  <d:prop>
    <d:resourcetype/><d:displayname/><d:current-user-privilege-set/>
    <c:supported-calendar-component-set/><c:calendar-description/>
    <a:calendar-color/>
  </d:prop></d:propfind>"""

_REPORT_TIME_RANGE = """<?xml version="1.0" encoding="utf-8"?>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><d:getetag/><c:calendar-data/></d:prop>
  <c:filter>
    <c:comp-filter name="VCALENDAR">
      <c:comp-filter name="VEVENT">
        <c:time-range start="{start}" end="{end}"/>
      </c:comp-filter>
    </c:comp-filter>
  </c:filter>
</c:calendar-query>"""

_REPORT_BY_UID = """<?xml version="1.0" encoding="utf-8"?>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><d:getetag/><c:calendar-data/></d:prop>
  <c:filter>
    <c:comp-filter name="VCALENDAR">
      <c:comp-filter name="VEVENT">
        <c:prop-filter name="UID">
          <c:text-match collation="i;octet">{uid}</c:text-match>
        </c:prop-filter>
      </c:comp-filter>
    </c:comp-filter>
  </c:filter>
</c:calendar-query>"""


class CalDavError(RuntimeError):
    """Raised for any CalDAV failure, with a message fit for an agent."""

    def __init__(self, message: str, *, detail: str = "", status: int = 0):
        self.message = message
        self.detail = detail
        self.status = status
        super().__init__(f"{message} {detail}".strip())


@dataclass
class CalendarInfo:
    href: str
    name: str
    description: str = ""
    color: str = ""
    read_only: bool = False

    def matches(self, selector: str) -> bool:
        wanted = selector.strip().lower().rstrip("/")
        return wanted in (self.name.lower(), self.href.lower().rstrip("/"))


def usable_etag(etag: str) -> str:
    """The ETag to put in ``If-Match``, or "" when there is none to trust.

    A weak validator (``W/"..."``) is not allowed in ``If-Match`` (RFC 9110,
    13.1.1), and an empty one means the server gave us nothing to be
    conditional about.
    """
    cleaned = (etag or "").strip()
    if not cleaned or cleaned.upper().startswith("W/"):
        return ""
    return cleaned


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


class CalDavClient:
    """Async CalDAV client for one account.

    ``transport`` exists for the test suite, which mounts a fake CalDAV server
    as an ASGI app instead of opening a socket.
    """

    def __init__(
        self, account: CalendarAccount, *, transport: httpx.AsyncBaseTransport | None = None
    ):
        self.account = account
        self._entry_point = account.entry_point()
        if not self._entry_point:
            raise CalDavError(
                f"No CalDAV server is known for {account.address}. Set the URL."
            )
        self._client = httpx.AsyncClient(
            auth=httpx.BasicAuth(account.username, account.secret),
            timeout=account.timeout,
            verify=account.verify_ssl,
            follow_redirects=True,
            max_redirects=5,
            transport=transport,
            headers={"User-Agent": "mail-mcp-gateway/0.1 CalDAV"},
            # Every hop, redirects included, is checked against the network
            # policy before the request (and its credentials) leaves.
            event_hooks={"request": [_guard]},
        )
        self._home: str = account.discovered_home or ""
        self._calendars: list[CalendarInfo] | None = None

    async def close(self) -> None:
        await self._client.aclose()

    # --- plumbing ------------------------------------------------------------

    def absolute(self, href: str) -> str:
        """Turn a server-relative href into an absolute URL."""
        if href.startswith(("http://", "https://")):
            return href
        base = self._home or self._entry_point
        parsed = urlparse(base)
        return f"{parsed.scheme}://{parsed.netloc}{href}"

    async def _request(
        self,
        method: str,
        url: str,
        *,
        body: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: tuple[int, ...] = (200, 201, 204, 207),
        what: str = "request",
    ) -> httpx.Response:
        # A 302 or 303 turns a PUT or DELETE into a GET (that is what the
        # status codes mean), which then answers 200: the write would be
        # reported as done without having happened. Writes do not follow.
        writes = method in ("PUT", "DELETE")
        try:
            response = await self._client.request(
                method,
                url,
                content=body,
                headers=headers or {},
                follow_redirects=not writes,
            )
        except netguard.TargetError as e:
            raise CalDavError(str(e)) from e
        except httpx.HTTPError as e:
            raise CalDavError(
                f"Cannot reach the CalDAV server at {url}.", detail=str(e)
            ) from e

        if writes and 300 <= response.status_code < 400:
            raise CalDavError(
                f"The CalDAV server redirected the {what} elsewhere, so nothing "
                "was written.",
                detail=f"HTTP {response.status_code} to "
                f"{response.headers.get('Location', '?')}. Check the calendar URL.",
                status=response.status_code,
            )

        if response.status_code in (401, 403):
            raise CalDavError(
                f"CalDAV login rejected for {self.account.address}.",
                detail="Apple iCloud needs an app-specific password, not your "
                "Apple ID password.",
                status=response.status_code,
            )
        if response.status_code == 412:
            raise CalDavError(
                "The server rejected the write because the event changed "
                "underneath it. The change was re-applied to the newer version "
                "and rejected again, so something else is editing this event "
                "right now.",
                status=412,
            )
        if response.status_code == 404:
            raise CalDavError(
                "That calendar or event no longer exists on the server.", status=404
            )
        if response.status_code not in expected:
            # The body stays in the log: echoing it would let a connection
            # test read whatever page sits at the URL.
            logger.debug(
                "CalDAV %s %s -> %s: %s", method, url, response.status_code,
                response.text[:500],
            )
            raise CalDavError(
                f"The CalDAV server refused the {what}.",
                detail=f"HTTP {response.status_code}.",
                status=response.status_code,
            )
        return response

    @staticmethod
    def _tree(response: httpx.Response) -> ET.Element:
        try:
            return ET.fromstring(response.content)
        except ET.ParseError as e:
            raise CalDavError(
                "The CalDAV server sent a reply I could not parse.", detail=str(e)
            ) from e

    # --- discovery -----------------------------------------------------------

    async def _principal(self) -> str:
        """Find the current user's principal URL (RFC 5397 / RFC 6764)."""
        candidates = [self._entry_point, urljoin(self._entry_point + "/", "/.well-known/caldav")]
        last_error: CalDavError | None = None
        for url in candidates:
            try:
                response = await self._request(
                    "PROPFIND",
                    url,
                    body=_PROPFIND_PRINCIPAL,
                    headers={"Depth": "0", "Content-Type": "application/xml; charset=utf-8"},
                    what="principal lookup",
                )
            except CalDavError as e:
                last_error = e
                continue
            node = self._tree(response).find(".//d:current-user-principal/d:href", NS)
            if node is not None and node.text:
                return self.absolute(node.text.strip())
        if last_error is not None:
            raise last_error
        raise CalDavError(
            "The server did not say which principal this login belongs to.",
            detail="It may not be a CalDAV server, or the URL may point elsewhere.",
        )

    async def calendar_home(self) -> str:
        """The collection holding this account's calendars, discovered once."""
        if self._home:
            return self._home
        principal = await self._principal()
        response = await self._request(
            "PROPFIND",
            principal,
            body=_PROPFIND_HOME,
            headers={"Depth": "0", "Content-Type": "application/xml; charset=utf-8"},
            what="calendar home lookup",
        )
        node = self._tree(response).find(".//c:calendar-home-set/d:href", NS)
        if node is None or not node.text:
            raise CalDavError("The server exposed no calendar home for this account.")
        self._home = self.absolute(node.text.strip())
        self.account.discovered_home = self._home
        logger.info("CalDAV home for %s: %s", self.account.address, self._home)
        return self._home

    async def list_calendars(self, refresh: bool = False) -> list[CalendarInfo]:
        """List the calendars that can hold events."""
        if self._calendars is not None and not refresh:
            return self._calendars
        home = await self.calendar_home()
        response = await self._request(
            "PROPFIND",
            home,
            body=_PROPFIND_CALENDARS,
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
            what="calendar listing",
        )
        calendars: list[CalendarInfo] = []
        for entry in self._tree(response).findall(".//d:response", NS):
            href_node = entry.find("d:href", NS)
            if href_node is None or not href_node.text:
                continue
            href = href_node.text.strip()
            if entry.find(".//d:resourcetype/c:calendar", NS) is None:
                continue
            components = entry.findall(".//c:supported-calendar-component-set/c:comp", NS)
            names = {c.get("name", "").upper() for c in components}
            if names and "VEVENT" not in names:
                continue  # task or journal collection
            privileges = entry.findall(".//d:current-user-privilege-set/d:privilege", NS)
            can_write = not privileges or any(
                privilege.find("d:write", NS) is not None
                or privilege.find("d:write-content", NS) is not None
                or privilege.find("d:all", NS) is not None
                for privilege in privileges
            )
            display = entry.find(".//d:displayname", NS)
            description = entry.find(".//c:calendar-description", NS)
            color = entry.find(".//a:calendar-color", NS)
            calendars.append(
                CalendarInfo(
                    href=href,
                    name=(display.text or "").strip()
                    if display is not None and display.text
                    else href.rstrip("/").rpartition("/")[2],
                    description=(description.text or "").strip()
                    if description is not None and description.text
                    else "",
                    color=(color.text or "").strip()
                    if color is not None and color.text
                    else "",
                    read_only=not can_write,
                )
            )
        calendars.sort(key=lambda c: c.name.lower())
        self._calendars = calendars
        return calendars

    async def resolve_calendar(self, selector: str | None = None) -> CalendarInfo:
        """Pick the calendar a call is about, by name or href."""
        calendars = await self.list_calendars()
        if not calendars:
            raise CalDavError("This account has no calendar the agent can use.")
        wanted = (selector or self.account.default_calendar or "").strip()
        if wanted:
            for calendar in calendars:
                if calendar.matches(wanted):
                    return calendar
            known = ", ".join(c.name for c in calendars)
            raise CalDavError(
                f"No calendar named {wanted!r}. Available: {known}."
            )
        return calendars[0]

    async def check(self) -> dict[str, Any]:
        """Log in and report what was found, for the connection test."""
        calendars = await self.list_calendars(refresh=True)
        return {
            "ok": True,
            "home": self._home,
            "calendars": [
                {"name": c.name, "href": c.href, "read_only": c.read_only}
                for c in calendars
            ],
        }

    # --- reading -------------------------------------------------------------

    def _parse_multistatus(
        self,
        response: httpx.Response,
        calendar: CalendarInfo,
        window: tuple[datetime, datetime] | None = None,
    ) -> list[EventRecord]:
        records: list[EventRecord] = []
        for entry in self._tree(response).findall(".//d:response", NS):
            href_node = entry.find("d:href", NS)
            data_node = entry.find(".//c:calendar-data", NS)
            if href_node is None or data_node is None or not data_node.text:
                continue
            etag_node = entry.find(".//d:getetag", NS)
            options = {
                "href": href_node.text.strip(),
                "etag": usable_etag(etag_node.text or "") if etag_node is not None else "",
                "calendar": calendar.name,
            }
            if window is not None:
                records += expand_events(data_node.text, *window, **options)
            else:
                records += parse_events(data_node.text, **options)
        return records

    async def events_between(
        self, start: datetime, end: datetime, *, calendar: str | None = None
    ) -> tuple[list[EventRecord], CalendarInfo]:
        """Occurrences overlapping a time range, recurring events expanded."""
        target = await self.resolve_calendar(calendar)
        body = _REPORT_TIME_RANGE.format(
            start=caldav_stamp(start), end=caldav_stamp(end)
        )
        response = await self._request(
            "REPORT",
            self.absolute(target.href),
            body=body,
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
            what="event query",
        )
        records = self._parse_multistatus(response, target, window=(start, end))
        tz = zone(self.account.timezone)
        records.sort(key=lambda r: _sort_key(r, tz))
        return records, target

    async def find_by_uid(
        self, uid: str, *, calendar: str | None = None
    ) -> tuple[EventRecord | None, CalendarInfo]:
        """Find one event by its UID inside a calendar."""
        target = await self.resolve_calendar(calendar)
        body = _REPORT_BY_UID.format(uid=_escape(uid))
        response = await self._request(
            "REPORT",
            self.absolute(target.href),
            body=body,
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
            what="event lookup",
        )
        # text-match is a substring match (RFC 4791 9.7.5): "abc" also finds
        # "xabcx". Only an exact UID counts, and two resources claiming the
        # same one is a question for the caller, not a coin toss.
        records = [r for r in self._parse_multistatus(response, target) if r.uid == uid]
        hrefs = {r.href for r in records}
        if len(hrefs) > 1:
            raise CalDavError(
                f"{len(hrefs)} entries in {target.name!r} carry the UID {uid}, so "
                "I will not guess which one you mean.",
                detail="Fix the duplicate in a calendar app.",
            )
        return master_of(records), target

    async def fetch(self, href: str, calendar: str = "") -> EventRecord:
        """Read one calendar resource by its href."""
        response = await self._request(
            "GET", self.absolute(href), what="event fetch", expected=(200,)
        )
        records = parse_events(
            response.content,
            href=href,
            etag=usable_etag(response.headers.get("ETag", "")),
            calendar=calendar,
        )
        master = master_of(records)
        if master is None:
            raise CalDavError("That calendar entry holds no event.")
        return master

    # --- writing -------------------------------------------------------------

    def _guard_read_only(self, action: str) -> None:
        if self.account.read_only:
            error = CalDavError(
                f"{self.account.address} is connected read-only, so {action} is "
                "not allowed. Change that in the web UI if you meant to."
            )
            error.activity_status = "denied"
            raise error

    async def create(
        self, ics: bytes, uid: str, *, calendar: str | None = None
    ) -> tuple[str, CalendarInfo]:
        """PUT a new event; returns its href."""
        self._guard_read_only("creating events")
        target = await self.resolve_calendar(calendar)
        if target.read_only:
            raise CalDavError(f"The calendar {target.name!r} is read-only on the server.")
        href = target.href.rstrip("/") + f"/{_safe_name(uid)}.ics"
        await self._request(
            "PUT",
            self.absolute(href),
            body=ics,
            headers={
                "Content-Type": "text/calendar; charset=utf-8",
                "If-None-Match": "*",
            },
            expected=(200, 201, 204),
            what="new event",
        )
        return href, target

    async def replace(self, href: str, ics: bytes, etag: str = "") -> None:
        """PUT over an existing event, refusing to clobber a newer version."""
        self._guard_read_only("changing events")
        headers = {"Content-Type": "text/calendar; charset=utf-8"}
        if etag:
            headers["If-Match"] = etag
        await self._request(
            "PUT",
            self.absolute(href),
            body=ics,
            headers=headers,
            expected=(200, 201, 204),
            what="event update",
        )

    async def update_resource(
        self,
        href: str,
        transform,
        *,
        calendar: str = "",
        attempts: int = 2,
    ) -> EventRecord:
        """Read a resource, apply ``transform`` to its bytes, write it back.

        The validator comes from **this** GET, not from the REPORT that found
        the event: several servers, iCloud among them, hand out ETags in a
        ``calendar-query`` that do not match the resource's current validator,
        which would make every conditional write fail with 412 even when
        nobody else touched the event.

        If the write still loses a race, the whole read-modify-write is
        replayed once against the newer version before giving up, so a change
        the agent asked for is not dropped because of a concurrent edit it
        could not have known about.
        """
        self._guard_read_only("changing events")
        last_error: CalDavError | None = None
        for attempt in range(max(1, attempts)):
            current = await self.fetch(href, calendar)
            updated = transform(current.raw)
            try:
                await self.replace(href, updated, etag=current.etag)
                return current
            except CalDavError as e:
                if e.status != 412:
                    raise
                last_error = e
                logger.info(
                    "Conditional write on %s lost a race (attempt %d); re-reading",
                    href,
                    attempt + 1,
                )
        raise last_error or CalDavError("The event could not be updated.")

    async def delete_resource(
        self, href: str, *, calendar: str = "", attempts: int = 2
    ) -> EventRecord:
        """Delete a resource, conditional on the version just read."""
        self._guard_read_only("deleting events")
        last_error: CalDavError | None = None
        for attempt in range(max(1, attempts)):
            current = await self.fetch(href, calendar)
            try:
                await self.delete(href, etag=current.etag)
                return current
            except CalDavError as e:
                if e.status != 412:
                    raise
                last_error = e
                logger.info(
                    "Conditional delete on %s lost a race (attempt %d); re-reading",
                    href,
                    attempt + 1,
                )
        raise last_error or CalDavError("The event could not be deleted.")

    async def delete(self, href: str, etag: str = "") -> None:
        self._guard_read_only("deleting events")
        headers = {"If-Match": etag} if etag else {}
        await self._request(
            "DELETE",
            self.absolute(href),
            headers=headers,
            expected=(200, 204, 404),
            what="event deletion",
        )


async def _guard(request: httpx.Request) -> None:
    await netguard.acheck_host(request.url.host)


def _sort_key(record: EventRecord, tz) -> tuple[int, datetime]:
    """Order all-day and timed events on one clock: the account's."""
    start = record.start
    if start is None:
        return (1, datetime.min.replace(tzinfo=UTC))
    if isinstance(start, datetime):
        moment = start if start.tzinfo else start.replace(tzinfo=tz)
    elif isinstance(start, date):
        moment = datetime.combine(start, time(0, 0), tzinfo=tz)
    else:
        return (1, datetime.min.replace(tzinfo=UTC))
    return (0, moment.astimezone(UTC))


def _safe_name(uid: str) -> str:
    """A filename derived from the UID: servers dislike odd characters."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", uid)
    return cleaned[:120] or "event"
