"""A tiny in-process IMAP server, just complete enough to drive ImapClient.

It speaks the subset the gateway uses (CAPABILITY, LOGIN, LIST, SELECT/EXAMINE,
STATUS, UID SEARCH/FETCH/STORE/MOVE/COPY, CREATE, APPEND, LOGOUT) over plain TCP on
localhost, so the IMAP code path is exercised for real rather than mocked.
"""

from __future__ import annotations

import re
import socketserver
import threading
from email.message import EmailMessage

CAPABILITIES = "IMAP4rev1 LITERAL+ UIDPLUS MOVE"


def _message(uid: int, subject: str, sender: str, to: str, date: str, body: str) -> bytes:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to
    message["Date"] = date
    message["Message-ID"] = f"<msg{uid}@example.test>"
    message.set_content(body)
    return message.as_bytes()


class Mailbox:
    def __init__(self, name: str, flags: str = "\\HasNoChildren"):
        self.name = name
        self.flags = flags
        self.messages: dict[int, tuple[bytes, set[str]]] = {}
        self.next_uid = 1

    def add(self, raw: bytes, flags: set[str] | None = None) -> int:
        uid = self.next_uid
        self.next_uid += 1
        self.messages[uid] = (raw, flags or set())
        return uid


class FakeIMAPState:
    """Server-side state, shared by every connection (one test mailbox set)."""

    def __init__(self) -> None:
        self.password = "s3cret"
        self.username = "ada@example.test"
        self.folders: dict[str, Mailbox] = {
            "INBOX": Mailbox("INBOX"),
            "Sent": Mailbox("Sent", "\\HasNoChildren \\Sent"),
            "Trash": Mailbox("Trash", "\\HasNoChildren \\Trash"),
            "Drafts": Mailbox("Drafts", "\\HasNoChildren \\Drafts"),
            # A non-ASCII folder, stored as modified UTF-7 like a real server.
            "Archives/&AMk-t&AOk- 2024": Mailbox("Archives/&AMk-t&AOk- 2024"),
        }
        self.appended: list[tuple[str, bytes]] = []
        # Tests downgrade this to exercise the fallbacks of older servers.
        self.capabilities = CAPABILITIES
        inbox = self.folders["INBOX"]
        inbox.add(
            _message(1, "Invoice #42", "Billing <billing@acme.test>",
                     "ada@example.test", "Mon, 21 Sep 2026 09:15:00 +0000",
                     "Please find invoice 42 attached."),
            {"\\Seen"},
        )
        inbox.add(
            _message(2, "Déjeuner jeudi ?", "Bob <bob@example.test>",
                     "ada@example.test", "Tue, 22 Sep 2026 11:30:00 +0000",
                     "On se voit jeudi midi ?"),
            set(),
        )
        inbox.add(
            _message(3, "Re: Invoice #42", "Billing <billing@acme.test>",
                     "ada@example.test", "Tue, 22 Sep 2026 14:00:00 +0000",
                     "Reminder about invoice 42."),
            set(),
        )


class _Handler(socketserver.StreamRequestHandler):
    state: FakeIMAPState

    def handle(self) -> None:
        self.selected: Mailbox | None = None
        self.authenticated = False
        self._send(f"* OK [CAPABILITY {self.state.capabilities}] fake IMAP ready")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            try:
                if not self._dispatch(line.decode("utf-8", errors="replace").strip()):
                    return
            except Exception as e:
                self._send(f"* BAD internal error: {e}")
                return

    # --- plumbing ---

    def _send(self, line: str) -> None:
        self.wfile.write(line.encode("utf-8") + b"\r\n")
        self.wfile.flush()

    def _send_bytes(self, payload: bytes) -> None:
        self.wfile.write(payload)
        self.wfile.flush()

    def _read_literal(self, size: int) -> bytes:
        data = self.rfile.read(size)
        self.rfile.readline()  # trailing CRLF
        return data

    @staticmethod
    def _unquote(value: str) -> str:
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        return value

    def _folder(self, name: str) -> Mailbox | None:
        return self.state.folders.get(self._unquote(name))

    # --- command dispatch ---

    def _dispatch(self, line: str) -> bool:
        tag, _, rest = line.partition(" ")
        command, _, args = rest.partition(" ")
        command = command.upper()

        if command == "CAPABILITY":
            self._send(f"* CAPABILITY {self.state.capabilities}")
            self._send(f"{tag} OK CAPABILITY completed")
        elif command == "LOGIN":
            user, _, password = args.partition(" ")
            if (
                self._unquote(user) == self.state.username
                and self._unquote(password) == self.state.password
            ):
                self.authenticated = True
                self._send(f"{tag} OK LOGIN completed")
            else:
                self._send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")
        elif command == "LOGOUT":
            self._send("* BYE logging out")
            self._send(f"{tag} OK LOGOUT completed")
            return False
        elif command == "NOOP":
            self._send(f"{tag} OK NOOP completed")
        elif not self.authenticated:
            self._send(f"{tag} NO not authenticated")
        elif command == "LIST":
            for mailbox in self.state.folders.values():
                self._send(f'* LIST ({mailbox.flags}) "/" "{mailbox.name}"')
            self._send(f"{tag} OK LIST completed")
        elif command in ("SELECT", "EXAMINE"):
            mailbox = self._folder(args)
            if mailbox is None:
                self._send(f"{tag} NO no such mailbox")
            else:
                self.selected = mailbox
                self._send(f"* {len(mailbox.messages)} EXISTS")
                self._send("* 0 RECENT")
                self._send("* OK [UIDVALIDITY 1] UIDs valid")
                mode = "READ-ONLY" if command == "EXAMINE" else "READ-WRITE"
                self._send(f"{tag} OK [{mode}] {command} completed")
        elif command == "STATUS":
            name, _, _items = args.partition(" (")
            mailbox = self._folder(name)
            if mailbox is None:
                self._send(f"{tag} NO no such mailbox")
            else:
                unseen = sum(
                    1 for _, flags in mailbox.messages.values() if "\\Seen" not in flags
                )
                self._send(
                    f'* STATUS "{mailbox.name}" (MESSAGES {len(mailbox.messages)} '
                    f"UNSEEN {unseen} RECENT 0 UIDNEXT {mailbox.next_uid} UIDVALIDITY 1)"
                )
                self._send(f"{tag} OK STATUS completed")
        elif command == "CREATE":
            name = self._unquote(args)
            self.state.folders.setdefault(name, Mailbox(name))
            self._send(f"{tag} OK CREATE completed")
        elif command == "EXPUNGE":
            # The folder-wide form: every \\Deleted message goes, whoever flagged it.
            mailbox = self.selected
            if mailbox is None:
                self._send(f"{tag} BAD no mailbox selected")
            else:
                for uid, (_, flags) in list(mailbox.messages.items()):
                    if "\\Deleted" in flags:
                        mailbox.messages.pop(uid, None)
                self._send(f"{tag} OK EXPUNGE completed")
        elif command == "APPEND":
            self._append(tag, args)
        elif command == "UID":
            self._uid(tag, args)
        else:
            self._send(f"{tag} BAD unsupported command {command}")
        return True

    def _append(self, tag: str, args: str) -> None:
        match = re.search(r"\{(\d+)\}$", args)
        if not match:
            self._send(f"{tag} BAD APPEND needs a literal")
            return
        name = self._unquote(args.split(" ")[0])
        self._send("+ Ready for literal data")
        payload = self._read_literal(int(match.group(1)))
        mailbox = self.state.folders.get(name)
        if mailbox is None:
            self._send(f"{tag} NO [TRYCREATE] no such mailbox")
            return
        uid = mailbox.add(payload)
        self.state.appended.append((name, payload))
        self._send(f"{tag} OK [APPENDUID 1 {uid}] APPEND completed")

    def _uid(self, tag: str, args: str) -> None:
        sub, _, rest = args.partition(" ")
        sub = sub.upper()
        mailbox = self.selected
        if mailbox is None:
            self._send(f"{tag} BAD no mailbox selected")
            return

        if sub == "SEARCH":
            self._search(tag, rest, mailbox)
        elif sub == "FETCH":
            self._fetch(tag, rest, mailbox)
        elif sub == "STORE":
            uid_set, _, flag_args = rest.partition(" ")
            operation, _, flags = flag_args.partition(" ")
            wanted = set(flags.strip("()").split())
            for uid in self._uids(uid_set, mailbox):
                raw, current = mailbox.messages[uid]
                if operation.startswith("+"):
                    current |= wanted
                else:
                    current -= wanted
                mailbox.messages[uid] = (raw, current)
            self._send(f"{tag} OK STORE completed")
        elif sub == "MOVE":
            uid_set, _, destination = rest.partition(" ")
            target = self._folder(destination)
            if target is None:
                self._send(f"{tag} NO [TRYCREATE] no such mailbox")
                return
            for uid in self._uids(uid_set, mailbox):
                raw, flags = mailbox.messages.pop(uid)
                target.add(raw, flags)
            self._send(f"{tag} OK MOVE completed")
        elif sub == "COPY":
            uid_set, _, destination = rest.partition(" ")
            target = self._folder(destination)
            if target is None:
                self._send(f"{tag} NO [TRYCREATE] no such mailbox")
                return
            for uid in self._uids(uid_set, mailbox):
                raw, flags = mailbox.messages[uid]
                target.add(raw, set(flags))
            self._send(f"{tag} OK COPY completed")
        elif sub == "EXPUNGE" and "UIDPLUS" not in self.state.capabilities:
            self._send(f"{tag} BAD UID EXPUNGE needs UIDPLUS")
        elif sub == "EXPUNGE":
            for uid in self._uids(rest, mailbox):
                _, flags = mailbox.messages.get(uid, (b"", set()))
                if "\\Deleted" in flags:
                    mailbox.messages.pop(uid, None)
            self._send(f"{tag} OK EXPUNGE completed")
        else:
            self._send(f"{tag} BAD unsupported UID command {sub}")

    @staticmethod
    def _uids(uid_set: str, mailbox: Mailbox) -> list[int]:
        out: list[int] = []
        for part in uid_set.strip().split(","):
            if ":" in part:
                start, _, end = part.partition(":")
                last = mailbox.next_uid if end == "*" else int(end)
                out += [u for u in mailbox.messages if int(start) <= u <= last]
            elif part.isdigit() and int(part) in mailbox.messages:
                out.append(int(part))
        return out

    def _search(self, tag: str, rest: str, mailbox: Mailbox) -> None:
        tokens = rest
        if tokens.upper().startswith("CHARSET "):
            tokens = tokens.partition(" ")[2].partition(" ")[2]
        matches: list[int] = []
        by_uid = re.match(r"UID (\S+)", tokens)
        allowed = set(self._uids(by_uid.group(1), mailbox)) if by_uid else None
        for uid, (raw, flags) in mailbox.messages.items():
            if allowed is not None and uid not in allowed:
                continue
            text = raw.decode("utf-8", errors="replace")
            keep = True
            upper = tokens.upper()
            if "UNSEEN" in upper and "\\Seen" in flags:
                keep = False
            if "SEEN" in upper and "UNSEEN" not in upper and "\\Seen" not in flags:
                keep = False
            subject = re.search(r'SUBJECT "([^"]*)"', tokens)
            if subject and subject.group(1).lower() not in text.lower():
                keep = False
            sender = re.search(r'FROM "([^"]*)"', tokens)
            if sender and sender.group(1).lower() not in text.lower():
                keep = False
            if keep:
                matches.append(uid)
        self._send("* SEARCH " + " ".join(str(uid) for uid in sorted(matches)))
        self._send(f"{tag} OK SEARCH completed")

    def _fetch(self, tag: str, rest: str, mailbox: Mailbox) -> None:
        uid_set, _, spec = rest.partition(" ")
        spec_upper = spec.upper()
        for sequence, uid in enumerate(self._uids(uid_set, mailbox), start=1):
            raw, flags = mailbox.messages[uid]
            flag_text = " ".join(sorted(flags))
            if "HEADER.FIELDS" in spec_upper:
                header_block = raw.split(b"\r\n\r\n")[0].split(b"\n\n")[0] + b"\r\n\r\n"
                preamble = (
                    f"* {sequence} FETCH (UID {uid} FLAGS ({flag_text}) "
                    f'INTERNALDATE "22-Sep-2026 10:00:00 +0000" '
                    f"RFC822.SIZE {len(raw)} "
                    f"BODY[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID "
                    f"IN-REPLY-TO REFERENCES LIST-UNSUBSCRIBE)] "
                    f"{{{len(header_block)}}}\r\n"
                )
                self._send_bytes(preamble.encode() + header_block + b")\r\n")
            else:
                preamble = f"* {sequence} FETCH (UID {uid} BODY[] {{{len(raw)}}}\r\n"
                self._send_bytes(preamble.encode() + raw + b")\r\n")
        self._send(f"{tag} OK FETCH completed")


class FakeIMAPServer:
    """Runs the fake server on a background thread; use as a context manager."""

    def __init__(self) -> None:
        self.state = FakeIMAPState()
        handler = type("BoundHandler", (_Handler,), {"state": self.state})
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        self.host, self.port = self.server.server_address[:2]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> FakeIMAPServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
