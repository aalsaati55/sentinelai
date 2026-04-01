"""
test_parser_auth.py

Unit tests for parser_auth.py.
Run with: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from parser_auth import parse_auth_line
from config import EventType, EventStatus, LogSource


# ── Sample auth.log lines ──────────────────────────────────────────────────────

FAILED_PASSWORD     = "Mar 25 03:00:01 ubuntu-vm sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
FAILED_INVALID_USER = "Mar 25 03:01:00 ubuntu-vm sshd[1235]: Failed password for invalid user hacker from 10.0.0.5 port 22 ssh2"
INVALID_USER_ONLY   = "Mar 25 03:01:05 ubuntu-vm sshd[1236]: Invalid user ghost from 10.0.0.6"
ACCEPTED_PASSWORD   = "Mar 25 03:05:00 ubuntu-vm sshd[1237]: Accepted password for alice from 192.168.1.100 port 22 ssh2"
ACCEPTED_PUBKEY     = "Mar 25 03:06:00 ubuntu-vm sshd[1238]: Accepted publickey for bob from 192.168.1.101 port 22 ssh2"
SUDO_COMMAND        = "Mar 25 03:10:00 ubuntu-vm sudo[1240]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
SUDO_FAILURE        = "Mar 25 03:11:00 ubuntu-vm sudo[1241]: pam_unix(sudo:auth): authentication failure; logname=alice uid=1001 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice"
SESSION_OPENED_SSH  = "Mar 25 03:05:01 ubuntu-vm sshd[1242]: pam_unix(sshd:session): session opened for user alice by (uid=0)"
SESSION_OPENED_SUDO = "Mar 25 03:10:01 ubuntu-vm sudo[1243]: pam_unix(sudo:session): session opened for user root by alice(uid=1001)"
SESSION_CLOSED      = "Mar 25 03:15:00 ubuntu-vm sshd[1244]: pam_unix(sshd:session): session closed for user alice"
DISCONNECTED        = "Mar 25 03:20:00 ubuntu-vm sshd[1245]: Disconnected from user alice 192.168.1.100 port 22"
IRRELEVANT          = "Mar 25 03:00:00 ubuntu-vm CRON[999]: (root) CMD (/usr/lib/cron/run-crons)"


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestFailedPassword:
    def test_returns_event(self):
        e = parse_auth_line(FAILED_PASSWORD)
        assert e is not None

    def test_event_type(self):
        e = parse_auth_line(FAILED_PASSWORD)
        assert e["event_type"] == EventType.LOGIN_FAILURE

    def test_source_ip(self):
        e = parse_auth_line(FAILED_PASSWORD)
        assert e["source_ip"] == "192.168.1.50"

    def test_username(self):
        e = parse_auth_line(FAILED_PASSWORD)
        assert e["username"] == "root"

    def test_status(self):
        e = parse_auth_line(FAILED_PASSWORD)
        assert e["status"] == EventStatus.FAILURE

    def test_log_source(self):
        e = parse_auth_line(FAILED_PASSWORD)
        assert e["log_source"] == LogSource.AUTH

    def test_raw_log_preserved(self):
        e = parse_auth_line(FAILED_PASSWORD)
        assert e["raw_log"] == FAILED_PASSWORD


class TestInvalidUser:
    def test_failed_password_for_invalid_user(self):
        e = parse_auth_line(FAILED_INVALID_USER)
        assert e is not None
        assert e["event_type"] == EventType.LOGIN_INVALID_USER

    def test_invalid_user_only_line(self):
        e = parse_auth_line(INVALID_USER_ONLY)
        assert e is not None
        assert e["event_type"] == EventType.LOGIN_INVALID_USER
        assert e["username"] == "ghost"
        assert e["source_ip"] == "10.0.0.6"


class TestAccepted:
    def test_accepted_password(self):
        e = parse_auth_line(ACCEPTED_PASSWORD)
        assert e is not None
        assert e["event_type"] == EventType.LOGIN_SUCCESS
        assert e["status"] == EventStatus.SUCCESS
        assert e["username"] == "alice"
        assert e["source_ip"] == "192.168.1.100"

    def test_accepted_publickey(self):
        e = parse_auth_line(ACCEPTED_PUBKEY)
        assert e is not None
        assert e["event_type"] == EventType.LOGIN_SUCCESS
        assert e["username"] == "bob"


class TestSudo:
    def test_sudo_command(self):
        e = parse_auth_line(SUDO_COMMAND)
        assert e is not None
        assert e["event_type"] == EventType.SUDO_SUCCESS
        assert e["username"] == "alice"
        assert e["status"] == EventStatus.SUCCESS
        assert "/etc/shadow" in e["message"]

    def test_sudo_failure(self):
        e = parse_auth_line(SUDO_FAILURE)
        assert e is not None
        assert e["event_type"] == EventType.SUDO_FAILURE
        assert e["status"] == EventStatus.FAILURE


class TestSessions:
    def test_ssh_session_opened(self):
        e = parse_auth_line(SESSION_OPENED_SSH)
        assert e is not None
        assert e["event_type"] == EventType.SESSION_OPENED
        assert e["username"] == "alice"

    def test_sudo_session_opened(self):
        e = parse_auth_line(SESSION_OPENED_SUDO)
        assert e is not None
        assert e["event_type"] == EventType.SUDO_SESSION_OPENED

    def test_session_closed(self):
        e = parse_auth_line(SESSION_CLOSED)
        assert e is not None
        assert e["event_type"] == EventType.SESSION_CLOSED

    def test_disconnected(self):
        e = parse_auth_line(DISCONNECTED)
        assert e is not None
        assert e["event_type"] == EventType.LOGOUT
        assert e["source_ip"] == "192.168.1.100"


class TestIrrelevantLine:
    def test_cron_line_returns_none(self):
        assert parse_auth_line(IRRELEVANT) is None

    def test_empty_line_returns_none(self):
        assert parse_auth_line("") is None


class TestNormalizedStructure:
    """Every parsed event must have all required fields."""
    REQUIRED_FIELDS = [
        "timestamp", "log_source", "event_type", "source_ip",
        "username", "hostname", "status", "message", "raw_log",
    ]

    def test_all_fields_present_on_failure(self):
        e = parse_auth_line(FAILED_PASSWORD)
        for field in self.REQUIRED_FIELDS:
            assert field in e, f"Missing field: {field}"

    def test_all_fields_present_on_success(self):
        e = parse_auth_line(ACCEPTED_PASSWORD)
        for field in self.REQUIRED_FIELDS:
            assert field in e, f"Missing field: {field}"
