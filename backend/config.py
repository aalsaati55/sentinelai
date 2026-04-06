import os

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_DIR = os.path.join(BASE_DIR, "data", "logs")

AUTH_LOG_PATH   = os.path.join(LOG_DIR, "auth.log")
SYSLOG_PATH     = os.path.join(LOG_DIR, "syslog")
CUSTOM_LOG_PATH = os.path.join(LOG_DIR, "custom_security.log")

DATABASE_PATH = os.path.join(BASE_DIR, "database", "sentinelai.db")
MODELS_DIR    = os.path.join(BASE_DIR, "models")

# ──────────────────────────────────────────────
# Log source identifiers
# ──────────────────────────────────────────────
class LogSource:
    AUTH   = "auth"
    SYSLOG = "syslog"
    CUSTOM = "custom"

# ──────────────────────────────────────────────
# Event type constants
# Each parser must map its output to one of these.
# ──────────────────────────────────────────────
class EventType:
    # Authentication events
    LOGIN_FAILURE          = "login_failure"
    LOGIN_SUCCESS          = "login_success"
    LOGIN_INVALID_USER     = "login_invalid_user"
    LOGOUT                 = "logout"

    # Privilege events
    SUDO_SUCCESS           = "sudo_success"
    SUDO_FAILURE           = "sudo_failure"
    SUDO_SESSION_OPENED    = "sudo_session_opened"
    SUDO_SESSION_CLOSED    = "sudo_session_closed"

    # Session events
    SESSION_OPENED         = "session_opened"
    SESSION_CLOSED         = "session_closed"

    # System / service events (syslog)
    SERVICE_STARTED        = "service_started"
    SERVICE_STOPPED        = "service_stopped"
    SERVICE_FAILED         = "service_failed"
    KERNEL_EVENT           = "kernel_event"
    CRON_JOB               = "cron_job"
    SYSTEM_ERROR           = "system_error"

    # Custom / sensitive file events
    FILE_ACCESS            = "file_access"
    FILE_MODIFIED          = "file_modified"
    SENSITIVE_COMMAND      = "sensitive_command"
    NETWORK_ANOMALY        = "network_anomaly"
    CUSTOM_ALERT           = "custom_alert"

    # New attack surface events
    PORT_SCAN              = "port_scan"
    NEW_USER_CREATED       = "new_user_created"
    CRON_MODIFICATION      = "cron_modification"

    # Fallback
    UNKNOWN                = "unknown"

# ──────────────────────────────────────────────
# Event status constants
# ──────────────────────────────────────────────
class EventStatus:
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"

# ──────────────────────────────────────────────
# Severity levels
# ──────────────────────────────────────────────
class Severity:
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

# ──────────────────────────────────────────────
# Risk score thresholds
# ──────────────────────────────────────────────
RISK_LOW_MAX      = 29
RISK_MEDIUM_MAX   = 59
RISK_HIGH_MAX     = 79
RISK_CRITICAL_MIN = 80

# ──────────────────────────────────────────────
# Aggregation window (seconds)
# ──────────────────────────────────────────────
AGGREGATION_WINDOW_SECONDS = 900  # 15 minutes

# ──────────────────────────────────────────────
# Detection thresholds
# ──────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD      = 5    # wrong-password failures on a real user to trigger alert
INVALID_USER_THRESHOLD     = 4    # distinct invalid-user attempts from same IP
SUSPICIOUS_HOUR_START      = 22   # 10 PM
SUSPICIOUS_HOUR_END        = 6    # 6 AM
SUDO_FAILURE_THRESHOLD     = 5    # sudo password failures before alert
PORT_SCAN_THRESHOLD        = 10   # distinct blocked ports before port-scan alert
