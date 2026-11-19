"""
exam_attempts.py

Server-owned exam attempts. The browser no longer decides when an exam
starts, how much time is left, how many warnings were issued, or whether
a student may enter again. All of that is stored and enforced here.

Like face_verification.py and exam_locks.py, this module does not open its
own database connection; it uses the `db` object passed in by app.py.

Rules enforced:
  * One attempt per student per exam (UNIQUE user_id + exam_key).
  * A student can start only after a recent successful face verification
    (checked in app.py, which owns the session).
  * The deadline is fixed by the server when the attempt is created.
  * Warnings are counted by the server. The 4th violation terminates the
    attempt and writes a permanent lock (exam_locks), per student + exam.
  * Each attempt accepts exactly one submission (UNIQUE attempt_id), so
    duplicate or late browser requests cannot overwrite answers.
"""

import time

import mysql.connector

import exam_locks

MAX_WARNINGS = 3            # warnings shown; the next violation terminates
SUBMIT_GRACE_SECONDS = 120  # slow-network allowance after the deadline
FACE_VERIFY_TTL_SECONDS = 15 * 60

IN_PROGRESS = "in_progress"
TERMINATED = "terminated"


# ---------------------------------------------------------------- schema
def _column_exists(cursor, table, column):
    cursor.execute(
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=%s",
        (table, column),
    )
    return cursor.fetchone()[0] > 0


def ensure_schema(db):
    """Creates / upgrades the tables this module needs. Safe to run on every start."""
    cursor = db.cursor()
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS exam_attempts (
            id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            exam_key VARCHAR(50) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'in_progress',
            started_ts BIGINT NOT NULL,
            deadline_ts BIGINT NOT NULL,
            ended_ts BIGINT NULL,
            warning_count INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_attempt_user_exam (user_id, exam_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS exam_locks (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            exam_key VARCHAR(50) NOT NULL,
            reason VARCHAR(255) DEFAULT 'Terminated after 3 security warnings',
            locked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_user_exam (user_id, exam_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    # Link existing tables to an attempt (older rows keep attempt_id NULL).
    if not _column_exists(cursor, "behavior_events", "attempt_id"):
        cursor.execute("ALTER TABLE behavior_events ADD COLUMN attempt_id BIGINT NULL")
    if not _column_exists(cursor, "exam_submissions", "attempt_id"):
        cursor.execute(
            "ALTER TABLE exam_submissions ADD COLUMN attempt_id BIGINT NULL, "
            "ADD UNIQUE KEY uq_submission_attempt (attempt_id)"
        )
    db.commit()
    cursor.close()


# ---------------------------------------------------------------- reads
def _fresh(db):
    """End any open read snapshot so we see other connections' latest writes."""
    try:
        db.commit()
    except Exception:
        pass


_COLS = "id, user_id, exam_key, status, started_ts, deadline_ts, ended_ts, warning_count"


def _row_to_attempt(row):
    if not row:
        return None
    return {
        "id": int(row[0]), "user_id": int(row[1]), "exam_key": row[2],
        "status": row[3], "started_ts": int(row[4]), "deadline_ts": int(row[5]),
        "ended_ts": int(row[6]) if row[6] is not None else None,
        "warning_count": int(row[7]),
    }


def get_attempt(db, user_id, exam_key):
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT " + _COLS + " FROM exam_attempts WHERE user_id=%s AND exam_key=%s",
        (user_id, exam_key),
    )
    row = cursor.fetchone()
    cursor.close()
    return _row_to_attempt(row)


def get_attempt_for_user(db, attempt_id, user_id):
    """Returns the attempt only if it belongs to this student (ownership check)."""
    try:
        attempt_id = int(attempt_id)
    except (TypeError, ValueError):
        return None
    _fresh(db)
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT " + _COLS + " FROM exam_attempts WHERE id=%s AND user_id=%s",
        (attempt_id, user_id),
    )
    row = cursor.fetchone()
    cursor.close()
    return _row_to_attempt(row)


def get_exam_state(db, user_id, exam_key, now=None):
    """
    Returns (state, attempt):
      'locked'      - permanently locked out of this exam
      'completed'   - attempt already finished (submitted / time_up / late)
      'in_progress' - attempt exists and can be resumed
      'new'         - no attempt yet
    An in-progress attempt whose deadline (plus grace) has passed is closed here.
    """
    now = int(now if now is not None else time.time())
    _fresh(db)
    if exam_locks.is_exam_locked(db, user_id, exam_key):
        return "locked", get_attempt(db, user_id, exam_key)

    attempt = get_attempt(db, user_id, exam_key)
    if attempt is None:
        return "new", None
    if attempt["status"] == TERMINATED:
        return "locked", attempt
    if attempt["status"] != IN_PROGRESS:
        return "completed", attempt

    if now >= attempt["deadline_ts"] + SUBMIT_GRACE_SECONDS:
        _finish(db, attempt["id"], "time_up", now)
        attempt["status"] = "time_up"
        return "completed", attempt
    return "in_progress", attempt


def remaining_seconds(attempt, now=None):
    now = int(now if now is not None else time.time())
    return max(0, attempt["deadline_ts"] - now)


# --------------------------------------------------------------- writes
def create_attempt(db, user_id, exam_key, duration_seconds, now=None):
    """
    Creates the attempt. Returns (attempt, created). If two requests race,
    the UNIQUE key lets only one insert win; the other gets created=False.
    """
    now = int(now if now is not None else time.time())
    created = True
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO exam_attempts (user_id, exam_key, status, started_ts, deadline_ts) "
            "VALUES (%s, %s, 'in_progress', %s, %s)",
            (user_id, exam_key, now, now + int(duration_seconds)),
        )
        db.commit()
    except mysql.connector.IntegrityError:
        db.rollback()
        created = False
    finally:
        cursor.close()
    return get_attempt(db, user_id, exam_key), created


def _finish(db, attempt_id, status, now=None):
    """in_progress -> final status. Returns True if this call changed it."""
    now = int(now if now is not None else time.time())
    cursor = db.cursor()
    cursor.execute(
        "UPDATE exam_attempts SET status=%s, ended_ts=%s WHERE id=%s AND status='in_progress'",
        (status, now, attempt_id),
    )
    changed = cursor.rowcount > 0
    db.commit()
    cursor.close()
    return changed


def terminate_attempt(db, attempt, reason="Terminated after 3 security warnings", now=None):
    """
    Marks the attempt terminated AND writes the permanent lock in one commit.
    Safe to call repeatedly.
    """
    now = int(now if now is not None else time.time())
    cursor = db.cursor()
    cursor.execute(
        "UPDATE exam_attempts SET status='terminated', ended_ts=COALESCE(ended_ts, %s) "
        "WHERE id=%s AND status IN ('in_progress', 'terminated')",
        (now, attempt["id"]),
    )
    cursor.close()
    exam_locks.lock_exam(db, attempt["user_id"], attempt["exam_key"], reason, commit=False)
    db.commit()
    attempt["status"] = TERMINATED


def add_warning(db, attempt):
    """
    Server-side warning counter. Returns (warning_count, terminated).
    A violation that arrives when MAX_WARNINGS were already issued
    terminates the attempt (matches the on-screen 'final warning' rule).
    """
    cursor = db.cursor()
    cursor.execute(
        "UPDATE exam_attempts SET warning_count = warning_count + 1 "
        "WHERE id=%s AND status='in_progress' AND warning_count < %s",
        (attempt["id"], MAX_WARNINGS),
    )
    counted = cursor.rowcount > 0
    db.commit()
    cursor.close()

    if counted:
        fresh = get_attempt(db, attempt["user_id"], attempt["exam_key"])
        return fresh["warning_count"], False

    terminate_attempt(db, attempt, "Terminated after %d security warnings" % MAX_WARNINGS)
    return MAX_WARNINGS, True


def save_submission(db, attempt, client_status, answers_json, student_name,
                    username, exam_title, now=None):
    """
    Stores the single submission allowed for this attempt.
    Returns (final_status, duplicate).  The status is decided by the server,
    not by the browser.
    """
    now = int(now if now is not None else time.time())

    # Idempotent: a retry after a timeout must not fail or overwrite.
    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT status FROM exam_submissions WHERE attempt_id=%s", (attempt["id"],))
    existing = cursor.fetchone()
    cursor.close()
    if existing:
        return existing[0], True

    if client_status == "terminated" or attempt["status"] == TERMINATED:
        final = "terminated"
        terminate_attempt(db, attempt, "Terminated after %d security warnings" % MAX_WARNINGS, now)
    elif now > attempt["deadline_ts"] + SUBMIT_GRACE_SECONDS:
        final = "late"
        _finish(db, attempt["id"], "late", now)
    elif client_status == "time_up" and now >= attempt["deadline_ts"] - 10:
        final = "time_up"
        _finish(db, attempt["id"], "time_up", now)
    else:
        final = "submitted"
        _finish(db, attempt["id"], "submitted", now)

    elapsed = max(0, min(now, attempt["deadline_ts"] + SUBMIT_GRACE_SECONDS) - attempt["started_ts"])
    cursor = db.cursor()
    try:
        cursor.execute(
            """INSERT INTO exam_submissions
               (user_id, username, student_name, exam_title, status, answers,
                elapsed_seconds, attempt_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (attempt["user_id"], username, student_name, exam_title, final,
             answers_json, elapsed, attempt["id"]),
        )
        db.commit()
    except mysql.connector.IntegrityError:
        db.rollback()
        return final, True
    finally:
        cursor.close()
    return final, False


def reinstate(db, user_id, exam_key):
    """
    Teacher/admin action (UI comes in the review-workflow step): removes the
    lock and the attempt so the student may take the exam again.
    Their behavior events and submission rows are kept for the record.
    """
    cursor = db.cursor()
    cursor.execute("DELETE FROM exam_locks WHERE user_id=%s AND exam_key=%s", (user_id, exam_key))
    cursor.execute("DELETE FROM exam_attempts WHERE user_id=%s AND exam_key=%s", (user_id, exam_key))
    db.commit()
    cursor.close()
