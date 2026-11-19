"""
exam_locks.py

Server-side enforcement of "3 security warnings terminates this exam
attempt permanently." A lock is keyed by (user_id, exam_key), so
locking the Final Exam for one student has no effect on their access
to the Midterm Exam, or on any other student's access to the Final
Exam.

Like face_verification.py, this module does not open its own database
connection — it reuses the `db` object app.py already creates.
"""


def is_exam_locked(db, user_id, exam_key):
    """True if this student has already been locked out of this exam."""
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT id FROM exam_locks WHERE user_id=%s AND exam_key=%s",
        (user_id, exam_key),
    )
    row = cursor.fetchone()
    cursor.close()
    return row is not None


def lock_exam(db, user_id, exam_key, reason="Terminated after 3 security warnings", commit=True):
    """
    Records a permanent lock for this student + exam. Safe to call more
    than once: the UNIQUE (user_id, exam_key) key plus INSERT IGNORE means
    a duplicate request never creates a second row or raises an error.

    Pass commit=False when the caller commits together with other changes
    (exam_attempts.terminate_attempt does this so both happen atomically).
    """
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "INSERT IGNORE INTO exam_locks (user_id, exam_key, reason) VALUES (%s, %s, %s)",
        (user_id, exam_key, reason),
    )
    if commit:
        db.commit()
    cursor.close()


def get_locked_exams(db, user_id):
    """Returns a set of exam_key strings this student is locked out of."""
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT exam_key FROM exam_locks WHERE user_id=%s",
        (user_id,),
    )
    rows = cursor.fetchall()
    cursor.close()
    return {row[0] for row in rows}
