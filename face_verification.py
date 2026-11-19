"""
face_verification.py

Handles storage and comparison of face descriptors for the
Secure Examination Platform.

IMPORTANT: no raw images or video frames are ever handled here.
A "descriptor" is a list of 128 floating point numbers produced
in the browser by face-api.js. It mathematically represents a
face but cannot be turned back into a photo, which is why this
is the reference representation stored in the database instead
of a picture.

This module does not create its own database connection. It
reuses the same `db` (mysql.connector) connection object that
app.py already creates and passes in, per the project's
requirement not to introduce a second DB connection.
"""

import json
import math

# face-api.js's own documentation recommends 0.6 as the
# standard match/no-match cutoff for its 128-point descriptors.
# Lower distance = more similar faces. This is not a percentage.
DISTANCE_THRESHOLD = 0.6


def euclidean_distance(a, b):
    """Plain Python distance between two descriptors. No numpy needed."""
    if len(a) != len(b):
        raise ValueError("Descriptor length mismatch")
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def get_reference_descriptor(db, user_id):
    """Returns the stored descriptor (as a Python list) for a user, or None."""
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT descriptor FROM face_references WHERE user_id=%s "
        "ORDER BY id DESC LIMIT 1",
        (user_id,),
    )
    row = cursor.fetchone()
    cursor.close()

    if not row:
        return None

    return json.loads(row[0])


def save_reference_descriptor(db, user_id, descriptor):
    """
    Stores (or replaces) a student's reference descriptor.

    A student can only ever have one active reference. Re-enrolling
    replaces the old one rather than piling up rows, since old
    reference faces serve no purpose once replaced.
    """
    if not isinstance(descriptor, list) or len(descriptor) != 128:
        raise ValueError("Invalid descriptor: expected a list of 128 numbers")

    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT id FROM face_references WHERE user_id=%s LIMIT 1", (user_id,))
    existing = cursor.fetchone()
    if existing:
        cursor.execute("UPDATE face_references SET descriptor=%s WHERE user_id=%s", (json.dumps(descriptor), user_id))
    else:
        cursor.execute("INSERT INTO face_references (user_id, descriptor) VALUES (%s, %s)", (user_id, json.dumps(descriptor)))
    db.commit()
    cursor.close()


def verify_descriptor(db, user_id, live_descriptor):
    """
    Compares a freshly captured live descriptor against the student's
    stored reference.

    Returns a tuple: (is_match: bool, detail: str)
    detail is either "no_reference", or the numeric distance as a string
    (useful for debugging/logging, not shown to the student as a raw number).
    """
    if not isinstance(live_descriptor, list) or len(live_descriptor) != 128:
        return False, "invalid_descriptor"

    reference = get_reference_descriptor(db, user_id)
    if reference is None:
        return False, "no_reference"

    distance = euclidean_distance(reference, live_descriptor)
    is_match = distance < DISTANCE_THRESHOLD
    return is_match, f"{distance:.4f}"
