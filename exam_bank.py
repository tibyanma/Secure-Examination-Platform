"""
exam_bank.py

Exams, questions, answer keys, automatic scoring and manual grading.

Like the other helper modules, this one does not open its own database
connection; app.py passes in the request's connection.

Question types (same four the exam page already supports):
  mcq    - one correct option; the student's answer is the option number (0, 1, ...)
  tf     - True/False; the answer is the text "true" or "false"
  match  - pairs (left term -> right term); the answer maps left number -> right number
  short  - free text; marked by the teacher (never by the computer)

Answer keys NEVER leave the server: for_student() strips them.

Table layout (uses the exams / questions / question_options tables you already had):
  exams            id, exam_key, title, duration_minutes  + status, created_by, created_at
  questions        id, exam_id, question_text, question_type, position  + marks, answer_key
  question_options id, question_id, option_text, is_correct             + match_text
      mcq   : one row per option (is_correct marks the right one)
      match : one row per pair   (option_text = left term, match_text = right term)
  answer_grades    teacher marks for short answers, one row per submission + question
  exam_submissions + auto_score, max_score, manual_pending
"""

import random
import re

import mysql.connector

QUESTION_TYPES = ("mcq", "tf", "match", "short")
STATUSES = ("draft", "published")
KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$")  # 3-50 characters, URL friendly

MAX_QUESTIONS = 100
MIN_OPTIONS, MAX_OPTIONS = 2, 8
MIN_PAIRS, MAX_PAIRS = 2, 8
MAX_QUESTION_TEXT = 2000
MAX_OPTION_TEXT = 500
MAX_MARKS = 100
MAX_DURATION_MINUTES = 600


# ---------------------------------------------------------------- schema
def _column_exists(cursor, table, column):
    cursor.execute(
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=%s",
        (table, column),
    )
    return cursor.fetchone()[0] > 0


def ensure_schema(db):
    """Creates / upgrades the exam tables. Safe to run on every start."""
    cursor = db.cursor()
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS exams (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            exam_key VARCHAR(50) NOT NULL,
            title VARCHAR(200) NOT NULL,
            duration_minutes INT NOT NULL DEFAULT 30,
            UNIQUE KEY exam_key (exam_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS questions (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            exam_id INT NOT NULL,
            question_text TEXT NOT NULL,
            question_type VARCHAR(20) NOT NULL DEFAULT 'mcq',
            position INT NOT NULL,
            KEY exam_id (exam_id),
            CONSTRAINT questions_ibfk_1 FOREIGN KEY (exam_id) REFERENCES exams (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS question_options (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            question_id INT NOT NULL,
            option_text VARCHAR(500) NOT NULL,
            is_correct TINYINT(1) NOT NULL DEFAULT 0,
            KEY question_id (question_id),
            CONSTRAINT question_options_ibfk_1 FOREIGN KEY (question_id) REFERENCES questions (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    # New columns on the tables you already have.
    additions = (
        ("exams", "status", "ALTER TABLE exams ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'published'"),
        ("exams", "created_by", "ALTER TABLE exams ADD COLUMN created_by INT NULL"),
        ("exams", "created_at", "ALTER TABLE exams ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"),
        ("questions", "marks", "ALTER TABLE questions ADD COLUMN marks INT NOT NULL DEFAULT 1"),
        ("questions", "answer_key", "ALTER TABLE questions ADD COLUMN answer_key TEXT NULL"),
        ("question_options", "match_text", "ALTER TABLE question_options ADD COLUMN match_text VARCHAR(500) NULL"),
        ("exam_submissions", "auto_score", "ALTER TABLE exam_submissions ADD COLUMN auto_score DECIMAL(7,2) NULL"),
        ("exam_submissions", "max_score", "ALTER TABLE exam_submissions ADD COLUMN max_score DECIMAL(7,2) NULL"),
        ("exam_submissions", "manual_pending", "ALTER TABLE exam_submissions ADD COLUMN manual_pending INT NOT NULL DEFAULT 0"),
    )
    for table, column, statement in additions:
        if not _column_exists(cursor, table, column):
            cursor.execute(statement)
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS answer_grades (
            id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            submission_id BIGINT NOT NULL,
            question_id INT NOT NULL,
            marks DECIMAL(6,2) NOT NULL,
            graded_by INT NULL,
            graded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_grade (submission_id, question_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    db.commit()
    cursor.close()


# ------------------------------------------------------------ validation
def _clean_text(value, limit):
    return str(value if value is not None else "").strip()[:limit + 1]


def validate_exam(data, creating, content_locked=False):
    """
    Checks a payload from the exam editor. Returns (clean, errors).
    content_locked: students already attempted this exam, so only the title and
    status may change (questions and duration are frozen).
    """
    errors = []
    data = data if isinstance(data, dict) else {}
    clean = {}

    title = _clean_text(data.get("title"), 200)
    if not title:
        errors.append("The exam needs a title.")
    elif len(title) > 200:
        errors.append("The title is too long (200 characters at most).")
    clean["title"] = title[:200]

    status = str(data.get("status", "draft"))
    if status not in STATUSES:
        errors.append("Status must be draft or published.")
    clean["status"] = status if status in STATUSES else "draft"

    if creating:
        key = str(data.get("key", "")).strip().lower()
        if not KEY_PATTERN.match(key):
            errors.append("The exam key must be 3-50 characters: lowercase letters, numbers and hyphens (for example: database-midterm).")
        clean["key"] = key

    if content_locked:
        return clean, errors

    try:
        duration = int(data.get("duration_minutes"))
    except (TypeError, ValueError):
        duration = 0
    if not 1 <= duration <= MAX_DURATION_MINUTES:
        errors.append("Duration must be between 1 and %d minutes." % MAX_DURATION_MINUTES)
    clean["duration_minutes"] = duration

    questions = data.get("questions")
    if not isinstance(questions, list) or not questions:
        errors.append("Add at least one question.")
        questions = []
    if len(questions) > MAX_QUESTIONS:
        errors.append("An exam can have at most %d questions." % MAX_QUESTIONS)
        questions = questions[:MAX_QUESTIONS]

    clean_questions = []
    for number, q in enumerate(questions, start=1):
        label = "Question %d: " % number
        if not isinstance(q, dict):
            errors.append(label + "invalid data.")
            continue
        qtype = str(q.get("type", ""))
        if qtype not in QUESTION_TYPES:
            errors.append(label + "unknown question type.")
            continue
        item = {"type": qtype}

        text = _clean_text(q.get("text"), MAX_QUESTION_TEXT)
        if not text:
            errors.append(label + "the question text is empty.")
        elif len(text) > MAX_QUESTION_TEXT:
            errors.append(label + "the text is too long (%d characters at most)." % MAX_QUESTION_TEXT)
        item["text"] = text[:MAX_QUESTION_TEXT]

        try:
            marks = int(q.get("marks"))
        except (TypeError, ValueError):
            marks = 0
        if not 1 <= marks <= MAX_MARKS:
            errors.append(label + "marks must be a whole number from 1 to %d." % MAX_MARKS)
        item["marks"] = marks

        if qtype == "mcq":
            options = q.get("options") if isinstance(q.get("options"), list) else []
            if not MIN_OPTIONS <= len(options) <= MAX_OPTIONS:
                errors.append(label + "use %d to %d options." % (MIN_OPTIONS, MAX_OPTIONS))
                options = options[:MAX_OPTIONS]
            cleaned, seen, correct = [], set(), 0
            for opt in options:
                opt = opt if isinstance(opt, dict) else {}
                otext = _clean_text(opt.get("text"), MAX_OPTION_TEXT)
                if not otext:
                    errors.append(label + "an option is empty.")
                elif len(otext) > MAX_OPTION_TEXT:
                    errors.append(label + "an option is too long.")
                elif otext.lower() in seen:
                    errors.append(label + "two options are identical.")
                seen.add(otext.lower())
                is_correct = bool(opt.get("correct"))
                correct += 1 if is_correct else 0
                cleaned.append({"text": otext[:MAX_OPTION_TEXT], "correct": is_correct})
            if correct != 1:
                errors.append(label + "mark exactly one option as correct.")
            item["options"] = cleaned
        elif qtype == "tf":
            answer = str(q.get("answer", "")).lower()
            if answer not in ("true", "false"):
                errors.append(label + "choose whether the statement is True or False.")
            item["answer"] = answer
        elif qtype == "match":
            pairs = q.get("pairs") if isinstance(q.get("pairs"), list) else []
            if not MIN_PAIRS <= len(pairs) <= MAX_PAIRS:
                errors.append(label + "use %d to %d pairs." % (MIN_PAIRS, MAX_PAIRS))
                pairs = pairs[:MAX_PAIRS]
            cleaned, lefts, rights = [], set(), set()
            for pair in pairs:
                pair = pair if isinstance(pair, dict) else {}
                left = _clean_text(pair.get("left"), MAX_OPTION_TEXT)
                right = _clean_text(pair.get("right"), MAX_OPTION_TEXT)
                if not left or not right:
                    errors.append(label + "every pair needs both a left and a right item.")
                elif len(left) > MAX_OPTION_TEXT or len(right) > MAX_OPTION_TEXT:
                    errors.append(label + "a pair item is too long.")
                if left.lower() in lefts or right.lower() in rights:
                    errors.append(label + "left items and right items must each be different from each other.")
                lefts.add(left.lower())
                rights.add(right.lower())
                cleaned.append({"left": left[:MAX_OPTION_TEXT], "right": right[:MAX_OPTION_TEXT]})
            item["pairs"] = cleaned
        else:  # short
            model = _clean_text(q.get("answer"), 3000)
            if len(model) > 3000:
                errors.append(label + "the model answer is too long.")
            item["answer"] = model[:3000]
        clean_questions.append(item)

    clean["questions"] = clean_questions
    return clean, errors


# ----------------------------------------------------------------- reads
_EXAM_COLS = "id, exam_key, title, duration_minutes, status, created_by"


def _exam_row(row):
    if not row:
        return None
    return {"id": int(row[0]), "key": row[1], "title": row[2], "duration_minutes": int(row[3]),
            "status": row[4], "created_by": row[5]}


def get_exam_by_key(db, exam_key):
    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT " + _EXAM_COLS + " FROM exams WHERE exam_key=%s", (exam_key,))
    row = cursor.fetchone()
    cursor.close()
    return _exam_row(row)


def get_exam_by_id(db, exam_id):
    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT " + _EXAM_COLS + " FROM exams WHERE id=%s", (exam_id,))
    row = cursor.fetchone()
    cursor.close()
    return _exam_row(row)


def get_title(db, exam_key):
    exam = get_exam_by_key(db, exam_key)
    return exam["title"] if exam else exam_key


def load_questions(db, exam_id):
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT id, question_text, question_type, position, marks, answer_key "
        "FROM questions WHERE exam_id=%s ORDER BY position, id", (exam_id,))
    rows = cursor.fetchall()
    questions, by_id = [], {}
    for qid, text, qtype, _pos, marks, answer in rows:
        q = {"id": int(qid), "type": qtype, "text": text, "marks": int(marks),
             "answer": answer, "options": [], "pairs": []}
        questions.append(q)
        by_id[q["id"]] = q
    if by_id:
        marks_ = ",".join(["%s"] * len(by_id))
        cursor.execute(
            "SELECT id, question_id, option_text, is_correct, match_text FROM question_options "
            "WHERE question_id IN (" + marks_ + ") ORDER BY id", tuple(by_id))
        for _oid, qid, text, is_correct, match_text in cursor.fetchall():
            q = by_id.get(int(qid))
            if not q:
                continue
            if q["type"] == "match":
                q["pairs"].append({"left": text, "right": match_text or ""})
            else:
                q["options"].append({"text": text, "correct": bool(is_correct)})
    cursor.close()
    return questions


def get_exam_full(db, exam_id):
    exam = get_exam_by_id(db, exam_id)
    if exam:
        exam["questions"] = load_questions(db, exam["id"])
    return exam


def list_exams(db, published_only=False):
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT e.id, e.exam_key, e.title, e.duration_minutes, e.status, "
        "(SELECT COUNT(*) FROM questions q WHERE q.exam_id = e.id), "
        "(SELECT COUNT(*) FROM exam_attempts a WHERE a.exam_key = e.exam_key), "
        "(SELECT COALESCE(SUM(q.marks), 0) FROM questions q WHERE q.exam_id = e.id) "
        "FROM exams e " + ("WHERE e.status = 'published' " if published_only else "") +
        "ORDER BY e.id DESC")
    exams = [{"id": int(r[0]), "key": r[1], "title": r[2], "duration_minutes": int(r[3]),
              "status": r[4], "question_count": int(r[5]), "attempt_count": int(r[6]),
              "total_marks": int(r[7])} for r in cursor.fetchall()]
    cursor.close()
    return exams


def attempt_count(db, exam_key):
    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT COUNT(*) FROM exam_attempts WHERE exam_key=%s", (exam_key,))
    n = int(cursor.fetchone()[0])
    cursor.close()
    return n


# ------------------------------------------------------ what students see
def match_order(question):
    """
    The right-hand items are shown in a fixed shuffled order (the same for every
    student), so the answer is not simply 'item 1 goes with item 1'.
    order[k] = index of the pair whose right item is shown at position k.
    """
    n = len(question["pairs"])
    order = list(range(n))
    rng = random.Random(question["id"] * 7919 + 17)
    for _ in range(25):
        rng.shuffle(order)
        if n < 2 or order != list(range(n)):
            break
    return order


def for_student(exam):
    """Exam in the format the exam page expects, WITHOUT any answer key."""
    out = {"duration_minutes": exam["duration_minutes"], "questions": []}
    for q in exam["questions"]:
        item = {"id": "q%d" % q["id"], "type": q["type"], "marks": q["marks"], "text": q["text"]}
        if q["type"] == "mcq":
            item["options"] = [o["text"] for o in q["options"]]
        elif q["type"] == "match":
            order = match_order(q)
            item["left"] = [p["left"] for p in q["pairs"]]
            item["right"] = [q["pairs"][i]["right"] for i in order]
        out["questions"].append(item)
    return out


# ---------------------------------------------------------------- scoring
def _as_int(value):
    try:
        if isinstance(value, bool):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def score_answers(questions, answers):
    """
    Marks everything the computer can mark.
    Returns {'auto_score', 'max_score', 'manual_pending', 'detail': {question_id: {...}}}.
    detail[...]['awarded'] is None for short answers (teacher marks those).
    """
    answers = answers if isinstance(answers, dict) else {}
    detail, auto_score, max_score, pending = {}, 0.0, 0, 0
    for q in questions:
        a = answers.get("q%d" % q["id"])
        marks = q["marks"]
        max_score += marks
        info = {"type": q["type"], "marks": marks, "awarded": 0.0, "status": "unanswered", "answer": a}

        if q["type"] == "mcq":
            correct_index = next((i for i, o in enumerate(q["options"]) if o["correct"]), None)
            chosen = _as_int(a)
            if chosen is not None:
                right = chosen == correct_index
                info["status"] = "correct" if right else "wrong"
                info["awarded"] = float(marks) if right else 0.0
        elif q["type"] == "tf":
            if a is not None and str(a).lower() in ("true", "false"):
                right = str(a).lower() == str(q["answer"]).lower()
                info["status"] = "correct" if right else "wrong"
                info["awarded"] = float(marks) if right else 0.0
        elif q["type"] == "match":
            order = match_order(q)
            n = len(q["pairs"])
            given = a if isinstance(a, dict) else {}
            if given:
                hits = 0
                for li in range(n):
                    if _as_int(given.get(str(li))) == order.index(li):
                        hits += 1
                info["awarded"] = round(marks * hits / n, 2)
                info["status"] = "correct" if hits == n else ("partial" if hits else "wrong")
                info["hits"], info["pairs"] = hits, n
        else:  # short
            if a is not None and str(a).strip():
                info["status"] = "needs_grading"
                info["awarded"] = None
                pending += 1
        if info["awarded"] is not None:
            auto_score += info["awarded"]
        detail[q["id"]] = info
    return {"auto_score": round(auto_score, 2), "max_score": max_score,
            "manual_pending": pending, "detail": detail}


def record_score(db, attempt_id, exam_key, answers):
    """Scores a stored submission and saves the automatic part. Returns the result or None."""
    exam = get_exam_by_key(db, exam_key)
    if not exam:
        return None
    result = score_answers(load_questions(db, exam["id"]), answers)
    cursor = db.cursor()
    cursor.execute(
        "UPDATE exam_submissions SET auto_score=%s, max_score=%s, manual_pending=%s WHERE attempt_id=%s",
        (result["auto_score"], result["max_score"], result["manual_pending"], attempt_id))
    db.commit()
    cursor.close()
    return result


# ----------------------------------------------------------- manual grades
def get_grades(db, submission_id):
    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT question_id, marks FROM answer_grades WHERE submission_id=%s", (submission_id,))
    grades = {int(r[0]): float(r[1]) for r in cursor.fetchall()}
    cursor.close()
    return grades


def save_grades(db, submission_id, questions, grades, teacher_id):
    """
    grades: {question_id: marks}. Only short-answer questions can be marked here and
    the marks must be between 0 and the question's marks. Returns a list of error strings.
    """
    short = {q["id"]: q for q in questions if q["type"] == "short"}
    errors, accepted = [], {}
    for raw_id, raw_marks in (grades or {}).items():
        qid = _as_int(raw_id)
        if qid not in short:
            errors.append("Question %s cannot be marked by hand." % raw_id)
            continue
        if raw_marks in (None, ""):
            continue
        try:
            marks = round(float(raw_marks), 2)
        except (TypeError, ValueError):
            errors.append("Marks for question %s must be a number." % raw_id)
            continue
        if not 0 <= marks <= short[qid]["marks"]:
            errors.append("Marks for question %s must be between 0 and %d." % (raw_id, short[qid]["marks"]))
            continue
        accepted[qid] = marks
    if errors:
        return errors
    cursor = db.cursor(buffered=True)
    for qid, marks in accepted.items():
        cursor.execute("SELECT id FROM answer_grades WHERE submission_id=%s AND question_id=%s", (submission_id, qid))
        if cursor.fetchone():
            cursor.execute("UPDATE answer_grades SET marks=%s, graded_by=%s WHERE submission_id=%s AND question_id=%s",
                           (marks, teacher_id, submission_id, qid))
        else:
            cursor.execute("INSERT INTO answer_grades (submission_id, question_id, marks, graded_by) VALUES (%s, %s, %s, %s)",
                           (submission_id, qid, marks, teacher_id))
    db.commit()
    cursor.close()
    return []


def list_submissions(db, exam_key):
    """Submissions of one exam with automatic score, manual score and grading progress."""
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT s.id, s.user_id, s.username, s.student_name, s.status, s.elapsed_seconds, s.submitted_at, "
        "s.auto_score, s.max_score, s.manual_pending, a.warning_count, "
        "(SELECT COALESCE(SUM(g.marks), 0) FROM answer_grades g WHERE g.submission_id = s.id), "
        "(SELECT COUNT(*) FROM answer_grades g WHERE g.submission_id = s.id) "
        "FROM exam_submissions s JOIN exam_attempts a ON a.id = s.attempt_id "
        "WHERE a.exam_key=%s ORDER BY s.submitted_at DESC, s.id DESC", (exam_key,))
    rows = []
    for r in cursor.fetchall():
        auto = float(r[7]) if r[7] is not None else None
        manual = float(r[11])
        rows.append({
            "id": int(r[0]), "user_id": r[1], "username": r[2], "name": r[3], "status": r[4],
            "elapsed": int(r[5] or 0), "submitted_at": r[6],
            "score": None if auto is None else round(auto + manual, 2),
            "max_score": float(r[8]) if r[8] is not None else None,
            "pending": max(0, int(r[9]) - int(r[12])), "warnings": int(r[10]),
        })
    cursor.close()
    return rows


def get_submission(db, submission_id):
    cursor = db.cursor(buffered=True)
    cursor.execute(
        "SELECT s.id, s.user_id, s.username, s.student_name, s.status, s.answers, s.submitted_at, "
        "a.exam_key FROM exam_submissions s JOIN exam_attempts a ON a.id = s.attempt_id WHERE s.id=%s",
        (submission_id,))
    r = cursor.fetchone()
    cursor.close()
    if not r:
        return None
    return {"id": int(r[0]), "user_id": r[1], "username": r[2], "name": r[3], "status": r[4],
            "answers": r[5], "submitted_at": r[6], "exam_key": r[7]}


# ------------------------------------------------------------------ writes
def _write_questions(cursor, exam_id, questions):
    for position, q in enumerate(questions, start=1):
        answer_key = q.get("answer") if q["type"] in ("tf", "short") else None
        cursor.execute(
            "INSERT INTO questions (exam_id, question_text, question_type, position, marks, answer_key) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (exam_id, q["text"], q["type"], position, q["marks"], answer_key or None))
        question_id = cursor.lastrowid
        if q["type"] == "mcq":
            for opt in q["options"]:
                cursor.execute(
                    "INSERT INTO question_options (question_id, option_text, is_correct, match_text) VALUES (%s, %s, %s, NULL)",
                    (question_id, opt["text"], 1 if opt["correct"] else 0))
        elif q["type"] == "match":
            for pair in q["pairs"]:
                cursor.execute(
                    "INSERT INTO question_options (question_id, option_text, is_correct, match_text) VALUES (%s, %s, 0, %s)",
                    (question_id, pair["left"], pair["right"]))


def _delete_questions(cursor, exam_id):
    cursor.execute("DELETE FROM question_options WHERE question_id IN (SELECT id FROM questions WHERE exam_id=%s)", (exam_id,))
    cursor.execute("DELETE FROM questions WHERE exam_id=%s", (exam_id,))


def create_exam(db, clean, created_by):
    """clean = output of validate_exam(creating=True). Returns the new exam id."""
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO exams (exam_key, title, duration_minutes, status, created_by) VALUES (%s, %s, %s, %s, %s)",
            (clean["key"], clean["title"], clean["duration_minutes"], clean["status"], created_by))
        exam_id = cursor.lastrowid
        _write_questions(cursor, exam_id, clean["questions"])
        db.commit()
        return exam_id
    except mysql.connector.IntegrityError:
        db.rollback()
        raise ValueError("An exam with the key '%s' already exists. Choose a different key." % clean["key"])
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()


def update_exam(db, exam, clean, content_locked):
    """
    Saves the editor. When content_locked (students already attempted it) only the
    title and status change, so stored answers always match the questions they answered.
    """
    cursor = db.cursor()
    try:
        if content_locked:
            cursor.execute("UPDATE exams SET title=%s, status=%s WHERE id=%s",
                           (clean["title"], clean["status"], exam["id"]))
        else:
            cursor.execute("UPDATE exams SET title=%s, status=%s, duration_minutes=%s WHERE id=%s",
                           (clean["title"], clean["status"], clean["duration_minutes"], exam["id"]))
            _delete_questions(cursor, exam["id"])
            _write_questions(cursor, exam["id"], clean["questions"])
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()


def question_count(db, exam_id):
    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT COUNT(*) FROM questions WHERE exam_id=%s", (exam_id,))
    n = int(cursor.fetchone()[0])
    cursor.close()
    return n


def set_status(db, exam, status):
    """Returns an error string, or None on success."""
    if status not in STATUSES:
        return "Status must be draft or published."
    if status == "published" and question_count(db, exam["id"]) == 0:
        return "Add at least one question before publishing."
    cursor = db.cursor()
    cursor.execute("UPDATE exams SET status=%s WHERE id=%s", (status, exam["id"]))
    db.commit()
    cursor.close()
    return None


def delete_exam(db, exam):
    """Only exams nobody has attempted can be deleted. Returns an error string or None."""
    if attempt_count(db, exam["key"]) > 0:
        return "Students have already attempted this exam, so it cannot be deleted. Unpublish it instead."
    cursor = db.cursor()
    try:
        _delete_questions(cursor, exam["id"])
        cursor.execute("DELETE FROM exams WHERE id=%s", (exam["id"],))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()
    return None


def duplicate_exam(db, exam_id, created_by):
    """Copies an exam (as a draft) so its questions can be changed. Returns the new exam id or None."""
    source = get_exam_full(db, exam_id)
    if not source:
        return None
    questions = []
    for q in source["questions"]:
        item = {"type": q["type"], "text": q["text"], "marks": q["marks"]}
        if q["type"] == "mcq":
            item["options"] = [dict(o) for o in q["options"]]
        elif q["type"] == "match":
            item["pairs"] = [dict(p) for p in q["pairs"]]
        else:
            item["answer"] = q["answer"] or ""
        questions.append(item)
    base = source["key"][:42]
    for n in range(1, 100):
        key = "%s-copy" % base if n == 1 else "%s-copy-%d" % (base, n)
        if get_exam_by_key(db, key) is None:
            break
    clean = {"key": key, "title": (source["title"] + " (copy)")[:200], "status": "draft",
             "duration_minutes": source["duration_minutes"], "questions": questions}
    return create_exam(db, clean, created_by)


# ------------------------------------------------------------------- seeds
SEED_QUESTIONS = [
    {"type": "mcq", "marks": 2, "text": "Which SQL command is used to retrieve data from a database?",
     "options": ["INSERT", "SELECT", "UPDATE", "DELETE"], "correct": 1},
    {"type": "mcq", "marks": 2, "text": "What is the main purpose of a PRIMARY KEY?",
     "options": ["To encrypt a table", "To uniquely identify each row", "To sort the table alphabetically", "To delete duplicate tables"], "correct": 1},
    {"type": "mcq", "marks": 2, "text": "Which normal form removes partial dependency?",
     "options": ["First normal form (1NF)", "Second normal form (2NF)", "Third normal form (3NF)", "Boyce-Codd normal form (BCNF)"], "correct": 1},
    {"type": "mcq", "marks": 2, "text": "Which SQL clause is used to filter records?",
     "options": ["GROUP BY", "ORDER BY", "WHERE", "LIMIT"], "correct": 2},
    {"type": "mcq", "marks": 2, "text": "Which keyword is used to sort the result set?",
     "options": ["SORT", "ORDER BY", "ARRANGE", "GROUP"], "correct": 1},
    {"type": "mcq", "marks": 2, "text": "Which of the following is a relational database management system?",
     "options": ["MySQL", "Photoshop", "Excel Charts", "Notepad"], "correct": 0},
    {"type": "tf", "marks": 1, "text": "A table can have more than one primary key.", "answer": "false"},
    {"type": "tf", "marks": 1, "text": "A foreign key creates a link between two tables.", "answer": "true"},
    {"type": "tf", "marks": 1, "text": "The DELETE command removes the whole table structure from the database.", "answer": "false"},
    {"type": "tf", "marks": 1, "text": "NULL is the same as zero.", "answer": "false"},
    {"type": "match", "marks": 4, "text": "Match each SQL command with its purpose.",
     "pairs": [("SELECT", "Retrieve data"), ("INSERT", "Add a new row"), ("UPDATE", "Modify existing rows"), ("DELETE", "Remove rows")]},
    {"type": "match", "marks": 4, "text": "Match each database term with its definition.",
     "pairs": [("Primary key", "Uniquely identifies a row"), ("Foreign key", "Links a table to another table"),
               ("Index", "Speeds up searching"), ("View", "A virtual table built from a query")]},
    {"type": "short", "marks": 4, "text": "Define a database in one or two sentences.",
     "answer": "An organised collection of related data stored so it can be easily accessed, managed and updated."},
    {"type": "short", "marks": 4, "text": "Explain the difference between the DELETE and DROP commands.",
     "answer": "DELETE removes rows (the table remains); DROP removes the whole table structure."},
    {"type": "short", "marks": 4, "text": "Write an SQL query that returns all columns of every row from a table named students.",
     "answer": "SELECT * FROM students;"},
]


def _seed_payload():
    questions = []
    for q in SEED_QUESTIONS:
        item = {"type": q["type"], "marks": q["marks"], "text": q["text"]}
        if q["type"] == "mcq":
            item["options"] = [{"text": t, "correct": i == q["correct"]} for i, t in enumerate(q["options"])]
        elif q["type"] == "match":
            item["pairs"] = [{"left": l, "right": r} for l, r in q["pairs"]]
        else:
            item["answer"] = q["answer"]
        questions.append(item)
    return questions


def seed_if_empty(db):
    """First run only: create the two sample exams (midterm, final) so the app is usable at once."""
    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT COUNT(*) FROM exams")
    empty = int(cursor.fetchone()[0]) == 0
    cursor.close()
    if not empty:
        return False
    for key, title in (("midterm", "Midterm Examination"), ("final", "Final Examination")):
        data = {"key": key, "title": title, "status": "published", "duration_minutes": 30,
                "questions": _seed_payload()}
        clean, errors = validate_exam(data, creating=True)
        if errors:
            raise RuntimeError("Sample exam is invalid: %s" % errors)
        create_exam(db, clean, None)
    return True
