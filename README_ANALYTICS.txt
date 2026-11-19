SOEMS behavior analytics update
===============================
Files: app.py, face_verification.py, exam_locks.py, risk_analytics.py, requirements.txt

This update builds on SOEMS_focused_fixes.zip, NOT on the original app(3).py.
Back up your project and MySQL database before replacing files.
Copy these Python files into the same project folder.
No new database table is required for this first analytics version.

The teacher dashboard has a Behavior Reports link. It now displays a
per-attempt provisional risk score, trust score, category counts and
an exam-level summary. The scoring is a transparent heuristic, not a
probability of cheating and not suitable for automatic penalties.

IMPORTANT LIMITATIONS
- The risk engine only scores events already logged by the browser.
- A score of zero means no logged warning, not proof of honest behavior.
- The browser can be interrupted or manipulated; events may be missing.
- Existing logs without a 'started' marker may have ambiguous attempts.
- Current code has no authenticated server-side exam attempt ID.
- Current browser-based termination does not reliably enforce exam locks.
- MediaPipe face_landmarker.task is still required in the app directory.
- Webcam, MySQL, and browser behavior must be tested locally.
- Current login/password implementation is not production-ready.

Suggested next milestone: server-owned attempt IDs, durable autosave,
server-enforced exam locks, CSRF protection, hashed passwords,
calibration of behavior detectors, and a human review workflow.
