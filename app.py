from flask import Flask, request
import mysql.connector
app=Flask(__name__)
db=mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="secure_exam_db"
)
@app.route("/")
def home():
    return"""
    <h1>Secure Online Examination Platform</h1>
    <h2>Welcome</h2>
    <p>Please Select You Role</p>
    <a href="/student"><button>Student</button></a>
    <a href="/teacher"><button>teacher</button></a>
    """
@app.route("/student", methods=["GET", "POST"])
def student():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        cursor = db.cursor(buffered=True)
        cursor.execute(
            "SELECT * FROM users WHERE username=%s AND password=%s AND role='student'",
            (username, password)
        )

        user = cursor.fetchone()
        cursor.close()

        if user:
            return """
            <html>
            <head>
                <title>Student Exam</title>
            </head>

            <body>
                <h1>Welcome Student</h1>

                <p>Before starting the exam, camera access is required.</p>

                <button onclick="startCamera()">Start Camera Test</button>

                <br><br>

                <video id="camera" width="500" autoplay></video>

                <script>
                    async function startCamera() {
                        try {
                            const stream = await navigator.mediaDevices.getUserMedia({
                                video: true,
                                audio: true
                            });

document.getElementById("camera").srcObject = stream;

                       } catch (error) {
                           alert("Camera and microphone access was denied.");
console.log(error);
                       }
                     }
                 </script>

             </body>
             </html>
             """

        return "<h1>Invalid username or password</h1>"

    return """
    <h1>Student Login</h1>

    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    """


@app.route("/teacher", methods=["GET", "POST"])
def teacher():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        cursor = db.cursor(buffered=True)

        cursor.execute(
            "SELECT * FROM users WHERE username=%s AND password=%s AND role='teacher'",
            (username, password)
        )

        user = cursor.fetchone()
        cursor.close()

        if user:
            return """
            <html>
            <head>
                <title>Teacher Dashboard</title>
            </head>

            <body>

                <h1>Welcome Teacher</h1>

                <h2>My Courses</h2>

                <ul>
                    <li>
                        <a href="/course/database">
                            Database Management
                        </a>
                    </li>

                    <li>
                        <a href="/course/mis">
                            Management Information Systems
                        </a>
                    </li>

                    <li>
                        <a href="/course/python">
                            Python Programming
                        </a>
                    </li>
                </ul>

            </body>
            </html>
            """

        return "<h1>Invalid username or password</h1>"

    return """
    <h1>Teacher Login</h1>

    <form method="POST">

        <input type="text"
               name="username"
               placeholder="Username"
               required>

        <input type="password"
               name="password"
               placeholder="Password"
               required>

        <button type="submit">Login</button>

    </form>
    """
@app.route("/course/<course_name>")
def course(course_name):

    return f"""
    <html>

    <head>
        <title>Course Details</title>
    </head>

    <body>

        <h1>{course_name}</h1>

        <h2>Course Information</h2>

        <p>Teacher: Teacher</p>

        <h2>Reference</h2>
        <p>Course Reference Book</p>

        <h2>Lectures</h2>

        <ul>
            <li>Lecture 1</li>
            <li>Lecture 2</li>
            <li>Lecture 3</li>
        </ul>

        <h2>Recordings</h2>

        <ul>
            <li>Lecture Recording 1</li>
            <li>Lecture Recording 2</li>
        </ul>

        <h2>Exams</h2>

        <button>Add Exam</button>

        <br><br>

        <button>Dashboard</button>

    </body>

    </html>
    """
if __name__=="__main__":
    app.run(debug=True)