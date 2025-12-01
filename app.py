import os
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)

# DB 파일 경로 (프로젝트 루트에 vuln.db 생성)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vuln.db")


def init_db():
    """사용자 테이블을 만들고, 기본 계정을 하나 넣어준다."""
    if os.path.exists(DB_PATH):
        return  # 이미 있으면 건너뜀

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
        """
    )

    # 테스트용 계정 (아이디: admin / 비번: admin123)
    cur.execute(
        "INSERT INTO users (username, password) VALUES ('admin', 'admin123');"
    )

    conn.commit()
    conn.close()
    print("[+] 초기 DB 생성 완료: 기본 계정 admin / admin123")


@app.route("/")
def index():
    # 홈 화면
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ✅ 안전한 쿼리 (파라미터 바인딩 사용)
        query = """
        SELECT id, username FROM users
        WHERE username = ? AND password = ?;
        """

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        try:
            # 값은 SQL 문자열에 직접 붙이지 않고,
            # 두 번째 인자 튜플로 "따로" 전달한다.
            cur.execute(query, (username, password))
            row = cur.fetchone()
        except Exception as e:
            conn.close()
            error = f"쿼리 실행 중 에러: {e}"
            return render_template("login.html", error=error)

        conn.close()

        if row:
            user_id, user_name = row
            return f"로그인 성공! 환영합니다, {user_name} (id={user_id})"
        else:
            error = "로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다."

    return render_template("login.html", error=error)



# 디버깅용: 등록된 모든 라우트 확인
@app.route("/routes")
def routes():
    output = []
    for rule in app.url_map.iter_rules():
        methods = ",".join(sorted(rule.methods - {"HEAD", "OPTIONS"}))
        output.append(f"{rule.rule}  [{methods}]")
    return "<br>".join(sorted(output))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
