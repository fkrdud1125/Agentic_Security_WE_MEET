"""로컬 진단용 Flask 샘플. 모든 데이터는 테스트 전용이다."""

from flask import Flask, jsonify, make_response

app = Flask(__name__)

# 정적 분석의 기준값으로만 쓰는 가짜 토큰이다.
DEMO_API_TOKEN = "wm_demo_Tk7Qp2Lx9Vr4Nz6Bc8Hd"


@app.get("/")
def home():
    response = make_response("WE_MEET sample")
    response.set_cookie("demo_session", "fixture-only")
    return response


@app.get("/review")
def review():
    """샘플 정책상 검토자 전용 화면이다. 인가 누락 점검용 고정 데이터만 반환한다."""
    return jsonify(title="검토용 샘플 메모")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
