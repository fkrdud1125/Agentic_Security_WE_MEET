"""정적 분석용 코드 표본. Flask 앱이 이 모듈을 불러오지 않는다."""

from markupsafe import Markup


def find_note(connection, title):
    query = "SELECT title FROM notes WHERE title = '" + title + "'"
    return connection.execute(query).fetchone()


def render_note(title):
    return Markup(title)
