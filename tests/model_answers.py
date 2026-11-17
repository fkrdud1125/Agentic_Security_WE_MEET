"""Contract fixtures for the fake provider, never production responses."""

from vibescan.analysis import CHECKS


def plan_answer(data=None):
    sources = data.get("sources", []) if data else []
    return {"summary": "제공된 코드에서 라우트와 데이터 접근 단서를 확인했습니다. 런타임은 미확인입니다.",
            "surfaces": [{"id": s["id"], "note": "코드 단서 확인 · 호출 경로는 별도 검토 필요"} for s in sources],
            "checks": [{"id": key, "reason": "제공된 소스 범위에서 점검합니다.", "source_ids": []} for key in CHECKS]}


def review_answer(data):
    return {"reviews": [{"id": item["id"], "decision": "keep", "severity": item["severity"],
                         "impact": "외부 입력 경로 확인이 필요합니다.", "fix": "문맥에 맞는 수정을 검토하세요.",
                         "reason": "정적 패턴은 있으나 실제 호출은 확인되지 않았습니다.",
                         "confidence": "Potential", "replacement": None} for item in data]}
