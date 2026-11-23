"""Attach external observations without rewriting static or AI execution history."""


def attach(criteria, checks):
    for row in criteria:
        row['checks'] = [check for check in checks if row['code'] in check.get(row['framework'], [])]
        if not any(check['kind'] == 'runtime' for check in row['checks']):
            row['checks'].append({'id': 'runtime-not-configured', 'kind': 'runtime',
                                  'state': 'skipped', 'outcome': 'unassessed',
                                  'reason': '이 기준의 HTTP 검증 시나리오 미설정', 'evidence': []})
    return criteria
