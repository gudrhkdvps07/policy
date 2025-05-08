from datetime import datetime
from policy_dsl import evaluate_access_reason  

# 사용자 정보 (context["user"])
user = {
    "id": "hong123",
    "rank": 2,
    "dn": "CN=홍길동,OU=1학년,DC=school,DC=local",
    "ou": "OU=1학년,DC=school,DC=local",
    "groups": ["학생부", "정보부"]
}

# 파일 정보 (context["file"])
file_info = {
    "file_ou": "OU=1학년,DC=school,DC=local",
    "file_rank": 2,
    "file_path": "C:/문서/시험지.xlsx"
}

# 테스트용 정책 리스트 (in-memory)
policies = [
    {
        "policy_id": "test-policy-ou",
        "policy_type": "OU",
        "priority": 2,
        "rules": [
            {
                "id": "rule-deny-exe",
                "description": "실행파일 금지",
                "condition": {
                    "eq": ["file.extension", "exe"]
                },
                "action": {
                    "deny": "deny_all",
                    "allow": "",
                    "rank_override": None
                },
                "exception": {}
            },
            {
                "id": "rule-allow-default",
                "description": "기본 허용",
                "condition": {
                    "eq": ["file_ou", "OU=1학년,DC=school,DC=local"]
                },
                "action": {
                    "allow": "allow_all",
                    "deny": "",
                    "rank_override": None
                },
                "exception": {}
            }
        ],
        "policy_description": "기본 1학년 정책",
        "is_active": True,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
]

# 테스트 실행
result, reason = evaluate_access_reason(user, file_info, policies)

print("결과:", "허용" if result else "차단")
print("사유:", reason)
