import logging
from policy_dsl_enum import evaluate_access_reason, prepare_file_context, AccessDecision

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# ─────────────────── 공통 러너 ───────────────────
def run_test_case(test_name, user, file_info, policies, expected: AccessDecision):
    """
    file_info: 반드시 file_name, file_ou, file_rank 포함.
               is_private, extension은 있으면 사용하고 prepare_file_context에서 추출/보강.
    """
    file_info = prepare_file_context(file_info)
    print(f"\n=== 테스트: {test_name} ===")

    # 디버그 출력을 위한 로그 캡처
    import io
    import contextlib
    debug_output = io.StringIO()
    with contextlib.redirect_stdout(debug_output):
        result = evaluate_access_reason(user, file_info, policies)

    ok = result == expected
    print(f"결과 ➜ {result.name} | 예상 ➜ {expected.name} | {'✅ PASS' if ok else '❌ FAIL'}")

    if not ok:
        print("📌 [디버그 정보]")
        print(f"📁 file_info: {file_info}")
        print(f"👤 user_info: {user}")
        print(f"📜 정책 수: {len(policies)}")
        for p in policies:
            print(f" - policy_id: {p.get('policy_id')}, priority: {p.get('priority')}, active: {p.get('is_active', True)}")
            for r in p.get("rules", []):
                print(f"   · rule_id: {r.get('id')}, condition: {r.get('condition')}, exception: {r.get('exception')}, action: {r.get('action')}")

        print("\n🧩 내부 평가 로그 (evaluate_access_reason 내부)")
        print(debug_output.getvalue())

    return ok


# ─────────────────── 테스트 케이스 ───────────────────
def test_basic_allow():
    return run_test_case(
        "기본 허용",
        {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_name": "test.txt", "file_ou": "OU=IT", "file_rank": 2},
        [{
            "policy_id": "POL001",
            "is_active": True,
            "rules": [{
                "id": "R001",
                "condition": {"eq": ["file.ou", "OU=IT"]},
                "action": {"allow": "allow_all"}
            }]
        }],
        AccessDecision.ALLOW_ALL
    )


def test_deny_exe():
    return run_test_case(
        "실행파일 차단",
        {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_name": "danger.exe", "file_ou": "OU=IT", "file_rank": 2},
        [{
            "policy_id": "POL002",
            "is_active": True,
            "rules": [{
                "id": "R002",
                "condition": {"eq": ["file.extension", "exe"]},
                "action": {"deny": "deny_all"}
            }]
        }],
        AccessDecision.DENY
    )


def test_rank_restriction():
    return run_test_case(
        "등급 제한 – 거부",
        {"id": "user1", "rank": 2, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_name": "secret.txt", "file_ou": "OU=IT", "file_rank": 3},
        [{
            "policy_id": "POL003",
            "is_active": True,
            "rules": [{
                "id": "R003",
                "condition": {"ge": ["user.rank", "file.rank"]},
                "action": {"allow": "read_only"}
            }]
        }],
        AccessDecision.DENY  # rank 부족
    )


def test_exception_allow():
    return run_test_case(
        "예외 허용",
        {"id": "user1", "rank": 2, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_name": "secret.txt", "file_ou": "OU=IT", "file_rank": 3},
        [{
            "policy_id": "POL004",
            "is_active": True,
            "rules": [{
                "id": "R004",
                "condition": {"eq": ["file.ou", "OU=IT"]},
                "exception": {
                    "allowed_users": ["user1"],
                    "allowed_groups": ["IT_Staff"]
                },
                "action": {"allow": "allow_all"}
            }]
        }],
        AccessDecision.ALLOW_ALL
    )


def test_group_policy():
    return run_test_case(
        "그룹 정책 허용",
        {"id": "user1", "rank": 2, "ou": "OU=IT", "groups": ["Admin_Group"]},
        {"file_name": "admin.txt", "file_ou": "OU=IT", "file_rank": 2},
        [{
            "policy_id": "POL005",
            "is_active": True,
            "rules": [{
                "id": "R005",
                "condition": {"in": ["user.groups", ["Admin_Group"]]},
                "action": {"allow": "allow_all"}
            }]
        }],
        AccessDecision.ALLOW_ALL
    )


def test_rank_override():
    return run_test_case(
        "rank_override 허용",
        {"id": "user1", "rank": 2, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_name": "secret.txt", "file_ou": "OU=IT", "file_rank": 3},
        [{
            "policy_id": "POL006",
            "is_active": True,
            "rules": [{
                "id": "R006",
                "condition": {"eq": ["file.ou", "OU=IT"]},
                "action": {"rank_override": 4, "allow": "allow_all"}
            }]
        }],
        AccessDecision.ALLOW_ALL
    )


def test_complex_condition():
    return run_test_case(
        "복합 조건 허용",
        {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff", "Admin_Group"]},
        {"file_name": "admin.txt", "file_ou": "OU=IT", "file_rank": 2},
        [{
            "policy_id": "POL007",
            "is_active": True,
            "rules": [{
                "id": "R007",
                "condition": {
                    "and": [
                        {"eq": ["file.ou", "OU=IT"]},
                        {"in": ["user.groups", ["Admin_Group"]]},
                        {"ge": ["user.rank", "file.rank"]}
                    ]
                },
                "action": {"allow": "allow_all"}
            }]
        }],
        AccessDecision.ALLOW_ALL
    )


def test_inactive_policy():
    return run_test_case(
        "비활성 정책 → 차단",
        {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_name": "test.txt", "file_ou": "OU=IT", "file_rank": 2},
        [{
            "policy_id": "POL008",
            "is_active": False,  # 비활성
            "rules": [{
                "id": "R008",
                "condition": {"eq": ["file.ou", "OU=IT"]},
                "action": {"allow": "allow_all"}
            }]
        }],
        AccessDecision.DENY
    )


def test_multiple_policies():
    return run_test_case(
        "다중 정책: 높은 priority allow",
        {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_name": "test.txt", "file_ou": "OU=IT", "file_rank": 2},
        [
            {
                "policy_id": "POL009",
                "priority": 200,
                "is_active": True,
                "rules": [{
                    "id": "R009",
                    "condition": {"eq": ["file.ou", "OU=IT"]},
                    "action": {"deny": "deny_all"}
                }]
            },
            {
                "policy_id": "POL010",
                "priority": 100,  # 더 높음
                "is_active": True,
                "rules": [{
                    "id": "R010",
                    "condition": {"eq": ["file.ou", "OU=IT"]},
                    "exception": {"allowed_users": ["user1"]},
                    "action": {"allow": "allow_all"}
                }]
            }
        ],
        AccessDecision.ALLOW_ALL
    )


def test_file_extension_restriction():
    return run_test_case(
        "PDF 금지",
        {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_name": "report.pdf", "file_ou": "OU=IT", "file_rank": 2},
        [{
            "policy_id": "POL011",
            "is_active": True,
            "rules": [{
                "id": "R011",
                "condition": {
                    "and": [
                        {"eq": ["file.ou", "OU=IT"]},
                        {"ne": ["file.extension", "pdf"]}
                    ]
                },
                "action": {"allow": "allow_all"}
            }]
        }],
        AccessDecision.DENY
    )


def test_personal_file_access():
    return run_test_case(
        "개인 파일 우선 허용",
        {"id": "user01", "rank": 1, "ou": "OU=ENG", "groups": ["Developers"]},
        {"file_name": "private.txt", "file_ou": "PRIVATE", "file_rank": 9999},
        [
            {
                "policy_id": "OU_DENY",
                "priority": 3,
                "is_active": True,
                "rules": [{
                    "id": "R_DENY",
                    "condition": {"eq": ["file.ou", "PRIVATE"]},
                    "action": {"deny": "deny_all"}
                }]
            },
            {
                "policy_id": "PERSONAL_POLICY",
                "priority": 1,
                "is_active": True,
                "rules": [{
                    "id": "R_PRIVATE",
                    "condition": {"eq": ["file.name", "private.txt"]},
                    "exception": {"allowed_users": ["user01"]},
                    "action": {"allow": "allow_all"}
                }]
            }
        ],
        AccessDecision.ALLOW_ALL
    )


def test_personal_overrides_ldap():
    return run_test_case(
        "개인 정책이 LDAP deny보다 우선",
        {"id": "user99", "rank": 4, "ou": "OU=SEC", "groups": ["Security_Team"]},
        {"file_name": "secret.txt", "file_ou": "OU=SEC", "file_rank": 3},
        [
            {
                "policy_id": "LDAP_DENY",
                "priority": 2,
                "is_active": True,
                "rules": [{
                    "id": "R_LDAP_DENY",
                    "condition": {"eq": ["file.ou", "OU=SEC"]},
                    "action": {"deny": "deny_all"}
                }]
            },
            {
                "policy_id": "PERSONAL_ALLOW",
                "priority": 1,
                "is_active": True,
                "rules": [{
                    "id": "R_PERSONAL",
                    "condition": {"eq": ["file.name", "secret.txt"]},
                    "exception": {"allowed_users": ["user99"]},
                    "action": {"allow": "allow_all"}
                }]
            }
        ],
        AccessDecision.ALLOW_ALL
    )


def test_rank_override_low_priority():
    return run_test_case(
        "low priority + rank_override 읽기 허용",
        {"id": "user42", "rank": 1, "ou": "OU=DATA", "groups": []},
        {"file_name": "confidential.docx", "file_ou": "OU=DATA", "file_rank": 5},
        [{
            "policy_id": "LOW_PRIORITY_ALLOW",
            "priority": 3,
            "is_active": True,
            "rules": [{
                "id": "R_OVERRIDE",
                "condition": {"eq": ["file.ou", "OU=DATA"]},
                "action": {"rank_override": 5, "allow": "read_only"}
            }]
        }],
        AccessDecision.READ_ONLY
    )


def test_personal_but_not_allowed():
    return run_test_case(
        "개인 조건 O, 예외 불만족 → DENY",
        {"id": "user44", "rank": 2, "ou": "OU=FIN", "groups": []},
        {"file_name": "private.txt", "file_ou": "PRIVATE", "file_rank": 9999},
        [{
            "policy_id": "PERSONAL_POLICY",
            "priority": 1,
            "is_active": True,
            "rules": [{
                "id": "R_DENIED_PERSONAL",
                "condition": {"eq": ["file.name", "private.txt"]},
                "exception": {"allowed_users": ["someone_else"]},
                "action": {"allow": "allow_all"}
            }]
        }],
        AccessDecision.DENY
    )


def test_private_flag_policy():
    """file.is_private == True 조건 정책 검증"""
    return run_test_case(
        "is_private 조건 허용",
        {"id": "user77", "rank": 1, "ou": "OU=SALES", "groups": []},
        {"file_name": "note.txt", "file_ou": "OU=SALES", "file_rank": 1, "is_private": True},
        [{
            "policy_id": "PRIVATE_FLAG",
            "priority": 1,
            "is_active": True,
            "rules": [{
                "id": "R_PRIVATE_FLAG",
                "condition": {"eq": ["file.is_private", True]},
                "exception": {"allowed_users": ["user77"]},
                "action": {"allow": "allow_all"}
            }]
        }],
        AccessDecision.ALLOW_ALL
    )


# ─────────────────── 실행 ───────────────────
def run_all_tests():
    tests = [
        test_basic_allow,
        test_deny_exe,
        test_rank_restriction,
        test_exception_allow,
        test_group_policy,
        test_rank_override,
        test_complex_condition,
        test_inactive_policy,
        test_multiple_policies,
        test_file_extension_restriction,
        test_personal_file_access,
        test_personal_overrides_ldap,
        test_rank_override_low_priority,
        test_personal_but_not_allowed,
        test_private_flag_policy
    ]

    success = sum(func() for func in tests)
    total = len(tests)
    print(f"\n총 성공: {success}/{total} ({'✅' if success == total else '❌'})")


if __name__ == "__main__":
    run_all_tests()
