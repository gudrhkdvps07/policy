import logging
import io
import contextlib
from policy_dsl_enum import evaluate_access_reason, prepare_file_context, AccessDecision

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def run_test_case(test_name, user, file_info, policies, expected):
    file_info = prepare_file_context(file_info)
    # 문자열 rank → int 변환 (예외 방지용)
    try:
        if isinstance(user.get("rank"), str):
            user["rank"] = int(user["rank"])
    except ValueError:
        pass

    print(f"\n=== 테스트: {test_name} ===")
    debug_output = io.StringIO()
    with contextlib.redirect_stdout(debug_output):
        result = evaluate_access_reason(user, file_info, policies)

    if result == expected:
        print(f"결과 ➜ {result.name} | 예상 ➜ {expected.name} | ✅ PASS")
    else:
        print(f"결과 ➜ {result.name} | 예상 ➜ {expected.name} | ❌ FAIL")
        print("📌 디버그 정보:")
        print(f"file_info: {file_info}")
        print(f"user_info: {user}")
        print("📜 내부 평가 로그:")
        print(debug_output.getvalue())
    return result == expected


# 테스트 케이스 정의
def test_cases():
    tests = []
    for i in range(1, 31):
        user = {"id": f"user{i}", "rank": i % 5 + 1, "dn": f"CN=user{i},OU=Dept", "ou": "OU=Dept", "groups": ["GroupA"]}
        file_info = {
            "file_name": f"file{i}.txt",
            "file_ou": "OU=Dept",
            "file_rank": (9999 if i in [5, 15] else (i % 5 + 1)),
            "is_private": (i == 5 or i == 15),
            "owner_user_id": f"user{i}" if i in [5, 15] else "userX"
        }
        policies = []

        if i == 1:
            policies = [{"policy_id": "POL_ALLOW", "priority": 3, "is_active": True,
                         "rules": [{"id": "R1", "condition": {"eq": ["file.ou", "OU=Dept"]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.ALLOW_ALL
        elif i == 2:
            file_info["file_name"] = "malware.exe"
            file_info["extension"] = "exe"
            policies = [{"policy_id": "POL_DENY_EXE", "priority": 2, "is_active": True,
                         "rules": [{"id": "R2", "condition": {"eq": ["file.extension", "exe"]}, "action": {"deny": "deny_all"}}]}]
            expected = AccessDecision.DENY
        elif i == 3:
            user["rank"] = 1
            file_info["file_rank"] = 3
            policies = [{"policy_id": "POL_RANK", "priority": 2, "is_active": True,
                         "rules": [{"id": "R3", "condition": {"ge": ["user.rank", "file.rank"]}, "action": {"allow": "read_only"}}]}]
            expected = AccessDecision.DENY
        elif i == 4:
            policies = [{"policy_id": "POL_EXCEPTION", "priority": 2, "is_active": True,
                         "rules": [{"id": "R4", "condition": {"eq": ["file.ou", "OU=Dept"]}, "exception": {"allowed_users": ["user4"]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.ALLOW_ALL
        elif i in [5, 15]:
            expected = AccessDecision.ALLOW_ALL
        elif i == 6:
            expected = AccessDecision.DENY
        elif i == 7:
            policies = [{"policy_id": "POL_INACTIVE", "priority": 2, "is_active": False,
                         "rules": [{"id": "R7", "condition": {"eq": ["file.ou", "OU=Dept"]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.DENY
        elif i == 8:
            user["groups"] = ["Admin"]
            policies = [{"policy_id": "POL_GROUP", "priority": 2, "is_active": True,
                         "rules": [{"id": "R8", "condition": {"in": ["user.groups", ["Admin"]]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.ALLOW_ALL
        elif i == 9:
            user["rank"] = 1
            file_info["file_rank"] = 5
            policies = [{"policy_id": "POL_OVR", "priority": 3, "is_active": True,
                         "rules": [{"id": "R9", "condition": {"eq": ["file.ou", "OU=Dept"]}, "action": {"rank_override": 5, "allow": "read_only"}}]}]
            expected = AccessDecision.READ_ONLY
        elif i == 21:
            user["id"] = "user21"
            policies = [{"policy_id": "POL_EX_USER", "priority": 2, "is_active": True,
                         "rules": [{"id": "R21", "condition": {"eq": ["file.ou", "OU=Dept"]}, "exception": {"allowed_users": ["user21"]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.ALLOW_ALL
        elif i == 22:
            user["groups"] = ["GroupX", "GroupY"]
            policies = [{"policy_id": "POL_GROUPS", "priority": 2, "is_active": True,
                         "rules": [{"id": "R22", "condition": {"in": ["user.groups", ["GroupY"]]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.ALLOW_ALL
        elif i == 23:
            user["rank"] = 1
            file_info["file_rank"] = 5
            policies = [{"policy_id": "POL_DENY_LOW_RANK", "priority": 2, "is_active": True,
                         "rules": [{"id": "R23", "condition": {"eq": ["file.ou", "OU=Dept"]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.DENY
        elif i == 24:
            policies = [
                {"policy_id": "POL_DENY_PRIORITY", "priority": 1, "is_active": True,
                 "rules": [{"id": "R24a", "condition": {"eq": ["file.ou", "OU=Dept"]}, "action": {"deny": "deny_all"}}]},
                {"policy_id": "POL_ALLOW_LOW", "priority": 5, "is_active": True,
                 "rules": [{"id": "R24b", "condition": {"eq": ["file.ou", "OU=Dept"]}, "action": {"allow": "allow_all"}}]}
            ]
            expected = AccessDecision.DENY
        elif i == 25:
            policies = [{"policy_id": "POL_TYPE_ERR", "priority": 3, "is_active": True,
                         "rules": [{"id": "R25", "condition": {"ge": ["user.rank", "non_integer"]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.DENY
        elif i == 26:
            user["groups"] = ["OtherGroup"]
            policies = [{
                "policy_id": "POL_NO_MATCH_GROUP",
                "priority": 2,
                "is_active": True,
                "rules": [{
                    "id": "R26",
                    "condition": {"eq": ["file.ou", "OU=Dept"]},
                    "exception": {
                        "allowed_groups": ["GroupZ"]
                    },
                    "action": {"allow": "allow_all"}
                }]
             }]
            expected = AccessDecision.DENY

        elif i == 27:
            user["rank"] = 3
            policies = [{"policy_id": "POL_RANK_ALLOW", "priority": 1, "is_active": True,
                         "rules": [{"id": "R27", "condition": {"eq": ["file.ou", "OU=Dept"]}, "exception": {"allowed_ranks": [3]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.ALLOW_ALL
        elif i == 28:
            user["rank"] = "3"
            policies = [{"policy_id": "POL_STR_RANK", "priority": 1, "is_active": True,
                         "rules": [{"id": "R28", "condition": {"eq": ["file.ou", "OU=Dept"]}, "exception": {"allowed_ranks": [3]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.ALLOW_ALL
        elif i == 29:
            policies = [{"policy_id": "POL_MATCH_NAME_ONLY", "priority": 2, "is_active": True,
                         "rules": [{"id": "R29", "condition": {"eq": ["file.ou", "WrongOU"]}, "exception": {"allowed_users": [f"user29"]}, "action": {"allow": "allow_all"}}]}]
            expected = AccessDecision.DENY
        elif i == 30:
            file_info["is_private"] = True
            file_info["owner_user_id"] = "someone_else"
            expected = AccessDecision.DENY
        else:
            expected = AccessDecision.DENY

        tests.append((f"TC_{i}", user, file_info, policies, expected))
    return tests


# 실행
if __name__ == "__main__":
    cases = test_cases()
    passed = 0
    for name, user, file_info, policies, expected in cases:
        if run_test_case(name, user, file_info, policies, expected):
            passed += 1
    print(f"\n총 성공: {passed}/{len(cases)} {'✅' if passed == len(cases) else '❌'}")
