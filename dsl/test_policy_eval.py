from datetime import datetime
from policy_dsl import evaluate_access_reason, get_file_metadata
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def run_test_case(test_name, user, file_info, policies, expected_result):
    file_info = get_file_metadata(file_info) 
    print(f"\n=== 테스트 케이스: {test_name} ===")
    print(f"사용자: {user}")
    print(f"파일: {file_info}")
    print(f"정책: {policies}")
    
    result, reason = evaluate_access_reason(user, file_info, policies)
    print(f"결과: {'허용' if result else '차단'}")
    print(f"사유: {reason}")
    print(f"예상 결과: {'허용' if expected_result else '차단'}")
    print("=" * 50)
    
    return result == expected_result

# --- 각 테스트 케이스 정의 ---
def test_basic_allow():
    user = {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]}
    file_info = {"file_path": "test.txt", "file_ou": "OU=IT", "file_rank": 2}
    policies = [{
        "policy_id": "POL001",
        "is_active": True,
        "rules": [{
            "id": "R001",
            "condition": {"eq": ["file.ou", "OU=IT"]},
            "action": {"allow": "allow_all"}
        }]
    }]
    return run_test_case("기본 허용 테스트", user, file_info, policies, True)

def test_deny_exe():
    user = {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]}
    file_info = {"file_path": "c://downloads/test.exe", "file_ou": "OU=IT", "file_rank": 2}
    policies = [{
        "policy_id": "POL002",
        "is_active": True,
        "rules": [{
            "id": "R002",
            "condition": {"eq": ["file.extension", "exe"]},
            "action": {"deny": "deny_all"}
        }]
    }]
    return run_test_case("실행파일 차단 테스트", user, file_info, policies, False)

def test_rank_restriction():
    user = {"id": "user1", "rank": 2, "ou": "OU=IT", "groups": ["IT_Staff"]}
    file_info = {"file_path": "secret.txt", "file_ou": "OU=IT", "file_rank": 3}
    policies = [{
        "policy_id": "POL003",
        "is_active": True,
        "rules": [{
            "id": "R003",
            "condition": {"ge": ["user.rank", "file.rank"]},
            "action": {"allow": "read_only"}
        }]
    }]
    return run_test_case("등급 제한 테스트", user, file_info, policies, False)

def test_exception_allow():
    user = {"id": "user1", "rank": 2, "ou": "OU=IT", "groups": ["IT_Staff"]}
    file_info = {"file_path": "secret.txt", "file_ou": "OU=IT", "file_rank": 3}
    policies = [{
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
    }]
    return run_test_case("예외 조건 테스트", user, file_info, policies, True)

def test_group_policy():
    user = {"id": "user1", "rank": 2, "ou": "OU=IT", "groups": ["Admin_Group"]}
    file_info = {"file_path": "admin.txt", "file_ou": "OU=IT", "file_rank": 2}
    policies = [{
        "policy_id": "POL005",
        "is_active": True,
        "rules": [{
            "id": "R005",
            "condition": {"in": ["user.groups", ["Admin_Group"]]},
            "action": {"allow": "allow_all"}
        }]
    }]
    return run_test_case("그룹 정책 테스트", user, file_info, policies, True)

def test_rank_override():
    user = {"id": "user1", "rank": 2, "ou": "OU=IT", "groups": ["IT_Staff"]}
    file_info = {"file_path": "secret.txt", "file_ou": "OU=IT", "file_rank": 3}
    policies = [{
        "policy_id": "POL006",
        "is_active": True,
        "rules": [{
            "id": "R006",
            "condition": {"eq": ["file.ou", "OU=IT"]},
            "action": {"rank_override": 4, "allow": "allow_all"}
        }]
    }]
    return run_test_case("등급 오버라이드 테스트", user, file_info, policies, True)

def test_complex_condition():
    user = {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff", "Admin_Group"]}
    file_info = {"file_path": "admin.txt", "file_ou": "OU=IT", "file_rank": 2}
    policies = [{
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
    }]
    return run_test_case("복합 조건 테스트", user, file_info, policies, True)

def test_inactive_policy():
    user = {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]}
    file_info = {"file_path": "test.txt", "file_ou": "OU=IT", "file_rank": 2}
    policies = [{
        "policy_id": "POL008",
        "is_active": False,
        "rules": [{
            "id": "R008",
            "condition": {"eq": ["file.ou", "OU=IT"]},
            "action": {"allow": "allow_all"}
        }]
    }]
    return run_test_case("비활성 정책 테스트", user, file_info, policies, False)

def test_multiple_policies():
    return run_test_case("다중 정책 테스트",
        {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]},
        {"file_path": "test.txt", "file_ou": "OU=IT", "file_rank": 2},
        [
            {
                "policy_id": "POL009",
                "priority": 200,  # 기본 OU 정책
                "is_active": True,
                "rules": [{
                    "id": "R009",
                    "condition": {"eq": ["file.ou", "OU=IT"]},
                    "action": {"deny": "deny_all"}
                }]
            },
            {
                "policy_id": "POL010",
                "priority": 100,  # 예외 LDAP 쿼리 정책
                "is_active": True,
                "rules": [{
                    "id": "R010",
                    "condition": {"eq": ["file.ou", "OU=IT"]},
                    "exception": {"allowed_users": ["user1"]},
                    "action": {"allow": "allow_all"}
                }]
            }
        ],
        True  # 예외 정책이 우선되어 허용
    )


def test_file_extension_restriction():
    user = {"id": "user1", "rank": 3, "ou": "OU=IT", "groups": ["IT_Staff"]}
    file_info = {"file_path": "test.pdf", "file_ou": "OU=IT", "file_rank": 2}
    policies = [{
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
    }]
    return run_test_case("파일 확장자 제한 테스트", user, file_info, policies, False)

# --- 테스트 실행 ---
def run_all_tests():
    tests = [
        ("기본 허용", test_basic_allow),
        ("실행파일 차단", test_deny_exe),
        ("등급 제한", test_rank_restriction),
        ("예외 조건", test_exception_allow),
        ("그룹 정책", test_group_policy),
        ("등급 오버라이드", test_rank_override),
        ("복합 조건", test_complex_condition),
        ("비활성 정책", test_inactive_policy),
        ("다중 정책", test_multiple_policies),
        ("파일 확장자 제한", test_file_extension_restriction)
    ]
    
    success_count = 0
    for name, func in tests:
        try:
            if func():
                success_count += 1
                print(f"✅ {name} 테스트 성공")
            else:
                print(f"❌ {name} 테스트 실패")
        except Exception as e:
            print(f"❌ {name} 테스트 예외 발생: {e}")
    
    print(f"\n테스트 결과: {success_count}/{len(tests)} 성공")

if __name__ == "__main__":
    run_all_tests()
