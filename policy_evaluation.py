import sqlite3
import json
import logging

# 로그 설정: INFO 이상의 로그만 출력되며, 모듈 이름 기준으로 구분 가능하게 설정함
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------
# 1. 정책 로딩 함수
# ---------------------------------------------------
def load_policies(db_path="policy.db"):
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT policy_json FROM policies WHERE is_active = 1")
        rows = cur.fetchall()
        conn.close()
        policies = [json.loads(row[0]) for row in rows]
        logger.info(f"[정책 로드 성공] {len(policies)}개 정책 로드됨 (DB={db_path})")
        return policies
    except Exception as error:
        logger.error(f"[정책 로드 실패] DB={db_path}, 오류: {error}")
        raise

# ---------------------------------------------------
# 2. 사용자 정보 조회 함수
# ---------------------------------------------------
def get_user_info(user_id, db_path="policy.db"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT rank, dn, ou, groups_json FROM users WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise ValueError(f"사용자 {user_id} 정보를 찾을 수 없음")
    return {
        "id": user_id,
        "rank": row[0],
        "dn": row[1],
        "ou": row[2],
        "groups": json.loads(row[3])
    }

# ---------------------------------------------------
# 3. 파일 메타데이터 조회 함수
# ---------------------------------------------------
def get_file_metadata(file_path, db_path="policy.db"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT file_ou, file_rank FROM files WHERE path = ?", (file_path,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise ValueError(f"파일 {file_path} 메타데이터 없음")
    return {
        "file_ou": row[0],
        "file_rank": row[1],
        "file_path": file_path
    }

# ---------------------------------------------------
# 4. 정책 적용 여부 판단 함수
# ---------------------------------------------------
def is_policy_applicable(policy_type, policy, user, file_info, ad_groups):
    if policy_type == "Public":
        return True
    elif policy_type == "OU":
        return file_info.get("file_ou") == policy.get("target_dn")
    elif policy_type == "Group":
        return policy.get("target_name") in ad_groups
    elif policy_type == "GPO":
        target_dn = policy.get("target_dn", "")
        target_name = policy.get("target_name", "")
        if target_dn:
            return user.get("ou") == target_dn or user.get("dn", "").endswith(target_dn)
        elif target_name:
            return target_name == user.get("id") or target_name in ad_groups
    return False

# ---------------------------------------------------
# 5. 예외 조건 만족 여부 판단 함수
# ---------------------------------------------------
def evaluate_exceptions(user, user_groups, exception):
    allowed_users = exception.get("allowed_users", [])
    allowed_groups = exception.get("allowed_groups", [])
    allowed_ous = exception.get("allowed_ous", [])
    allowed_ranks = exception.get("allowed_ranks")

    if allowed_users and user["id"] not in allowed_users:
        return False
    if allowed_groups and not any(group in user_groups for group in allowed_groups):
        return False
    if allowed_ous and user.get("ou") not in allowed_ous:
        return False
    if allowed_ranks is not None:
        try:
            return user.get("rank", 0) >= int(allowed_ranks)
        except (ValueError, TypeError):
            return False

    return True

# ---------------------------------------------------
# 6. 접근 평가 메인 함수
# ---------------------------------------------------
def evaluate_access_reason(user, file_info, policies):
    file_rank = file_info.get("file_rank")
    user_rank = user.get("rank", 0)
    ad_groups = user.get("groups", [])
    priority_order = ["GPO", "Group", "OU", "Public"]

    for policy_type in priority_order:
        for policy in [p for p in policies if p["policy_type"] == policy_type and p["is_active"]]:
            if not is_policy_applicable(policy_type, policy, user, file_info, ad_groups):
                continue

            policy_id = policy.get("policy_id", "unknown")
            action = policy.get("action", {})
            exception = policy.get("exception", {})

            # GPO 정책에서 rank_override 처리
            effective_rank = user_rank
            if policy_type == "GPO" and "rank_override" in action:
                try:
                    effective_rank = int(action["rank_override"])
                except ValueError:
                    pass

            if file_rank is not None and effective_rank < file_rank:
                continue

            if exception:
                if evaluate_exceptions(user, ad_groups, exception):
                    return True, f"허용됨: 예외 조건 만족 (policy={policy_id})"
                else:
                    continue  # 예외 조건 있음 → 만족 못 하면 무시

            if action.get("deny") == "deny_all":
                return False, f"차단됨: 정책({policy_id})에서 deny_all 명시됨"

            if action.get("allow") in ["read_only", "allow_all"]:
                return True, f"허용됨: 정책({policy_id})에서 {action.get('allow')} 허용됨"

    return False, "차단됨: 적용 가능한 정책 없음 또는 허용 조건 없음"

# ---------------------------------------------------
# 7. 외부 진입 함수 (DLL 호출 지점)
# ---------------------------------------------------
def evaluate_file_access(user_id, file_path, db_path="policy.db") -> bool:
    user_info = get_user_info(user_id, db_path)
    file_info = get_file_metadata(file_path, db_path)
    policies = load_policies(db_path)
    result, reason = evaluate_access_reason(user_info, file_info, policies)
    logger.info(f"[접근 평가 결과] user={user_id}, file={file_path}, result={'ALLOW' if result else 'DENY'} ({reason})")
    return result
