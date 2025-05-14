import sqlite3
import json
import logging
import os
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AccessDecision(Enum):
    DENY = "deny_all"
    READ_ONLY = "read_only"
    ALLOW_ALL = "allow_all"

def load_policies(db_path="policy.db"):
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT policy_json FROM policies WHERE is_active = 1")
        rows = cur.fetchall()
        conn.close()
        return [json.loads(row[0]) for row in rows]
    except Exception as error:
        logger.error(f"[정책 로드 실패] DB={db_path}, 오류: {error}")
        raise

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

def get_file_metadata(dll_file_path, db_path="policy.db"):
    file_name = os.path.basename(dll_file_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT file_ou, file_rank, is_private, owner_user_id FROM files WHERE file_name = ?",
        (file_name,)
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        raise ValueError(f"파일 {file_name} 메타데이터 없음")
    return {
        "file_ou": row[0],
        "file_rank": row[1],
        "is_private": bool(row[2]),
        "owner_user_id": row[3],
        "file_name": file_name
    }

def prepare_file_context(file_info: dict) -> dict:
    file_name = file_info.get("file_name", "")
    ext = os.path.splitext(file_name)[1].lower().lstrip(".")
    file_info["extension"] = ext
    file_info["rank"] = file_info.get("file_rank")
    file_info["ou"] = file_info.get("file_ou")
    file_info["is_private"] = file_info.get("is_private", False)
    file_info["name"] = file_name
    return file_info

def get_value_by_path(field_path: str, context: dict):
    logger.debug(f"Resolving field: {field_path}")
    parts = field_path.split(".")
    current = context
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current

def evaluate_condition(condition: dict, context: dict) -> bool:
    logger.debug(f"Evaluating condition: {condition}")
    if "and" in condition:
        return all(evaluate_condition(c, context) for c in condition["and"])
    if "or" in condition:
        return any(evaluate_condition(c, context) for c in condition["or"])
    if "not" in condition:
        return not evaluate_condition(condition["not"], context)

    for op, args in condition.items():
        if not isinstance(args, list) or len(args) != 2:
            continue
        field, value = args
        left = get_value_by_path(field, context) if isinstance(field, str) and "." in field else field
        right = get_value_by_path(value, context) if isinstance(value, str) and "." in value else value
        if left is None:
            return False
        if op == "eq":
            return str(left) == str(right)
        if op == "ne":
            return str(left) != str(right)
        if op in ["ge", "gt", "le", "lt"]:
            try:
                left = int(left)
                right = int(right)
            except (ValueError, TypeError):
                return False
            if op == "ge":
                return left >= right
            if op == "gt":
                return left > right
            if op == "le":
                return left <= right
            if op == "lt":
                return left < right
        if op == "in":
            if isinstance(left, list):
                return any(str(item) in right for item in left)
            return str(left) in right
    return False

def evaluate_exceptions(user, user_groups, exception):
    allowed_users = exception.get("allowed_users", [])
    allowed_groups = exception.get("allowed_groups", [])
    allowed_ous = exception.get("allowed_ous", [])
    allowed_ranks = exception.get("allowed_ranks")

    if allowed_users and user.get("id") not in allowed_users:
        return False
    if allowed_groups and not any(group in user_groups for group in allowed_groups):
        return False
    if allowed_ous and user.get("ou") not in allowed_ous:
        return False
    if allowed_ranks is not None:
        try:
            if isinstance(allowed_ranks, list):
                if user.get("rank", 0) not in [int(r) for r in allowed_ranks]:
                    return False
            else:
                if user.get("rank", 0) != int(allowed_ranks):
                    return False
        except (ValueError, TypeError):
            return False
    return True

def evaluate_access_reason(user, file_info, policies) -> AccessDecision:
    if file_info.get("file_rank") == 9999 and file_info.get("is_private") and file_info.get("owner_user_id") == user.get("id"):
        logger.debug("[개인 문서 우선 허용] 사용자 소유 개인 문서")
        return AccessDecision.ALLOW_ALL

    policies = sorted(policies, key=lambda p: p.get("priority", 999))
    context = {"user": user, "file": file_info}
    user_groups = user.get("groups", [])

    for policy in policies:
        if not policy.get("is_active", True):   #policy 가 활성된 상태인지
            continue
        for rule in policy.get("rules", []):
            if not evaluate_condition(rule.get("condition", {}), context):   #조건 불일치시
                continue

            exception = rule.get("exception", {})
            action = rule.get("action", {})
            effective_rank = user.get("rank", 0)
            file_rank = file_info.get("file_rank", 0)

            # 예외 조건이 존재하고 만족하지 못하면 건너뜀
            if exception:
                if not evaluate_exceptions(user, user_groups, exception):
                    continue
                else:
                    return AccessDecision(action.get("allow", "deny_all"))

            # # 예외와 무관하게 rank_override가 존재하면 rank 비교 전에 적용
            if "rank_override" in action and action["rank_override"] is not None:
                try:
                    effective_rank = int(action["rank_override"])
                except Exception as e:
                    logger.debug(f"[오버라이드 실패] {e}")

            if effective_rank < file_rank:
                continue

            if action.get("deny") == "deny_all":
                return AccessDecision.DENY
            if action.get("allow") == "read_only":
                return AccessDecision.READ_ONLY
            if action.get("allow") == "allow_all":
                return AccessDecision.ALLOW_ALL

    return AccessDecision.DENY

def evaluate_file_access(user_id, dll_file_path, db_path="policy.db") -> AccessDecision:
    user_info = get_user_info(user_id, db_path)
    file_info = get_file_metadata(dll_file_path, db_path)
    file_info = prepare_file_context(file_info)
    policies = load_policies(db_path)
    result = evaluate_access_reason(user_info, file_info, policies)
    logger.info(f"[접근 판단] user={user_id}, file={dll_file_path} → {result.value.upper()}")
    return result
