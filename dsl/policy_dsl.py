import sqlite3
import json
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------- 조건 평가 --------------------

def resolve_field(field_path: str, context: dict):
    logger.debug(f"Resolving field: {field_path}")
    parts = field_path.split(".")
    
    # 중첩된 구조로 시도
    current = context
    for part in parts:
        logger.debug(f"Looking for nested part: {part} in {current}")
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            elif parts[0] == "file" and f"file_{part}" in context:
                # file.ou -> file_ou 변환 시도
                current = context[f"file_{part}"]
                break
            else:
                logger.debug(f"Field not found: {part}")
                return None
        else:
            logger.debug(f"Not a dict: {current}")
            return None
            
    logger.debug(f"Resolved value: {current}")
    return current

def evaluate_condition(condition: dict, context: dict) -> bool:
    logger.debug(f"Evaluating condition: {condition}")
    logger.debug(f"Context: {context}")
    
    if "and" in condition:
        return all(evaluate_condition(c, context) for c in condition["and"])
    if "or" in condition:
        return any(evaluate_condition(c, context) for c in condition["or"])
    if "not" in condition:
        return not evaluate_condition(condition["not"], context)
    
    for op, args in condition.items():
        if not isinstance(args, list) or len(args) != 2:
            logger.debug(f"Invalid args format: {args}")
            continue
            
        field, value = args
        target = resolve_field(field, context)
        logger.debug(f"Operation: {op}, Field: {field}, Target: {target}, Value: {value}")
        
        if target is None:
            logger.debug(f"Target is None for field: {field}")
            return False
            
        if op == "eq": 
            result = str(target) == str(value)
            logger.debug(f"EQ result: {result} (comparing '{target}' with '{value}')")
            return result
        if op == "ne": return str(target) != str(value)
        if op == "ge": return target >= value
        if op == "gt": return target > value
        if op == "le": return target <= value
        if op == "lt": return target < value
        if op == "in": 
            if isinstance(target, list):
                return any(str(t) in value for t in target)
            return str(target) in value
            
    return False

# -------------------- DB 로딩 --------------------

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

# 확장자 + 중첩 구조 자동 생성
def enrich_file_metadata(file_info: dict) -> dict:
    file_path = file_info.get("file_path", "")
    ext = os.path.splitext(file_path)[1].lower().lstrip(".")

    file_info["extension"] = ext           # ✅ 예: xlsx
    file_info["rank"] = file_info.get("file_rank")
    file_info["ou"] = file_info.get("file_ou")

    return file_info


# -------------------- 예외 조건 --------------------

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

# -------------------- 정책 병합 --------------------

def extract_condition_key(rule: dict) -> str:
    for op, (field, _) in rule.get("condition", {}).items():
        return field
    return ""

def merge_policy_rules(policies: list) -> list:
    field_to_rule = {}
    sorted_policies = sorted(policies, key=lambda p: p.get("priority", 100))

    for policy in sorted_policies:
        for rule in policy.get("rules", []):
            key = extract_condition_key(rule)
            if key:
                field_to_rule[key] = rule

    return list(field_to_rule.values())

# -------------------- 접근 판단 --------------------

def evaluate_access_reason(user, file_info, policies):
    context = {"user": user, "file": file_info}
    user_groups = user.get("groups", [])
    
    logger.debug(f"Evaluating access with context: {context}")
    logger.debug(f"Policies: {policies}")

    for policy in policies:
        logger.debug(f"Checking policy: {policy.get('policy_id')}")
        if not policy.get("is_active"):
            logger.debug("Policy is not active, skipping")
            continue
            
        for rule in policy.get("rules", []):
            logger.debug(f"Evaluating rule: {rule.get('id')}")
            logger.debug(f"Rule condition: {rule.get('condition')}")
            
            condition_result = evaluate_condition(rule.get("condition", {}), context)
            logger.debug(f"Condition evaluation result: {condition_result}")
            
            if not condition_result:
                logger.debug("Condition not met, skipping rule")
                continue

            exception = rule.get("exception", {})
            if exception and evaluate_exceptions(user, user_groups, exception):
                logger.debug("Exception condition met")
                return True, f"예외 조건 만족: {rule.get('description', '')}"

            effective_rank = user.get("rank", 0)
            file_rank = file_info.get("file_rank", 0)
            logger.debug(f"Ranks - Effective: {effective_rank}, File: {file_rank}")

            action = rule.get("action", {})
            logger.debug(f"Action: {action}")
            
            if "rank_override" in action and action["rank_override"] is not None:
                try:
                    effective_rank = int(action["rank_override"])
                    logger.debug(f"Rank overridden to: {effective_rank}")
                except Exception:
                    pass

            if effective_rank < file_rank:
                logger.debug("Rank check failed")
                continue

            if action.get("deny") == "deny_all":
                logger.debug("Deny all action found")
                return False, f"차단: 정책({rule.get('id')}) - deny_all"

            if action.get("allow") in ["read_only", "allow_all"]:
                logger.debug(f"Allow action found: {action.get('allow')}")
                return True, f"허용: 정책({rule.get('id')}) - {action.get('allow')}"

    logger.debug("No matching conditions found")
    return False, "차단됨: 일치하는 조건 없음"

# -------------------- 외부 진입점 --------------------

def evaluate_file_access(user_id, file_path, db_path="policy.db") -> bool:
    user_info = get_user_info(user_id, db_path)
    file_info = get_file_metadata(file_path, db_path)
    file_info = enrich_file_metadata(file_info)  #확장자 자동 삽입 및 중첩 구조 생성
    policies = load_policies(db_path)
    result, reason = evaluate_access_reason(user_info, file_info, policies)
    logger.info(f"[접근 판단] user={user_id}, file={file_path} → {'ALLOW' if result else 'DENY'} ({reason})")
    return result
