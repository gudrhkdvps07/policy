import sqlite3
import json
import logging

# 로그 설정 :  INFO 이상 로그 출력, 로거 이름은 이 모듈 이름
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# 1. 정책 로딩 함수
# DB에서 활성화된 정책만 불러오기
def load_policies(db_path="policy.db"):
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT policy_json FROM policies WHERE is_active = 1")
        rows = cur.fetchall()
        conn.close()
        raw_policies = [json.loads(row[0]) for row in rows]
        policies = [p for p in raw_policies if validate_policy(p)]
        logger.info(f"[정책 로드 성공] {len(policies)}개 정책 로드됨 (DB={db_path})")
        return policies
    except Exception as error:
        logger.error(f"[정책 로드 실패] DB={db_path}, 오류: {error}")
        raise


# 2. 사용자 정보 조회 함수
# user_id 기반으로 사용자 rank, dn, ou, groups 반환
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


# 3. 파일 메타데이터 조회 함수
# 파일 경로 기반으로 ou와 rank 반환
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


# 4. 정책 유효성 검사 함수
#  정책 포맷이 유효한지 확인
def validate_policy(policy):
    try:
        assert policy.get("policy_id"), "policy_id 누락"
        assert policy.get("policy_type") in ["OU", "Group", "GPO"], "정책 유형 오류"

        action = policy.get("action", {})
        allow = action.get("allow")
        deny = action.get("deny")
        rank_override = action.get("rank_override", None)

        if allow and allow not in ["read_only", "allow_all"]:
            raise ValueError(f"허용값 오류: {allow}")
        if deny and deny != "deny_all":
            raise ValueError(f"차단값 오류: {deny}")
        if rank_override is not None and not isinstance(rank_override, int):
            try:
                policy["action"]["rank_override"] = int(rank_override)
            except Exception:
                raise ValueError("rank_override는 정수여야 함")

        exception = policy.get("exception", {})
        if exception:
            if not isinstance(exception.get("allowed_users", []), list):
                raise ValueError("allowed_users는 리스트여야 함")
            if not isinstance(exception.get("allowed_groups", []), list):
                raise ValueError("allowed_groups는 리스트여야 함")
            if not isinstance(exception.get("allowed_ous", []), list):
                raise ValueError("allowed_ous는 리스트여야 함")
            if "allowed_rank" in exception and not isinstance(exception["allowed_rank"], int):
                raise ValueError("allowed_rank는 정수여야 함")

        # OR/AND 연산자 검증 추가
        conditions = policy.get("conditions", [])
        if conditions:
            for condition in conditions:
                if not isinstance(condition, dict):
                    raise ValueError("조건은 딕셔너리여야 함")
                if "operator" not in condition:
                    raise ValueError("조건에 operator가 없음")
                if condition["operator"] not in ["AND", "OR"]:
                    raise ValueError("operator는 AND 또는 OR여야 함")
                if "values" not in condition:
                    raise ValueError("조건에 values가 없음")
                if not isinstance(condition["values"], list):
                    raise ValueError("values는 리스트여야 함")

        return True

    except (AssertionError, ValueError) as e:
        logger.warning(f"[정책 유효성 오류] policy_id={policy.get('policy_id')} - {e}")
        return False


# 5. 정책 적용 여부 판단 함수
# 정책이 이 사용자/파일에 해당하는지 여부 판단
def is_policy_applicable(policy_type, policy, user, file_info, ad_groups):
    if policy_type == "OU":
        return file_info.get("file_ou") == policy.get("target_dn")
    elif policy_type == "Group":
        if not ad_groups or not isinstance(ad_groups, list):
            logger.warning(f"[그룹 정책 무시됨] 그룹 정보 없음 또는 형식 오류 (policy_id={policy.get('policy_id')})")
            return False
        return policy.get("target_name") in ad_groups
    elif policy_type == "GPO":
        target_dn = policy.get("target_dn", "")
        target_name = policy.get("target_name", "")
        if target_dn:
            return user.get("ou") == target_dn or user.get("dn", "").endswith(target_dn)
        elif target_name:
            return target_name == user.get("id") or target_name in ad_groups
    return False


# 6. 예외 조건 만족 여부 판단 함수
# 예외 조건들 중 단일값 또는 리스트 조건 만족 여부
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
                ranks = [int(r) for r in allowed_ranks]
                if user.get("rank", 0) not in ranks:
                    return False
            else:
                if user.get("rank", 0) != int(allowed_ranks):
                    return False
        except (ValueError, TypeError):
            return False
    return True


# 7. 조건 평가 함수 (새로 추가)
# OR/AND 연산을 사용하여 조건을 평가
def evaluate_conditions(conditions, user, file_info, ad_groups):
    if not conditions:
        return True
    
    for condition in conditions:
        operator = condition.get("operator")
        values = condition.get("values", [])
        
        if operator == "AND":
            # AND 연산: 모든 조건이 참이어야 함
            for value in values:
                if not evaluate_single_condition(value, user, file_info, ad_groups):
                    return False
            return True
        elif operator == "OR":
            # OR 연산: 하나라도 참이면 됨
            for value in values:
                if evaluate_single_condition(value, user, file_info, ad_groups):
                    return True
            return False
    
    return True


# 8. 단일 조건 평가 함수 (새로 추가)
# 단일 조건을 평가
def evaluate_single_condition(condition, user, file_info, ad_groups):
    condition_type = condition.get("type")
    
    if condition_type == "user_rank":
        return user.get("rank", 0) >= condition.get("value", 0)
    elif condition_type == "file_rank":
        return file_info.get("file_rank", 0) <= condition.get("value", 0)
    elif condition_type == "user_group":
        return condition.get("value") in ad_groups
    elif condition_type == "user_ou":
        return user.get("ou") == condition.get("value")
    elif condition_type == "file_ou":
        return file_info.get("file_ou") == condition.get("value")
    
    return False


# 9. 접근 평가 메인 함수
# 정책 목록 기반으로 접근 허용/차단 판단
def evaluate_access_reason(user, file_info, policies):
    file_rank = file_info.get("file_rank")
    user_rank = user.get("rank", 0)
    ad_groups = user.get("groups", [])
    
    for policy_type in ["GPO", "Group", "OU"]:
        for policy in policies:
            if not policy.get("is_active"):
                continue
            if policy.get("policy_type") != policy_type:
                continue
            if not is_policy_applicable(policy_type, policy, user, file_info, ad_groups):
                continue

            policy_id = policy.get("policy_id", "unknown")
            action = policy.get("action", {})
            exception = policy.get("exception", {})
            conditions = policy.get("conditions", [])

            # 조건 평가
            if not evaluate_conditions(conditions, user, file_info, ad_groups):
                continue

            effective_rank = user_rank
            if policy_type == "GPO" and "rank_override" in action:
                try:
                    effective_rank = int(action.get("rank_override"))
                except (ValueError, TypeError):
                    effective_rank = user_rank

            if file_rank is not None and effective_rank < file_rank:
                continue

            if exception:
                if evaluate_exceptions(user, ad_groups, exception):
                    return True, f"허용됨: 예외 조건 만족 (policy={policy_id})"
                else:
                    continue

            if action.get("deny") == "deny_all":
                return False, f"차단됨: 정책({policy_id})에서 deny_all 명시됨"

            allow_type = action.get("allow")
            if allow_type in ["read_only", "allow_all"]:
                return True, f"허용됨: 정책({policy_id})에서 {allow_type} 허용됨"

    return False, "차단됨: 적용 가능한 정책 없음 또는 허용 조건 없음"


# 10. 외부 진입 함수 (DLL 호출 지점)
def evaluate_file_access(user_id, file_path, db_path="policy.db") -> bool:
    user_info = get_user_info(user_id, db_path)
    file_info = get_file_metadata(file_path, db_path)
    policies = load_policies(db_path)
    result, reason = evaluate_access_reason(user_info, file_info, policies)
    logger.info(f"[접근 평가 결과] user={user_id}, file={file_path}, result={'ALLOW' if result else 'DENY'} ({reason})")
    return result
