from dataclasses import dataclass
from typing import List, Union, Optional
from enum import Enum
import json
import logging

# 로그 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PolicyType(Enum):
    GPO = "GPO"
    GROUP = "Group"
    OU = "OU"
    USER = "User"

class ActionType(Enum):
    READ_ONLY = "read_only"
    ALLOW_ALL = "allow_all"
    DENY_ALL = "deny_all"

@dataclass
class Condition:
    type: str
    value: Union[int, str]

    def to_dict(self) -> dict:
        return {"type": self.type, "value": self.value}

class Operator:
    def __init__(self, conditions: List[Union[Condition, 'Operator']]):
        self.conditions = conditions

    def to_dict(self) -> dict:
        return {
            "operator": self.__class__.__name__,
            "values": [c.to_dict() if isinstance(c, Condition) else c.to_dict() for c in self.conditions]
        }

class And(Operator):
    pass

class Or(Operator):
    pass

@dataclass
class Action:
    allow: Optional[ActionType] = None
    deny: Optional[ActionType] = None
    rank_override: Optional[int] = None

    def to_dict(self) -> dict:
        result = {}
        if self.allow:
            result["allow"] = self.allow.value
        if self.deny:
            result["deny"] = self.deny.value
        if self.rank_override is not None:
            result["rank_override"] = self.rank_override
        return result

@dataclass
class Exception:
    allowed_users: List[str] = None
    allowed_groups: List[str] = None
    allowed_ous: List[str] = None
    allowed_ranks: Union[int, List[int]] = None

    def to_dict(self) -> dict:
        result = {}
        if self.allowed_users:
            result["allowed_users"] = self.allowed_users
        if self.allowed_groups:
            result["allowed_groups"] = self.allowed_groups
        if self.allowed_ous:
            result["allowed_ous"] = self.allowed_ous
        if self.allowed_ranks is not None:
            result["allowed_ranks"] = self.allowed_ranks
        return result

class Policy:
    def __init__(self):
        self._policy = {
            "policy_id": "",
            "policy_type": "",
            "target_dn": "",
            "target_name": "",
            "conditions": [],
            "action": {},
            "exception": {},
            "policy_description": "",
            "is_active": True,
            "created_at": "",
            "updated_at": ""
        }

    def id(self, policy_id: str) -> 'Policy':
        self._policy["policy_id"] = policy_id
        return self

    def type(self, policy_type: PolicyType) -> 'Policy':
        self._policy["policy_type"] = policy_type.value
        return self

    def target(self, dn: str = "", name: str = "") -> 'Policy':
        if dn:
            self._policy["target_dn"] = dn
        if name:
            self._policy["target_name"] = name
        return self

    def when(self, condition: Union[Condition, Operator]) -> 'Policy':
        self._policy["conditions"] = condition.to_dict()
        return self

    def then(self, action: Action) -> 'Policy':
        self._policy["action"] = action.to_dict()
        return self

    def except_for(self, exception: Exception) -> 'Policy':
        self._policy["exception"] = exception.to_dict()
        return self

    def description(self, desc: str) -> 'Policy':
        self._policy["policy_description"] = desc
        return self

    def active(self, is_active: bool = True) -> 'Policy':
        self._policy["is_active"] = is_active
        return self

    def to_json(self) -> dict:
        return self._policy

    def save(self, db_path: str) -> None:
        try:
            with open(db_path, 'w') as f:
                json.dump(self._policy, f, indent=2)
            logger.info(f"정책이 저장되었습니다: {db_path}")
        except Exception as e:
            logger.error(f"정책 저장 실패: {e}")
            raise

# 사용 예시
if __name__ == "__main__":
    # IT 부서의 관리자이면서 등급이 3 이상인 경우 읽기 전용 허용
    policy = (Policy()
        .id("POLICY_001")
        .type(PolicyType.GPO)
        .target(dn="OU=IT,DC=company,DC=com")
        .when(And([
            Condition("user_rank", 3),
            Condition("user_ou", "IT"),
            Or([
                Condition("user_group", "admin"),
                Condition("user_group", "it_admin")
            ])
        ]))
        .then(Action(allow=ActionType.READ_ONLY))
        .description("IT 부서 관리자 정책")
        .active(True))

    # JSON으로 변환
    print(json.dumps(policy.to_json(), indent=2, ensure_ascii=False))

    # 파일로 저장
    policy.save("policy_001.json") 