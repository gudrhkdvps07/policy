from dataclasses import dataclass
from typing import List, Union, Optional
from enum import Enum
import json
import logging
from datetime import datetime
import ldap3

# 로그 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AccessLevel(Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    FULL = "full"

class DocumentClass(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

class ADGroup(Enum):
    ADMIN = "CN=Administrators,CN=Builtin,DC=company,DC=com"
    IT_STAFF = "CN=IT Staff,OU=IT,DC=company,DC=com"
    HR_STAFF = "CN=HR Staff,OU=HR,DC=company,DC=com"

class ADOU(Enum):
    IT = "OU=IT,DC=company,DC=com"
    HR = "OU=HR,DC=company,DC=com"
    FINANCE = "OU=Finance,DC=company,DC=com"

@dataclass
class ADCondition:
    type: str
    value: Union[str, int, List[str]]

    def to_dict(self) -> dict:
        return {"type": self.type, "value": self.value}

class ADOperator:
    def __init__(self, conditions: List[Union[ADCondition, 'ADOperator']]):
        self.conditions = conditions

    def to_dict(self) -> dict:
        return {
            "operator": self.__class__.__name__,
            "values": [c.to_dict() if isinstance(c, ADCondition) else c.to_dict() for c in self.conditions]
        }

class And(ADOperator):
    pass

class Or(ADOperator):
    pass

@dataclass
class DRAction:
    access_level: AccessLevel
    watermark: bool = False
    print_allowed: bool = False
    copy_allowed: bool = False
    expiry_date: Optional[datetime] = None

    def to_dict(self) -> dict:
        result = {
            "access_level": self.access_level.value,
            "watermark": self.watermark,
            "print_allowed": self.print_allowed,
            "copy_allowed": self.copy_allowed
        }
        if self.expiry_date:
            result["expiry_date"] = self.expiry_date.isoformat()
        return result

class ADDRMPolicy:
    def __init__(self):
        self._policy = {
            "policy_id": "",
            "document_class": "",
            "conditions": [],
            "action": {},
            "metadata": {
                "created_at": "",
                "updated_at": "",
                "created_by": "",
                "is_active": True
            }
        }

    def id(self, policy_id: str) -> 'ADDRMPolicy':
        self._policy["policy_id"] = policy_id
        return self

    def document_class(self, doc_class: DocumentClass) -> 'ADDRMPolicy':
        self._policy["document_class"] = doc_class.value
        return self

    def when(self, condition: Union[ADCondition, ADOperator]) -> 'ADDRMPolicy':
        self._policy["conditions"] = condition.to_dict()
        return self

    def then(self, action: DRAction) -> 'ADDRMPolicy':
        self._policy["action"] = action.to_dict()
        return self

    def created_by(self, user: str) -> 'ADDRMPolicy':
        self._policy["metadata"]["created_by"] = user
        return self

    def active(self, is_active: bool = True) -> 'ADDRMPolicy':
        self._policy["metadata"]["is_active"] = is_active
        return self

    def to_json(self) -> dict:
        return self._policy

    def save(self, db_path: str) -> None:
        try:
            with open(db_path, 'w') as f:
                json.dump(self._policy, f, indent=2)
            logger.info(f"DRM 정책이 저장되었습니다: {db_path}")
        except Exception as e:
            logger.error(f"DRM 정책 저장 실패: {e}")
            raise

# 사용 예시
if __name__ == "__main__":
    # IT 부서의 관리자이면서 문서가 기밀인 경우 읽기 전용 허용
    policy = (ADDRMPolicy()
        .id("DRM_001")
        .document_class(DocumentClass.CONFIDENTIAL)
        .when(And([
            ADCondition("ad_group", ADGroup.IT_STAFF.value),
            ADCondition("ad_ou", ADOU.IT.value),
            Or([
                ADCondition("ad_group", ADGroup.ADMIN.value),
                ADCondition("document_owner", "IT_Manager")
            ])
        ]))
        .then(DRAction(
            access_level=AccessLevel.READ,
            watermark=True,
            print_allowed=False,
            copy_allowed=False
        ))
        .created_by("admin")
        .active(True))

    # JSON으로 변환
    print(json.dumps(policy.to_json(), indent=2, ensure_ascii=False))

    # 파일로 저장
    policy.save("drm_policy_001.json") 