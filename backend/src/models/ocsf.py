# OCSF (Open Cybersecurity Schema Framework) base models
from pydantic import BaseModel
from typing import Optional, Dict, Any, List


class OCSFBase(BaseModel):
    class_uid: str
    class_name: str
    category_uid: str
    category_name: str
    time: int
    severity_id: Optional[int] = None
    severity: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
