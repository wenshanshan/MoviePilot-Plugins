from dataclasses import dataclass, field
from typing import Optional, Dict

from .framework.schemas import BaseSession, BaseBusiness


@dataclass
class Business(BaseBusiness):
    """
    本插件专属的业务模型。
    """

    search_keyword: Optional[str] = None

    search_info: Optional[Dict] = field(default_factory=dict)


@dataclass
class Session(BaseSession):
    """
    组装成本插件专属的 Session。
    """

    # 指定默认视图，用于错误兜底
    default_view = "search"

    business: Business = field(default_factory=Business)
