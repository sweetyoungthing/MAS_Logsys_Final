"""多智能体旅行规划系统"""

import json
import re
import time
from datetime import datetime, timedelta
from typing import Any
from hello_agents import SimpleAgent

# 兼容检查：当前项目要求 MCPTool，若缺失则直接报错（不降级）
try:
    from hello_agents.tools import MCPTool  # type: ignore
except Exception:
    MCPTool = None  # type: ignore
from ..services.llm_service import get_llm
from ..models.schemas import (
    Attraction,
    Budget,
    DayPlan,
    Hotel,
    Location,
    Meal,
    TripPlan,
    TripRequest,
    WeatherInfo,
)
from ..config import get_settings
from ..mas_logviz.logger import finalize_execution, init_context, log_message, set_current_step
from ..security import ensure_safe_mas_execution
from ..mas_logviz.instrument import instrument_agent, instrument_mcp_tool

# ============ Agent提示词 ============

ATTRACTION_AGENT_PROMPT = """你是景点搜索专家。你的任务是根据城市和用户偏好搜索合适的景点。

**重要提示:**
你必须使用工具来搜索景点!不要自己编造景点信息!

**工具调用格式:**
使用maps_text_search工具时,必须严格按照以下格式:
`[TOOL_CALL:amap_maps_text_search:keywords=景点关键词,city=城市名]`

**示例:**
用户: "搜索北京的历史文化景点"
你的回复: [TOOL_CALL:amap_maps_text_search:keywords=历史文化,city=北京]

用户: "搜索上海的公园"
你的回复: [TOOL_CALL:amap_maps_text_search:keywords=公园,city=上海]

**注意:**
1. 必须使用工具,不要直接回答
2. 格式必须完全正确,包括方括号和冒号
3. 参数用逗号分隔
"""

WEATHER_AGENT_PROMPT = """你是天气查询专家。你的任务是查询指定城市的天气信息。

**重要提示:**
你必须使用工具来查询天气!不要自己编造天气信息!

**工具调用格式:**
使用maps_weather工具时,必须严格按照以下格式:
`[TOOL_CALL:amap_maps_weather:city=城市名]`

**示例:**
用户: "查询北京天气"
你的回复: [TOOL_CALL:amap_maps_weather:city=北京]

用户: "上海的天气怎么样"
你的回复: [TOOL_CALL:amap_maps_weather:city=上海]

**注意:**
1. 必须使用工具,不要直接回答
2. 格式必须完全正确,包括方括号和冒号
"""

HOTEL_AGENT_PROMPT = """你是酒店推荐专家。你的任务是根据城市和景点位置推荐合适的酒店。

**重要提示:**
你必须使用工具来搜索酒店!不要自己编造酒店信息!

**工具调用格式:**
使用maps_text_search工具搜索酒店时,必须严格按照以下格式:
`[TOOL_CALL:amap_maps_text_search:keywords=酒店,city=城市名]`

**示例:**
用户: "搜索北京的酒店"
你的回复: [TOOL_CALL:amap_maps_text_search:keywords=酒店,city=北京]

**注意:**
1. 必须使用工具,不要直接回答
2. 格式必须完全正确,包括方括号和冒号
3. 关键词使用"酒店"或"宾馆"
"""

PLANNER_AGENT_PROMPT = """你是行程规划专家。你的任务是根据景点信息和天气信息,生成详细的旅行计划。

请严格按照以下JSON格式返回旅行计划:
```json
{
  "city": "城市名称",
  "start_date": "YYYY-MM-DD",
  "end_date": "YYYY-MM-DD",
  "days": [
    {
      "date": "YYYY-MM-DD",
      "day_index": 0,
      "description": "第1天行程概述",
      "transportation": "交通方式",
      "accommodation": "住宿类型",
      "hotel": {
        "name": "酒店名称",
        "address": "酒店地址",
        "location": {"longitude": 116.397128, "latitude": 39.916527},
        "price_range": "300-500元",
        "rating": "4.5",
        "distance": "距离景点2公里",
        "type": "经济型酒店",
        "estimated_cost": 400
      },
      "attractions": [
        {
          "name": "景点名称",
          "address": "详细地址",
          "location": {"longitude": 116.397128, "latitude": 39.916527},
          "visit_duration": 120,
          "description": "景点详细描述",
          "category": "景点类别",
          "ticket_price": 60
        }
      ],
      "meals": [
        {"type": "breakfast", "name": "早餐推荐", "description": "早餐描述", "estimated_cost": 30},
        {"type": "lunch", "name": "午餐推荐", "description": "午餐描述", "estimated_cost": 50},
        {"type": "dinner", "name": "晚餐推荐", "description": "晚餐描述", "estimated_cost": 80}
      ]
    }
  ],
  "weather_info": [
    {
      "date": "YYYY-MM-DD",
      "day_weather": "晴",
      "night_weather": "多云",
      "day_temp": 25,
      "night_temp": 15,
      "wind_direction": "南风",
      "wind_power": "1-3级"
    }
  ],
  "overall_suggestions": "总体建议",
  "budget": {
    "total_attractions": 180,
    "total_hotels": 1200,
    "total_meals": 480,
    "total_transportation": 200,
    "total": 2060
  }
}
```

**重要提示:**
1. weather_info数组必须包含每一天的天气信息
2. 温度必须是纯数字(不要带°C等单位)
3. 每天最多安排2个景点
4. 考虑景点之间的距离和游览时间
5. 每天必须包含早中晚三餐
6. 提供简短实用的旅行建议
7. **必须包含预算信息**:
   - 景点门票价格(ticket_price)
   - 餐饮预估费用(estimated_cost)
   - 酒店预估费用(estimated_cost)
   - 预算汇总(budget)包含各项总费用
8. 只输出一个合法JSON对象,不要输出Markdown、解释或代码块
9. description、overall_suggestions、meals.description 必须简短,控制在单句内
"""

COMPACT_PLANNER_AGENT_PROMPT = """你是行程规划专家。你的任务是根据景点、天气、酒店候选，生成紧凑版旅行计划骨架。

你必须只输出一个合法 JSON 对象，不要输出 Markdown、解释或代码块。

返回格式必须严格为：
{
  "days": [
    {
      "date": "YYYY-MM-DD",
      "day_index": 0,
      "description": "单句概述",
      "transportation": "交通方式",
      "accommodation": "住宿类型",
      "hotel_name": "酒店名称",
      "attraction_names": ["景点1", "景点2"],
      "meals": [
        {"type": "breakfast", "name": "早餐名称", "description": "简短描述"},
        {"type": "lunch", "name": "午餐名称", "description": "简短描述"},
        {"type": "dinner", "name": "晚餐名称", "description": "简短描述"}
      ]
    }
  ],
  "overall_suggestions": "最多3句建议"
}

要求:
1. 每天最多2个景点
2. 酒店必须只从候选酒店中选择
3. 景点必须只从候选景点中选择
4. meals 每天必须包含 breakfast/lunch/dinner
5. 所有描述都保持简短，避免长段落
"""


class MultiAgentTripPlanner:
    """多智能体旅行规划系统"""

    def __init__(self):
        """初始化多智能体系统"""
        print("🔄 开始初始化多智能体旅行规划系统...")

        try:
            settings = get_settings()
            self.llm = get_llm()
            self.retry_attempts = settings.llm_retry_attempts
            self.retry_backoff_seconds = settings.llm_retry_backoff_seconds

            self.amap_tool = None
            self.expanded_amap_tools = []
            if MCPTool is not None:
                # 创建共享的MCP工具(只创建一次)
                print("  - 创建共享MCP工具...")
                self.amap_tool = MCPTool(
                    name="amap",
                    description="高德地图服务",
                    server_command=["uvx", "amap-mcp-server"],
                    env={"AMAP_MAPS_API_KEY": settings.amap_api_key},
                    auto_expand=True
                )

                # Instrument Tool
                if settings.enable_mas_logviz:
                    self.amap_tool = instrument_mcp_tool(self.amap_tool)

                # hello-agents 0.2.9 的 MCPTool 默认不会被 ToolRegistry 自动展开
                # 这里手动展开并注册，确保可直接调用 amap_maps_xxx 子工具
                self.expanded_amap_tools = self.amap_tool.get_expanded_tools()
                if not self.expanded_amap_tools:
                    raise RuntimeError(
                        "MCP工具展开失败，未发现可用子工具。请检查 amap-mcp-server 和 AMAP_API_KEY。"
                    )
                print(f"  - 已展开 {len(self.expanded_amap_tools)} 个MCP子工具")
                print(f"    示例工具: {', '.join([t.name for t in self.expanded_amap_tools[:6]])}")
            else:
                raise RuntimeError(
                    "当前 hello-agents 版本不包含 MCPTool，无法执行地图工具。"
                    "请安装 0.2.x 版本（例如 hello-agents[protocols]==0.2.9）。"
                )

            # 创建景点搜索Agent
            print("  - 创建景点搜索Agent...")
            self.attraction_agent = SimpleAgent(
                name="景点搜索专家",
                llm=self.llm,
                system_prompt=ATTRACTION_AGENT_PROMPT
            )
            # Instrument Agent
            if settings.enable_mas_logviz:
                instrument_agent(self.attraction_agent, "AttractionAgent")
            
            for tool in self.expanded_amap_tools:
                self.attraction_agent.add_tool(tool, auto_expand=True)

            # 创建天气查询Agent
            print("  - 创建天气查询Agent...")
            self.weather_agent = SimpleAgent(
                name="天气查询专家",
                llm=self.llm,
                system_prompt=WEATHER_AGENT_PROMPT
            )
            # Instrument Agent
            if settings.enable_mas_logviz:
                instrument_agent(self.weather_agent, "WeatherAgent")

            for tool in self.expanded_amap_tools:
                self.weather_agent.add_tool(tool, auto_expand=True)

            # 创建酒店推荐Agent
            print("  - 创建酒店推荐Agent...")
            self.hotel_agent = SimpleAgent(
                name="酒店推荐专家",
                llm=self.llm,
                system_prompt=HOTEL_AGENT_PROMPT
            )
            # Instrument Agent
            if settings.enable_mas_logviz:
                instrument_agent(self.hotel_agent, "HotelAgent")

            for tool in self.expanded_amap_tools:
                self.hotel_agent.add_tool(tool, auto_expand=True)

            # 创建行程规划Agent(不需要工具)
            print("  - 创建行程规划Agent...")
            self.planner_agent = SimpleAgent(
                name="行程规划专家",
                llm=self.llm,
                system_prompt=PLANNER_AGENT_PROMPT
            )
            # Instrument Agent
            if settings.enable_mas_logviz:
                instrument_agent(self.planner_agent, "PlannerAgent")

            self.compact_planner_agent = SimpleAgent(
                name="紧凑行程规划专家",
                llm=self.llm,
                system_prompt=COMPACT_PLANNER_AGENT_PROMPT
            )
            if settings.enable_mas_logviz:
                instrument_agent(self.compact_planner_agent, "CompactPlannerAgent")

            print(f"✅ 多智能体系统初始化成功")
            print(f"   景点搜索Agent: {len(self.attraction_agent.list_tools())} 个工具")
            print(f"   天气查询Agent: {len(self.weather_agent.list_tools())} 个工具")
            print(f"   酒店推荐Agent: {len(self.hotel_agent.list_tools())} 个工具")
            print(f"   LLM重试: {self.retry_attempts} 次, 退避: {self.retry_backoff_seconds}s")

        except Exception as e:
            print(f"❌ 多智能体系统初始化失败: {str(e)}")
            import traceback
            traceback.print_exc()
            raise

    def _reset_agent_histories(self) -> None:
        """Clear chat history so each trip request starts with a clean context."""
        for agent in (
            getattr(self, "attraction_agent", None),
            getattr(self, "weather_agent", None),
            getattr(self, "hotel_agent", None),
            getattr(self, "planner_agent", None),
            getattr(self, "compact_planner_agent", None),
        ):
            if agent is not None and hasattr(agent, "clear_history"):
                agent.clear_history()
    
    def plan_trip(self, request: TripRequest) -> TripPlan:
        """
        使用多智能体协作生成旅行计划

        Args:
            request: 旅行请求

        Returns:
            旅行计划
        """
        try:
            settings = get_settings()
            self._reset_agent_histories()
            
            # Initialize MAS Logging Context
            init_context(
                settings.enable_mas_logviz or settings.enable_mas_security,
                persist_logs=settings.enable_mas_logviz,
                security_enabled=settings.enable_mas_security,
            )
            if settings.enable_mas_security:
                log_message(
                    "User",
                    json.dumps(request.model_dump(), ensure_ascii=False),
                    role="user",
                    channel="user_instruction",
                    trust_level="trusted_user_input",
                )
                log_message(
                    "System",
                    f"Starting trip planning for {request.city}",
                    role="system",
                    channel="agent_message",
                    trust_level="internal_system",
                )

            print(f"\n{'='*60}")
            print(f"🚀 开始多智能体协作规划旅行...")
            print(f"目的地: {request.city}")
            print(f"日期: {request.start_date} 至 {request.end_date}")
            print(f"天数: {request.travel_days}天")
            print(f"偏好: {', '.join(request.preferences) if request.preferences else '无'}")
            print(f"{'='*60}\n")

            # 步骤1: 景点搜索Agent搜索景点
            print("📍 步骤1: 搜索景点...")
            attraction_query = self._build_attraction_query(request)
            attraction_response = self._run_agent_with_retry(
                self.attraction_agent,
                attraction_query,
                "步骤1-景点搜索"
            )
            print(f"景点搜索结果: {attraction_response[:200]}...\n")

            # 步骤2: 天气查询Agent查询天气
            print("🌤️  步骤2: 查询天气...")
            weather_query = f"请查询{request.city}的天气信息"
            weather_response = self._run_agent_with_retry(
                self.weather_agent,
                weather_query,
                "步骤2-天气查询"
            )
            print(f"天气查询结果: {weather_response[:200]}...\n")

            # 步骤3: 酒店推荐Agent搜索酒店
            print("🏨 步骤3: 搜索酒店...")
            hotel_query = f"请搜索{request.city}的{request.accommodation}酒店"
            hotel_response = self._run_agent_with_retry(
                self.hotel_agent,
                hotel_query,
                "步骤3-酒店搜索"
            )
            print(f"酒店搜索结果: {hotel_response[:200]}...\n")

            # 步骤4: 行程规划Agent整合信息生成计划
            print("📋 步骤4: 生成行程计划...")
            planner_attractions, attraction_count = self._compress_attractions_for_planner(attraction_response)
            planner_weather, weather_count = self._compress_weather_for_planner(
                weather_response,
                max_days=request.travel_days,
            )
            planner_hotels, hotel_count = self._compress_hotels_for_planner(hotel_response)
            planner_query = self._build_planner_query(request, planner_attractions, planner_weather, planner_hotels)
            print(
                f"📦 Planner输入压缩: attractions={attraction_count}, "
                f"weather={weather_count}, hotels={hotel_count}, query_len={len(planner_query)}"
            )
            final_response_text = ""
            try:
                if self._use_compact_planner_mode():
                    compact_query = self._build_compact_planner_query(
                        request,
                        planner_attractions,
                        planner_weather,
                        planner_hotels,
                    )
                    planner_response = self._run_compact_planner_with_retry(
                        compact_query,
                        "步骤4-紧凑行程生成"
                    )
                    print(f"🧾 紧凑Planner输出长度: {len(planner_response)}")
                    print(f"紧凑行程规划结果: {planner_response[:300]}...\n")
                    trip_plan = self._parse_compact_planner_response(
                        planner_response,
                        request,
                        attractions=planner_attractions,
                        weather=planner_weather,
                        hotels=planner_hotels,
                    )
                    final_response_text = json.dumps(trip_plan.model_dump(), ensure_ascii=False)
                else:
                    planner_response = self._run_planner_with_retry(
                        planner_query,
                        "步骤4-行程生成"
                    )
                    print(f"🧾 Planner输出长度: {len(planner_response)}")
                    print(f"行程规划结果: {planner_response[:300]}...\n")
                    trip_plan = self._parse_response(planner_response, request)
                    final_response_text = planner_response
            except Exception as planner_error:
                print(f"⚠️ 行程规划LLM失败，改用本地备用方案: {planner_error}")
                trip_plan = self._create_fallback_plan(
                    request,
                    attractions=planner_attractions,
                    weather=planner_weather,
                    hotels=planner_hotels,
                )
                final_response_text = json.dumps(trip_plan.model_dump(), ensure_ascii=False)

            if settings.enable_mas_security:
                annotated_events, security_summary = finalize_execution(final_response_text, agent="PlannerAgent")
                ensure_safe_mas_execution(
                    security_summary,
                    source="/api/trip/plan",
                    policy_name="trip-plan-mas-runtime",
                    events=annotated_events,
                )

            print(f"{'='*60}")
            print(f"✅ 旅行计划生成完成!")
            print(f"{'='*60}\n")

            return trip_plan

        except Exception as e:
            print(f"❌ 生成旅行计划失败: {str(e)}")
            import traceback
            traceback.print_exc()
            raise

    def _is_retryable_error(self, error: Exception) -> bool:
        msg = str(error).lower()
        retry_signals = [
            "timeout",
            "timed out",
            "connection error",
            "connecterror",
            "readtimeout",
            "api connection",
            "temporarily unavailable",
            "502",
            "503",
            "504",
            "remoteprotocolerror",
            "incomplete chunked read",
            "peer closed connection",
        ]
        return any(signal in msg for signal in retry_signals)

    def _run_agent_with_retry(self, agent: Any, query: str, step_name: str) -> str:
        last_error = None
        total_attempts = max(1, self.retry_attempts + 1)

        for attempt in range(1, total_attempts + 1):
            try:
                return agent.run(query)
            except Exception as e:
                last_error = e
                should_retry = self._is_retryable_error(e) and attempt < total_attempts
                if not should_retry:
                    raise

                wait_seconds = self.retry_backoff_seconds * attempt
                print(
                    f"⚠️ {step_name} 第{attempt}次调用失败: {e}. "
                    f"{wait_seconds}s后重试({attempt + 1}/{total_attempts})..."
                )
                time.sleep(wait_seconds)

        raise RuntimeError(f"{step_name} 调用失败: {last_error}")

    def _run_planner_with_retry(self, query: str, step_name: str) -> str:
        """Run the planner with provider-aware settings."""
        last_error = None
        total_attempts = 1 if not self._planner_supports_response_format() else max(1, self.retry_attempts + 1)
        request_kwargs = self._planner_request_kwargs(max_tokens=4000, prefer_response_format=True)

        for attempt in range(1, total_attempts + 1):
            try:
                return self.planner_agent.run(query, **request_kwargs)
            except Exception as e:
                last_error = e
                should_retry = self._is_retryable_error(e) and attempt < total_attempts
                if not should_retry:
                    raise

                wait_seconds = self.retry_backoff_seconds * attempt
                print(
                    f"⚠️ {step_name} 第{attempt}次调用失败: {e}. "
                    f"{wait_seconds}s后重试({attempt + 1}/{total_attempts})..."
                )
                time.sleep(wait_seconds)

        raise RuntimeError(f"{step_name} 调用失败: {last_error}")

    def _run_compact_planner_with_retry(self, query: str, step_name: str) -> str:
        last_error = None
        total_attempts = max(1, self.retry_attempts)
        request_kwargs = self._planner_request_kwargs(max_tokens=1800, prefer_response_format=False)

        for attempt in range(1, total_attempts + 1):
            try:
                return self.compact_planner_agent.run(query, **request_kwargs)
            except Exception as e:
                last_error = e
                should_retry = self._is_retryable_error(e) and attempt < total_attempts
                if not should_retry:
                    raise

                wait_seconds = self.retry_backoff_seconds * attempt
                print(
                    f"⚠️ {step_name} 第{attempt}次调用失败: {e}. "
                    f"{wait_seconds}s后重试({attempt + 1}/{total_attempts})..."
                )
                time.sleep(wait_seconds)

        raise RuntimeError(f"{step_name} 调用失败: {last_error}")

    def _planner_supports_response_format(self) -> bool:
        provider = str(getattr(self.llm, "provider", "") or "").lower()
        model = str(getattr(self.llm, "model", "") or "").lower()
        if "deepseek" in provider or "deepseek" in model:
            return False
        return True

    def _use_compact_planner_mode(self) -> bool:
        provider = str(getattr(self.llm, "provider", "") or "").lower()
        model = str(getattr(self.llm, "model", "") or "").lower()
        return "deepseek" in provider or "deepseek" in model

    def _planner_request_kwargs(self, max_tokens: int, prefer_response_format: bool) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "temperature": 0.0,
            "max_tokens": max_tokens,
        }
        if prefer_response_format and self._planner_supports_response_format():
            kwargs["response_format"] = {"type": "json_object"}
        return kwargs
    
    def _build_attraction_query(self, request: TripRequest) -> str:
        """构建景点搜索查询 - 直接包含工具调用"""
        keywords = []
        if request.preferences:
            # 只取第一个偏好作为关键词
            keywords = request.preferences[0]
        else:
            keywords = "景点"

        # 直接返回工具调用格式
        query = f"请使用amap_maps_text_search工具搜索{request.city}的{keywords}相关景点。\n[TOOL_CALL:amap_maps_text_search:keywords={keywords},city={request.city}]"
        return query

    @staticmethod
    def _normalize_line(line: str) -> str:
        text = str(line or "")
        text = text.replace("**", "").replace("`", "").replace("#", "")
        text = text.replace("•", "-").replace("—", "-")
        return re.sub(r"\s+", " ", text).strip()

    @classmethod
    def _truncate_text(cls, text: str, max_len: int) -> str:
        plain = cls._normalize_line(text)
        if len(plain) <= max_len:
            return plain
        return plain[: max_len - 1].rstrip() + "…"

    @classmethod
    def _split_ranked_blocks(cls, text: str) -> list[str]:
        cleaned = str(text or "").replace("**", "")
        blocks = [
            m.group(0).strip()
            for m in re.finditer(r"(?ms)^\s*\d+\.\s+.+?(?=^\s*\d+\.\s+|\Z)", cleaned)
        ]
        return blocks

    @classmethod
    def _extract_address(cls, text: str) -> str:
        patterns = [
            r"地址[:：]\s*([^，。；;\n]+)",
            r"位于([^，。；;\n]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return cls._truncate_text(match.group(1), 32)
        return ""

    @classmethod
    def _extract_type(cls, text: str) -> str:
        match = re.search(r"类型[:：]\s*([^\n]+)", text)
        if match:
            return cls._truncate_text(match.group(1), 24)
        return ""

    @classmethod
    def _extract_reason(cls, text: str) -> str:
        plain = cls._normalize_line(text)
        plain = re.sub(r"^\d+\.\s*", "", plain)
        plain = re.sub(r"(地址|位于)[:：]?\s*[^。；;]+", "", plain)
        plain = re.sub(r"类型[:：]?\s*[^。；;]+", "", plain)
        plain = plain.replace("温馨提示：", "").replace("温馨提示:", "")
        plain = plain.strip(" -;，。")
        if not plain:
            return ""
        sentence = re.split(r"[。；;]", plain)[0]
        return cls._truncate_text(sentence, 36)

    @classmethod
    def _extract_name(cls, text: str) -> str:
        plain = cls._normalize_line(text)
        plain = re.sub(r"^\d+\.\s*", "", plain)
        for sep in (" - ", "：", ":"):
            if sep in plain:
                candidate = plain.split(sep, 1)[0].strip()
                if candidate:
                    return cls._truncate_text(candidate, 36)
        return cls._truncate_text(plain, 36)

    @classmethod
    def _compress_attractions_for_planner(cls, text: str, limit: int = 6) -> tuple[str, int]:
        items: list[str] = []
        for block in cls._split_ranked_blocks(text):
            name = cls._extract_name(block)
            address = cls._extract_address(block)
            reason = cls._extract_reason(block)
            if not name:
                continue
            parts = [f"名称: {name}"]
            if address:
                parts.append(f"地址: {address}")
            if reason:
                parts.append(f"理由: {reason}")
            items.append(" | ".join(parts))
            if len(items) >= limit:
                break
        if not items:
            fallback = cls._truncate_text(cls._normalize_line(text), 360)
            return fallback, 0 if not fallback else 1
        return "\n".join(f"- {item}" for item in items), len(items)

    @classmethod
    def _compress_hotels_for_planner(cls, text: str, limit: int = 4) -> tuple[str, int]:
        items: list[str] = []
        for block in cls._split_ranked_blocks(text):
            name = cls._extract_name(block)
            address = cls._extract_address(block)
            hotel_type = cls._extract_type(block)
            if not name:
                continue
            parts = [f"名称: {name}"]
            if address:
                parts.append(f"地址: {address}")
            if hotel_type:
                parts.append(f"类型: {hotel_type}")
            items.append(" | ".join(parts))
            if len(items) >= limit:
                break
        if not items:
            fallback = cls._truncate_text(cls._normalize_line(text), 280)
            return fallback, 0 if not fallback else 1
        return "\n".join(f"- {item}" for item in items), len(items)

    @classmethod
    def _compress_weather_for_planner(cls, text: str, max_days: int) -> tuple[str, int]:
        lines = [cls._normalize_line(line) for line in str(text or "").splitlines()]
        lines = [line for line in lines if line]
        blocks: list[dict[str, str]] = []
        current: dict[str, str] | None = None

        for line in lines:
            if "温馨提示" in line or "根据查询结果" in line:
                continue
            if re.search(r"(今日|明日|后天|\d{1,2}月\d{1,2}日|\d{4}-\d{2}-\d{2})", line):
                if current:
                    blocks.append(current)
                current = {"label": line.rstrip("：:")}
                continue
            if current is None:
                continue
            candidate = line.lstrip("- ").strip()
            if "温馨提示" in candidate:
                continue
            if "天气" in candidate:
                current["weather"] = candidate.split("：", 1)[-1].split(":", 1)[-1].strip()
            elif "温度" in candidate:
                current["temp"] = candidate.split("：", 1)[-1].split(":", 1)[-1].strip()
            elif "风向风力" in candidate or candidate.startswith("风力") or candidate.startswith("风向"):
                current["wind"] = candidate.split("：", 1)[-1].split(":", 1)[-1].strip()
        if current:
            blocks.append(current)

        trimmed = blocks[:max(1, max_days)]
        items = []
        for block in trimmed:
            parts = [block.get("label", "天气")]
            if block.get("weather"):
                parts.append(f"天气: {block['weather']}")
            if block.get("temp"):
                parts.append(f"温度: {block['temp']}")
            if block.get("wind"):
                parts.append(f"风力: {block['wind']}")
            items.append("- " + " | ".join(parts))
        if not items:
            fallback = cls._truncate_text(cls._normalize_line(text), 240)
            return fallback, 0 if not fallback else 1
        return "\n".join(items), len(items)

    def _build_planner_query(self, request: TripRequest, attractions: str, weather: str, hotels: str = "") -> str:
        """构建行程规划查询"""
        query = f"""请根据以下信息生成{request.city}的{request.travel_days}天旅行计划:

**基本信息:**
- 城市: {request.city}
- 日期: {request.start_date} 至 {request.end_date}
- 天数: {request.travel_days}天
- 交通方式: {request.transportation}
- 住宿: {request.accommodation}
- 偏好: {', '.join(request.preferences) if request.preferences else '无'}

**景点信息:**
{attractions}

**天气信息:**
{weather}

**酒店信息:**
{hotels}

**要求:**
1. 每天最多安排2个景点
2. 每天必须包含早中晚三餐
3. 每天推荐一个具体的酒店，且必须只从上方酒店候选中选择
4. 考虑景点之间的距离和交通方式
5. 返回完整的JSON格式数据
6. 景点的经纬度坐标要真实准确
7. 只输出一个合法JSON对象，不要输出Markdown代码块，不要输出任何解释文字
8. 每天 description 保持单句且简短
9. overall_suggestions 控制在3句以内
10. meals.description 使用简短短语，不要写长段落
11. attractions.location 只需提供数值经纬度，保留4位小数即可
12. hotel.location、meal.address、meal.location 不是必须字段，拿不准时可省略
"""
        if request.free_text_input:
            query += f"\n**额外要求:** {request.free_text_input}"

        return query

    def _build_compact_planner_query(self, request: TripRequest, attractions: str, weather: str, hotels: str = "") -> str:
        return f"""请根据以下信息生成{request.city}的{request.travel_days}天紧凑版旅行计划骨架:

基本信息:
- 城市: {request.city}
- 日期: {request.start_date} 至 {request.end_date}
- 天数: {request.travel_days}天
- 交通方式: {request.transportation}
- 住宿: {request.accommodation}
- 偏好: {', '.join(request.preferences) if request.preferences else '无'}

景点候选:
{attractions}

天气摘要:
{weather}

酒店候选:
{hotels}

规则:
1. 每天最多安排2个景点
2. attraction_names 和 hotel_name 只能从候选中选择
3. 每天输出 breakfast/lunch/dinner 三餐
4. description 保持单句
5. 只输出合法 JSON
"""

    @staticmethod
    def _parse_compact_lines(text: str) -> list[dict[str, str]]:
        items: list[dict[str, str]] = []
        for raw_line in str(text or "").splitlines():
            line = raw_line.strip()
            if not line.startswith("- "):
                continue
            entry: dict[str, str] = {}
            for part in line[2:].split(" | "):
                if ": " not in part:
                    continue
                key, value = part.split(": ", 1)
                entry[key.strip()] = value.strip()
            if entry:
                items.append(entry)
        return items

    @staticmethod
    def _normalize_name(name: str) -> str:
        text = str(name or "").strip()
        text = re.sub(r"[（(].*?[)）]", "", text)
        text = re.sub(r"\s+", "", text)
        return text.lower()

    def _select_candidate_by_name(self, name: str, candidates: list[dict[str, str]], fallback_index: int = 0) -> dict[str, str]:
        if not candidates:
            return {}
        target = self._normalize_name(name)
        if target:
            for candidate in candidates:
                candidate_name = self._normalize_name(candidate.get("名称", ""))
                if candidate_name == target or target in candidate_name or candidate_name in target:
                    return candidate
        return candidates[min(fallback_index, len(candidates) - 1)]

    @staticmethod
    def _safe_int(value: str, default: int = 0) -> int:
        match = re.search(r"-?\d+", str(value or ""))
        if not match:
            return default
        try:
            return int(match.group(0))
        except ValueError:
            return default

    def _build_weather_items(self, request: TripRequest, weather: str) -> list[WeatherInfo]:
        compact = self._parse_compact_lines(weather)
        start_date = datetime.strptime(request.start_date, "%Y-%m-%d")
        items: list[WeatherInfo] = []
        for day_index in range(request.travel_days):
            source = compact[day_index] if day_index < len(compact) else {}
            weather_text = source.get("天气", "")
            if "夜间" in weather_text:
                day_weather, _, night_weather = weather_text.partition("夜间")
                day_weather = day_weather.replace("白天", "").replace("，", "").strip() or weather_text
                night_weather = night_weather.strip() or weather_text
            elif "转" in weather_text:
                day_weather, _, night_weather = weather_text.partition("转")
                day_weather = day_weather.replace("白天", "").strip() or weather_text
                night_weather = night_weather.replace("夜间", "").strip() or day_weather
            else:
                day_weather = weather_text or "晴"
                night_weather = weather_text or "晴"

            temp_text = source.get("温度", "")
            temps = re.findall(r"-?\d+", temp_text)
            low = int(temps[0]) if temps else 8
            high = int(temps[-1]) if temps else 20

            wind_text = source.get("风力", "")
            wind_direction = wind_text.split()[0] if wind_text else ""
            wind_power = " ".join(wind_text.split()[1:]) if len(wind_text.split()) > 1 else wind_text
            current_date = (start_date + timedelta(days=day_index)).strftime("%Y-%m-%d")
            items.append(
                WeatherInfo(
                    date=current_date,
                    day_weather=day_weather or "晴",
                    night_weather=night_weather or day_weather or "晴",
                    day_temp=high,
                    night_temp=low,
                    wind_direction=wind_direction,
                    wind_power=wind_power,
                )
            )
        return items

    def _build_attraction_items(self, request: TripRequest, attractions: str) -> list[dict[str, str]]:
        compact = self._parse_compact_lines(attractions)
        if compact:
            return compact
        return [{"名称": f"{request.city}景点", "地址": f"{request.city}市", "理由": "城市代表性景点"}]

    def _build_hotel_item(self, request: TripRequest, hotels: str) -> dict[str, str]:
        compact = self._parse_compact_lines(hotels)
        if compact:
            return compact[0]
        return {"名称": f"{request.city}{request.accommodation}", "地址": f"{request.city}市中心", "类型": request.accommodation}

    def _compact_plan_to_trip_plan(
        self,
        compact_data: dict[str, Any],
        request: TripRequest,
        attractions: str,
        weather: str,
        hotels: str,
    ) -> TripPlan:
        weather_items = self._build_weather_items(request, weather)
        attraction_candidates = self._build_attraction_items(request, attractions)
        hotel_candidates = self._parse_compact_lines(hotels) or [self._build_hotel_item(request, hotels)]
        hotel_fallback = self._build_hotel_item(request, hotels)
        compact_days = compact_data.get("days") or []
        start_date = datetime.strptime(request.start_date, "%Y-%m-%d")

        days: list[DayPlan] = []
        for day_index in range(request.travel_days):
            day_data = compact_days[day_index] if day_index < len(compact_days) else {}
            date_value = day_data.get("date") or (start_date + timedelta(days=day_index)).strftime("%Y-%m-%d")
            hotel_choice = self._select_candidate_by_name(day_data.get("hotel_name", ""), hotel_candidates)
            if not hotel_choice:
                hotel_choice = hotel_fallback

            hotel = Hotel(
                name=hotel_choice.get("名称", hotel_fallback.get("名称", f"{request.city}{request.accommodation}")),
                address=hotel_choice.get("地址", hotel_fallback.get("地址", f"{request.city}市中心")),
                type=hotel_choice.get("类型", request.accommodation),
                estimated_cost=400,
            )

            selected_names = day_data.get("attraction_names") or []
            if not isinstance(selected_names, list):
                selected_names = []
            selected_items = [
                self._select_candidate_by_name(str(name), attraction_candidates, fallback_index=idx)
                for idx, name in enumerate(selected_names[:2])
            ]
            if not selected_items:
                selected_items = attraction_candidates[:2]

            attraction_models: list[Attraction] = []
            for idx, item in enumerate(selected_items[:2]):
                attraction_models.append(
                    Attraction(
                        name=item.get("名称", f"{request.city}景点{idx + 1}"),
                        address=item.get("地址", f"{request.city}市"),
                        location=Location(
                            longitude=116.40 + day_index * 0.01 + idx * 0.005,
                            latitude=39.90 + day_index * 0.01 + idx * 0.005,
                        ),
                        visit_duration=120,
                        description=item.get("理由", "推荐游览"),
                        category=request.preferences[0] if request.preferences else "景点",
                        ticket_price=0,
                    )
                )

            meal_items = day_data.get("meals") or []
            meal_types = ["breakfast", "lunch", "dinner"]
            meals: list[Meal] = []
            for idx, meal_type in enumerate(meal_types):
                meal_data = meal_items[idx] if idx < len(meal_items) and isinstance(meal_items[idx], dict) else {}
                meals.append(
                    Meal(
                        type=meal_type,
                        name=meal_data.get("name", {"breakfast": "酒店早餐", "lunch": "当地午餐", "dinner": "特色晚餐"}[meal_type]),
                        description=meal_data.get("description", {"breakfast": "简餐", "lunch": "家常菜", "dinner": "地方风味"}[meal_type]),
                        estimated_cost={"breakfast": 20, "lunch": 50, "dinner": 80}[meal_type],
                    )
                )

            description = day_data.get("description") or f"游览{'、'.join(a.name for a in attraction_models)}，行程以就近安排为主。"
            days.append(
                DayPlan(
                    date=date_value,
                    day_index=day_index,
                    description=description,
                    transportation=day_data.get("transportation", request.transportation),
                    accommodation=day_data.get("accommodation", request.accommodation),
                    hotel=hotel,
                    attractions=attraction_models,
                    meals=meals,
                )
            )

        total_meals = request.travel_days * 150
        total_hotels = request.travel_days * 400
        total_transportation = request.travel_days * 50
        budget = Budget(
            total_attractions=0,
            total_hotels=total_hotels,
            total_meals=total_meals,
            total_transportation=total_transportation,
            total=total_hotels + total_meals + total_transportation,
        )
        return TripPlan(
            city=request.city,
            start_date=request.start_date,
            end_date=request.end_date,
            days=days,
            weather_info=weather_items,
            overall_suggestions=compact_data.get("overall_suggestions", "优先选择相邻景点，减少往返；根据天气调整户外时间；出发前确认开放时间。"),
            budget=budget,
        )

    def _parse_compact_planner_response(
        self,
        response: str,
        request: TripRequest,
        attractions: str,
        weather: str,
        hotels: str,
    ) -> TripPlan:
        try:
            json_str = self._extract_json_candidate(response)
            compact_data = json.loads(self._normalize_json_candidate(json_str))
        except Exception as e:
            print(f"⚠️ 紧凑行程JSON首次解析失败，尝试自动修复: {e}")
            repaired_json = self._repair_compact_plan_json(response, request)
            compact_data = json.loads(self._normalize_json_candidate(repaired_json))
        return self._compact_plan_to_trip_plan(compact_data, request, attractions, weather, hotels)

    def _create_fallback_plan(
        self,
        request: TripRequest,
        attractions: str = "",
        weather: str = "",
        hotels: str = "",
    ) -> TripPlan:
        """Create a deterministic local plan when the planner LLM fails."""
        start_date = datetime.strptime(request.start_date, "%Y-%m-%d")
        weather_items = self._build_weather_items(request, weather)
        attraction_items = self._build_attraction_items(request, attractions)
        hotel_item = self._build_hotel_item(request, hotels)

        hotel = Hotel(
            name=hotel_item.get("名称", f"{request.city}{request.accommodation}"),
            address=hotel_item.get("地址", f"{request.city}市中心"),
            type=hotel_item.get("类型", request.accommodation),
            estimated_cost=400,
        )

        days: list[DayPlan] = []
        for day_index in range(request.travel_days):
            current_date = start_date + timedelta(days=day_index)
            start = (day_index * 2) % max(1, len(attraction_items))
            selected_raw = [
                attraction_items[(start + offset) % len(attraction_items)]
                for offset in range(min(2, len(attraction_items)))
            ]
            selected: list[Attraction] = []
            for offset, item in enumerate(selected_raw):
                selected.append(
                    Attraction(
                        name=item.get("名称", f"{request.city}景点{offset + 1}"),
                        address=item.get("地址", f"{request.city}市"),
                        location=Location(
                            longitude=116.40 + day_index * 0.01 + offset * 0.005,
                            latitude=39.90 + day_index * 0.01 + offset * 0.005,
                        ),
                        visit_duration=120,
                        description=item.get("理由", "推荐游览"),
                        category=request.preferences[0] if request.preferences else "景点",
                        ticket_price=0,
                    )
                )

            names = "、".join(attraction.name for attraction in selected)
            meals = [
                Meal(type="breakfast", name="酒店早餐", description="简餐", estimated_cost=20),
                Meal(type="lunch", name="当地午餐", description="家常菜", estimated_cost=50),
                Meal(type="dinner", name="特色晚餐", description="地方风味", estimated_cost=80),
            ]
            days.append(
                DayPlan(
                    date=current_date.strftime("%Y-%m-%d"),
                    day_index=day_index,
                    description=f"游览{names}，行程以就近安排为主。",
                    transportation=request.transportation,
                    accommodation=request.accommodation,
                    hotel=hotel,
                    attractions=selected,
                    meals=meals,
                )
            )

        total_meals = request.travel_days * 150
        total_hotels = request.travel_days * hotel.estimated_cost
        total_transportation = request.travel_days * 50
        budget = Budget(
            total_attractions=0,
            total_hotels=total_hotels,
            total_meals=total_meals,
            total_transportation=total_transportation,
            total=total_hotels + total_meals + total_transportation,
        )
        return TripPlan(
            city=request.city,
            start_date=request.start_date,
            end_date=request.end_date,
            days=days,
            weather_info=weather_items,
            overall_suggestions=(
                f"优先选择相邻景点，减少往返；"
                f"根据天气增减户外停留时间；"
                f"出发前再次确认景点开放时间。"
            ),
            budget=budget,
        )

    @staticmethod
    def _extract_json_candidate(response: str) -> str:
        """Extract the most likely JSON object from an LLM response."""
        text = str(response or "").strip()
        if not text:
            raise ValueError("响应为空")

        if "```json" in text:
            json_start = text.find("```json") + 7
            json_end = text.find("```", json_start)
            return text[json_start:json_end].strip() if json_end != -1 else text[json_start:].strip()

        if "```" in text:
            json_start = text.find("```") + 3
            json_end = text.find("```", json_start)
            snippet = text[json_start:json_end].strip() if json_end != -1 else text[json_start:].strip()
            if snippet.startswith("{") or snippet.startswith("["):
                return snippet

        if "{" in text and "}" in text:
            json_start = text.find("{")
            json_end = text.rfind("}") + 1
            return text[json_start:json_end].strip()

        raise ValueError("响应中未找到JSON数据")

    @staticmethod
    def _normalize_json_candidate(json_str: str) -> str:
        """Apply low-risk cleanup before JSON parsing."""
        cleaned = str(json_str or "").strip()
        cleaned = cleaned.replace("\u201c", '"').replace("\u201d", '"')
        cleaned = cleaned.replace("\u2018", "'").replace("\u2019", "'")
        cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
        return cleaned

    def _repair_trip_plan_json(self, draft: str, request: TripRequest) -> str:
        """Regenerate a strict JSON trip plan when the draft is invalid."""
        request_payload = json.dumps(request.model_dump(), ensure_ascii=False)
        draft_text = str(draft or "")
        if len(draft_text) > 6000:
            draft_text = draft_text[:6000]

        messages = [
            {
                "role": "system",
                "content": (
                    "你是旅行计划JSON修复器。"
                    "你的唯一任务是输出严格合法的 JSON。"
                    "不要输出 markdown，不要输出解释，不要输出代码块。"
                    "输出必须能被 json.loads 直接解析。"
                    "如果原草稿有语法错误，请基于原始请求重新生成完整且合法的JSON。"
                ),
            },
            {
                "role": "user",
                "content": (
                    f"请把下面的旅行计划草稿修复为严格 JSON。\n\n"
                    f"原始请求：\n{request_payload}\n\n"
                    f"待修复草稿：\n{draft_text}"
                ),
            },
        ]
        repaired = self.llm.invoke(
            messages,
            **self._planner_request_kwargs(max_tokens=2500, prefer_response_format=True),
        )
        return self._extract_json_candidate(repaired)

    def _repair_compact_plan_json(self, draft: str, request: TripRequest) -> str:
        request_payload = json.dumps(request.model_dump(), ensure_ascii=False)
        draft_text = str(draft or "")
        if len(draft_text) > 4000:
            draft_text = draft_text[:4000]

        messages = [
            {
                "role": "system",
                "content": (
                    "你是紧凑旅行计划JSON修复器。"
                    "只输出严格合法 JSON。"
                    "不要输出 markdown、解释或代码块。"
                    "输出必须包含 days 和 overall_suggestions。"
                ),
            },
            {
                "role": "user",
                "content": (
                    f"原始请求:\n{request_payload}\n\n"
                    f"请把下面的紧凑旅行计划草稿修复为合法 JSON:\n{draft_text}"
                ),
            },
        ]
        repaired = self.llm.invoke(
            messages,
            **self._planner_request_kwargs(max_tokens=1600, prefer_response_format=False),
        )
        return self._extract_json_candidate(repaired)

    def _parse_trip_plan_json(self, json_str: str) -> TripPlan:
        """Parse a JSON string into the TripPlan model."""
        normalized = self._normalize_json_candidate(json_str)
        data = json.loads(normalized)
        return TripPlan(**data)

    def _parse_response(self, response: str, request: TripRequest) -> TripPlan:
        """
        解析Agent响应
        
        Args:
            response: Agent响应文本
            request: 原始请求
            
        Returns:
            旅行计划
        """
        try:
            json_str = self._extract_json_candidate(response)
            return self._parse_trip_plan_json(json_str)
        except Exception as e:
            print(f"⚠️ 首次解析行程JSON失败，尝试自动修复: {e}")
            try:
                repaired_json = self._repair_trip_plan_json(response, request)
                trip_plan = self._parse_trip_plan_json(repaired_json)
                print("✅ 行程JSON自动修复成功")
                return trip_plan
            except Exception as repair_error:
                print(f"⚠️ 修复后解析仍失败: {repair_error}")
                raise ValueError(f"解析行程JSON失败: {str(repair_error)}") from repair_error
    
# 全局多智能体系统实例
_multi_agent_planner = None


def get_trip_planner_agent() -> MultiAgentTripPlanner:
    """获取多智能体旅行规划系统实例(单例模式)"""
    global _multi_agent_planner

    if _multi_agent_planner is None:
        _multi_agent_planner = MultiAgentTripPlanner()

    return _multi_agent_planner
