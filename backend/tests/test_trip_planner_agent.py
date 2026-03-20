"""Unit tests for trip planner compression and JSON recovery helpers."""

import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from app.agents.trip_planner_agent import MultiAgentTripPlanner
from app.models.schemas import TripRequest


class _FakeLLM:
    def __init__(self, response: str, provider: str = "openai", model: str = "gpt-4o-mini"):
        self.response = response
        self.provider = provider
        self.model = model

    def invoke(self, messages, **kwargs) -> str:
        return self.response


class _AlwaysFailPlannerAgent:
    def __init__(self):
        self.calls = 0

    def run(self, query, **kwargs):
        self.calls += 1
        raise RuntimeError("Connection error.")


class TripPlannerAgentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = MultiAgentTripPlanner.__new__(MultiAgentTripPlanner)
        self.request = TripRequest(
            city="北京",
            start_date="2026-03-20",
            end_date="2026-03-23",
            travel_days=4,
            transportation="公共交通",
            accommodation="舒适型酒店",
            preferences=["自然风光"],
            free_text_input="",
        )

    def test_compress_attractions_limits_items(self) -> None:
        raw = """
1. **龙潭公园** - 位于龙潭路16号，是北京市区内的大型公园，湖景和园林景观丰富。
2. **什刹海景区** - 位于地安门西大街49号，适合步行和夜景游览。
3. **南苑森林湿地公园** - 位于槐房路42号，湿地生态景观明显。
4. **北海公园荷花湖** - 位于文津街1号，湖景优美。
5. **玉渊潭公园** - 位于西三环中路10号，适合春季赏花。
6. **桃苑公园** - 位于公益桥附近，安静适合散步。
7. **凉水河公园** - 位于金桥东街，适合傍晚散步。
"""
        compressed, count = self.planner._compress_attractions_for_planner(raw)
        self.assertEqual(count, 6)
        self.assertLessEqual(compressed.count("\n") + 1, 6)
        self.assertIn("名称: 龙潭公园", compressed)

    def test_compress_weather_keeps_requested_days(self) -> None:
        raw = """
**今日（3月20日，周五）：**
- 天气：全天晴
- 温度：1°C ~ 16°C
- 风向风力：东南风 1-3级
**明日（3月21日，周六）：**
- 天气：全天多云
- 温度：7°C ~ 16°C
- 风向风力：南风 1-3级
**后天（3月22日，周日）：**
- 天气：白天晴，夜间转多云
- 温度：8°C ~ 21°C
- 风向风力：西北风 1-3级
**3月23日（周一）：**
- 天气：白天多云，夜间转晴
- 温度：5°C ~ 18°C
- 风向风力：南风 1-3级
**3月24日（周二）：**
- 天气：晴
- 温度：7°C ~ 19°C
- 风向风力：北风 1-2级
"""
        compressed, count = self.planner._compress_weather_for_planner(raw, max_days=4)
        self.assertEqual(count, 4)
        self.assertNotIn("3月24日", compressed)
        self.assertIn("天气: 全天晴", compressed)

    def test_compress_hotels_limits_items(self) -> None:
        raw = """
1. **北京千峋轻舍酒店**
   - 地址：周口店镇周口村村委会西457米
   - 类型：酒店
2. **东方1956文化酒店(北京马各庄饶乐府地铁站店)**
   - 地址：北京市房山区马各庄地铁站顾八路东方1956文化园内1956文化酒店
   - 类型：酒店
3. **艾扉酒店(延庆区政府世园公园店)**
   - 地址：湖北西路5号7幢
   - 类型：酒店
4. **潮漫酒店(北京平谷区政府店)**
   - 地址：旧城街17号楼
   - 类型：酒店
5. **时光漫步酒店(北京东直门北桥地坛公园店)**
   - 地址：和平里南口转角楼北里5号
   - 类型：酒店
"""
        compressed, count = self.planner._compress_hotels_for_planner(raw)
        self.assertEqual(count, 4)
        self.assertNotIn("时光漫步酒店", compressed)
        self.assertIn("类型: 酒店", compressed)

    def test_parse_response_repairs_invalid_json(self) -> None:
        repaired = """
{
  "city": "北京",
  "start_date": "2026-03-20",
  "end_date": "2026-03-23",
  "days": [
    {
      "date": "2026-03-20",
      "day_index": 0,
      "description": "第一天游览公园。",
      "transportation": "公共交通",
      "accommodation": "舒适型酒店",
      "hotel": {"name": "北京千峋轻舍酒店", "address": "龙潭路16号"},
      "attractions": [
        {
          "name": "龙潭公园",
          "address": "龙潭路16号",
          "location": {"longitude": 116.44, "latitude": 39.88},
          "visit_duration": 120,
          "description": "湖景公园",
          "category": "公园",
          "ticket_price": 0
        }
      ],
      "meals": [
        {"type": "breakfast", "name": "豆浆油条", "description": "简餐", "estimated_cost": 20},
        {"type": "lunch", "name": "家常菜", "description": "午餐", "estimated_cost": 50},
        {"type": "dinner", "name": "烤鸭", "description": "晚餐", "estimated_cost": 120}
      ]
    }
  ],
  "weather_info": [
    {"date": "2026-03-20", "day_weather": "晴", "night_weather": "多云", "day_temp": 16, "night_temp": 8, "wind_direction": "东南风", "wind_power": "1-3级"}
  ],
  "overall_suggestions": "注意早晚温差。",
  "budget": {"total_attractions": 0, "total_hotels": 400, "total_meals": 190, "total_transportation": 50, "total": 640}
}
"""
        self.planner.llm = _FakeLLM(repaired)
        bad = '{"city":"北京","start_date":"2026-03-20" "end_date":"2026-03-23"}'
        plan = self.planner._parse_response(bad, self.request)
        self.assertEqual(plan.city, "北京")
        self.assertEqual(len(plan.days), 1)
        self.assertEqual(plan.days[0].hotel.name, "北京千峋轻舍酒店")

    def test_planner_request_kwargs_disable_response_format_for_deepseek(self) -> None:
        self.planner.llm = _FakeLLM("{}", provider="deepseek", model="deepseek-chat")
        kwargs = self.planner._planner_request_kwargs(max_tokens=4000, prefer_response_format=True)
        self.assertEqual(kwargs["temperature"], 0.0)
        self.assertEqual(kwargs["max_tokens"], 4000)
        self.assertNotIn("response_format", kwargs)

    def test_create_fallback_plan_uses_compressed_candidates(self) -> None:
        attractions = "- 名称: 龙潭公园 | 地址: 龙潭路16号 | 理由: 湖景公园\n- 名称: 什刹海景区 | 地址: 地安门西大街49号 | 理由: 水域风光"
        weather = "- 3月20日 | 天气: 晴转多云 | 温度: 1°C ~ 16°C | 风力: 东南风 1-3级\n- 3月21日 | 天气: 多云 | 温度: 7°C ~ 16°C | 风力: 南风 1-3级"
        hotels = "- 名称: 北京千峋轻舍酒店 | 地址: 周口店镇周口村村委会西457米 | 类型: 酒店"
        plan = self.planner._create_fallback_plan(self.request, attractions=attractions, weather=weather, hotels=hotels)
        self.assertEqual(plan.city, "北京")
        self.assertEqual(len(plan.days), 4)
        self.assertEqual(plan.days[0].hotel.name, "北京千峋轻舍酒店")
        self.assertIn(plan.days[0].attractions[0].name, {"龙潭公园", "什刹海景区"})
        self.assertEqual(plan.weather_info[0].date, "2026-03-20")

    def test_run_planner_with_retry_uses_single_attempt_for_deepseek(self) -> None:
        self.planner.llm = _FakeLLM("{}", provider="deepseek", model="deepseek-chat")
        self.planner.retry_attempts = 3
        self.planner.retry_backoff_seconds = 0
        self.planner.planner_agent = _AlwaysFailPlannerAgent()
        with self.assertRaises(RuntimeError):
            self.planner._run_planner_with_retry("test", "步骤4-行程生成")
        self.assertEqual(self.planner.planner_agent.calls, 1)

    def test_parse_compact_planner_response_builds_trip_plan(self) -> None:
        compact = """
{
  "days": [
    {
      "date": "2026-03-20",
      "day_index": 0,
      "description": "游览龙潭公园和什刹海景区。",
      "transportation": "公共交通",
      "accommodation": "舒适型酒店",
      "hotel_name": "北京千峋轻舍酒店",
      "attraction_names": ["龙潭公园", "什刹海景区"],
      "meals": [
        {"type": "breakfast", "name": "酒店早餐", "description": "简餐"},
        {"type": "lunch", "name": "北京家常菜", "description": "午餐"},
        {"type": "dinner", "name": "烤鸭", "description": "晚餐"}
      ]
    }
  ],
  "overall_suggestions": "注意早晚温差，合理安排户外时间。"
}
"""
        attractions = "- 名称: 龙潭公园 | 地址: 龙潭路16号 | 理由: 湖景公园\n- 名称: 什刹海景区 | 地址: 地安门西大街49号 | 理由: 水域风光"
        weather = "- 3月20日 | 天气: 晴转多云 | 温度: 1°C ~ 16°C | 风力: 东南风 1-3级\n- 3月21日 | 天气: 多云 | 温度: 7°C ~ 16°C | 风力: 南风 1-3级"
        hotels = "- 名称: 北京千峋轻舍酒店 | 地址: 周口店镇周口村村委会西457米 | 类型: 酒店"
        plan = self.planner._parse_compact_planner_response(
            compact,
            self.request,
            attractions=attractions,
            weather=weather,
            hotels=hotels,
        )
        self.assertEqual(plan.days[0].hotel.name, "北京千峋轻舍酒店")
        self.assertEqual(plan.days[0].attractions[0].name, "龙潭公园")
        self.assertEqual(plan.days[0].meals[2].name, "烤鸭")
        self.assertEqual(plan.overall_suggestions, "注意早晚温差，合理安排户外时间。")


if __name__ == "__main__":
    unittest.main()
