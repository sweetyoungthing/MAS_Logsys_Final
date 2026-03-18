"""Production-oriented Amap REST API service layer."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from ..config import get_settings
from ..models.schemas import Location, POIInfo, RouteInfo, WeatherInfo

logger = logging.getLogger(__name__)


class AmapServiceError(Exception):
    """Base exception for Amap service failures."""


class AmapValidationError(AmapServiceError):
    """Raised when caller input is invalid."""


class AmapRateLimitError(AmapServiceError):
    """Raised when the upstream Amap API rate limits the request."""


class AmapUpstreamError(AmapServiceError):
    """Raised when Amap returns an unexpected upstream error."""


class AmapService:
    """Typed wrapper around the Amap REST API with validation and logging."""

    BASE_URL = "https://restapi.amap.com/v3"
    RATE_LIMIT_HINTS = {
        "DAILY_QUERY_OVER_LIMIT",
        "ACCESS_TOO_FREQUENT",
        "USER_DAILY_QUERY_OVER_LIMIT",
        "CUQPS_HAS_EXCEEDED_THE_LIMIT",
    }

    def __init__(self) -> None:
        """Initialize the service with shared configuration."""
        settings = get_settings()
        if not settings.amap_api_key:
            raise AmapValidationError("高德地图 API Key 未配置，请在环境变量中设置 AMAP_API_KEY。")

        self.api_key = settings.amap_api_key
        self.timeout = settings.llm_timeout
        self.client = httpx.Client(timeout=httpx.Timeout(self.timeout))

    def search_poi(self, keywords: str, city: str, citylimit: bool = True) -> List[POIInfo]:
        """Search POIs in a city by keyword."""
        keywords = self._require_non_empty(keywords, "keywords")
        city = self._require_non_empty(city, "city")

        response = self._request(
            path="/place/text",
            params={
                "keywords": keywords,
                "city": city,
                "citylimit": str(citylimit).lower(),
                "output": "json",
                "offset": 10,
                "page": 1,
                "extensions": "all",
            },
            operation="search_poi",
        )

        pois: List[POIInfo] = []
        for poi in response.get("pois", []) or []:
            location = self._parse_location(poi.get("location"))
            if location is None:
                continue
            pois.append(
                POIInfo(
                    id=str(poi.get("id") or ""),
                    name=str(poi.get("name") or ""),
                    type=str(poi.get("type") or ""),
                    address=str(poi.get("address") or ""),
                    location=location,
                    tel=self._optional_str(poi.get("tel")),
                )
            )

        logger.info("Amap POI search succeeded for city=%s keywords=%s count=%s", city, keywords, len(pois))
        return pois

    def get_weather(self, city: str) -> List[WeatherInfo]:
        """Query multi-day weather information for a city."""
        city = self._require_non_empty(city, "city")
        adcode = self._resolve_city_adcode(city)

        response = self._request(
            path="/weather/weatherInfo",
            params={"city": adcode, "extensions": "all"},
            operation="get_weather",
        )

        forecasts = response.get("forecasts", []) or []
        if not forecasts:
            raise AmapUpstreamError(f"未获取到城市 {city} 的天气预报。")

        casts = forecasts[0].get("casts", []) or []
        weather_list = [
            WeatherInfo(
                date=str(cast.get("date") or ""),
                day_weather=str(cast.get("dayweather") or ""),
                night_weather=str(cast.get("nightweather") or ""),
                day_temp=str(cast.get("daytemp") or 0),
                night_temp=str(cast.get("nighttemp") or 0),
                wind_direction=str(cast.get("daywind") or cast.get("nightwind") or ""),
                wind_power=str(cast.get("daypower") or cast.get("nightpower") or ""),
            )
            for cast in casts
            if cast.get("date")
        ]

        logger.info("Amap weather query succeeded for city=%s count=%s", city, len(weather_list))
        return weather_list

    def plan_route(
        self,
        origin_address: str,
        destination_address: str,
        origin_city: Optional[str] = None,
        destination_city: Optional[str] = None,
        route_type: str = "walking",
    ) -> RouteInfo:
        """Plan a route between two addresses using Amap direction services."""
        origin_address = self._require_non_empty(origin_address, "origin_address")
        destination_address = self._require_non_empty(destination_address, "destination_address")

        normalized_route_type = route_type.strip().lower()
        if normalized_route_type not in {"walking", "driving", "transit"}:
            raise AmapValidationError("route_type 仅支持 walking、driving 或 transit。")

        origin_geo = self._geocode_detail(origin_address, origin_city)
        destination_geo = self._geocode_detail(destination_address, destination_city)

        params: Dict[str, Any] = {
            "origin": origin_geo["location"],
            "destination": destination_geo["location"],
            "output": "json",
        }

        path = "/direction/walking"
        if normalized_route_type == "driving":
            path = "/direction/driving"
        elif normalized_route_type == "transit":
            path = "/direction/transit/integrated"
            city_name = origin_city or destination_city or origin_geo.get("city") or destination_geo.get("city")
            if not city_name:
                raise AmapValidationError("公共交通路线规划需要提供 origin_city 或 destination_city。")
            params["city"] = city_name
            params["cityd"] = destination_city or city_name
            params["strategy"] = 0

        response = self._request(path=path, params=params, operation=f"plan_route:{normalized_route_type}")
        route_info = self._parse_route_info(response, normalized_route_type)
        logger.info(
            "Amap route planning succeeded type=%s distance=%s duration=%s",
            normalized_route_type,
            route_info.distance,
            route_info.duration,
        )
        return route_info

    def geocode(self, address: str, city: Optional[str] = None) -> Location:
        """Convert an address into geographic coordinates."""
        detail = self._geocode_detail(address, city)
        location = self._parse_location(detail["location"])
        if location is None:
            raise AmapUpstreamError(f"高德地图返回了无效坐标: {detail['location']}")
        return location

    def get_poi_detail(self, poi_id: str) -> Dict[str, Any]:
        """Fetch detailed POI information, including business data and photos."""
        poi_id = self._require_non_empty(poi_id, "poi_id")
        response = self._request(
            path="/place/detail",
            params={"id": poi_id, "extensions": "all"},
            operation="get_poi_detail",
        )
        pois = response.get("pois", []) or []
        if not pois:
            raise AmapUpstreamError(f"未找到 POI 详情: {poi_id}")

        poi = pois[0]
        detail: Dict[str, Any] = {
            "id": str(poi.get("id") or ""),
            "name": str(poi.get("name") or ""),
            "type": str(poi.get("type") or ""),
            "address": str(poi.get("address") or ""),
            "location": poi.get("location") or "",
            "tel": poi.get("tel"),
            "website": poi.get("website"),
            "business_area": poi.get("business_area"),
            "rating": (poi.get("biz_ext") or {}).get("rating"),
            "cost": (poi.get("biz_ext") or {}).get("cost"),
            "photos": [item.get("url") for item in (poi.get("photos") or []) if item.get("url")],
        }
        logger.info("Amap POI detail query succeeded poi_id=%s", poi_id)
        return detail

    def _geocode_detail(self, address: str, city: Optional[str] = None) -> Dict[str, Any]:
        """Resolve a raw address into the first Amap geocode result."""
        address = self._require_non_empty(address, "address")
        params: Dict[str, Any] = {"address": address, "output": "json"}
        if city:
            params["city"] = city.strip()

        response = self._request(path="/geocode/geo", params=params, operation="geocode")
        geocodes = response.get("geocodes", []) or []
        if not geocodes:
            raise AmapUpstreamError(f"地址解析失败，未找到匹配地址: {address}")
        return geocodes[0]

    def _resolve_city_adcode(self, city: str) -> str:
        """Resolve a city name into its Amap adcode."""
        response = self._request(
            path="/config/district",
            params={"keywords": city, "subdistrict": 0, "extensions": "base"},
            operation="resolve_city_adcode",
        )
        districts = response.get("districts", []) or []
        if not districts:
            raise AmapUpstreamError(f"未找到城市行政区编码: {city}")
        adcode = str(districts[0].get("adcode") or "").strip()
        if not adcode:
            raise AmapUpstreamError(f"城市行政区编码为空: {city}")
        return adcode

    def _request(self, *, path: str, params: Dict[str, Any], operation: str) -> Dict[str, Any]:
        """Perform a GET request against the Amap REST API with consistent error handling."""
        query = dict(params)
        query["key"] = self.api_key

        try:
            response = self.client.get(f"{self.BASE_URL}{path}", params=query)
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            logger.warning("Amap request timed out op=%s path=%s", operation, path)
            raise AmapUpstreamError(f"高德地图请求超时: {operation}") from exc
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Amap HTTP error op=%s path=%s status=%s",
                operation,
                path,
                exc.response.status_code,
            )
            raise AmapUpstreamError(f"高德地图 HTTP 错误: {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            logger.warning("Amap request failed op=%s path=%s reason=%s", operation, path, exc)
            raise AmapUpstreamError(f"高德地图网络请求失败: {operation}") from exc

        try:
            data = response.json()
        except ValueError as exc:
            logger.warning("Amap returned invalid JSON op=%s path=%s", operation, path)
            raise AmapUpstreamError(f"高德地图返回了无效 JSON: {operation}") from exc

        if str(data.get("status")) != "1":
            info = str(data.get("info") or "未知错误")
            info_code = str(data.get("infocode") or "")
            logger.warning("Amap upstream rejected request op=%s infocode=%s info=%s", operation, info_code, info)
            if info in self.RATE_LIMIT_HINTS or info_code in self.RATE_LIMIT_HINTS:
                raise AmapRateLimitError(f"高德地图接口限流: {info}")
            raise AmapUpstreamError(f"高德地图请求失败: {info}")

        return data

    @staticmethod
    def _parse_location(raw_location: Any) -> Optional[Location]:
        """Parse a 'lng,lat' string into a Location model."""
        if not raw_location:
            return None
        try:
            longitude_str, latitude_str = str(raw_location).split(",", 1)
            return Location(longitude=float(longitude_str), latitude=float(latitude_str))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _optional_str(value: Any) -> Optional[str]:
        """Convert a value to a stripped optional string."""
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _require_non_empty(value: str, field_name: str) -> str:
        """Validate that a required string field is present and reasonably short."""
        text = str(value or "").strip()
        if not text:
            raise AmapValidationError(f"{field_name} 不能为空。")
        if len(text) > 200:
            raise AmapValidationError(f"{field_name} 过长，请缩短后重试。")
        return text

    @staticmethod
    def _parse_route_info(response: Dict[str, Any], route_type: str) -> RouteInfo:
        """Parse route data from the Amap response into the project's RouteInfo model."""
        route = response.get("route") or {}
        if route_type == "transit":
            transit = (route.get("transits") or [None])[0]
            if not transit:
                raise AmapUpstreamError("未获取到公共交通路线。")
            distance = float(transit.get("distance") or 0)
            duration = int(float(transit.get("duration") or 0))
            segments = transit.get("segments") or []
            description = f"共 {len(segments)} 段公共交通方案，预计 {duration // 60} 分钟，距离 {distance / 1000:.1f} 公里。"
            return RouteInfo(
                distance=distance,
                duration=duration,
                route_type=route_type,
                description=description,
            )

        paths = route.get("paths") or []
        if not paths:
            raise AmapUpstreamError("未获取到可用路线。")
        first_path = paths[0]
        distance = float(first_path.get("distance") or 0)
        duration = int(float(first_path.get("duration") or 0))
        description = f"预计 {duration // 60} 分钟，距离 {distance / 1000:.1f} 公里。"
        return RouteInfo(
            distance=distance,
            duration=duration,
            route_type=route_type,
            description=description,
        )


_amap_service = None


def get_amap_service() -> AmapService:
    """Return the shared Amap service instance."""
    global _amap_service
    if _amap_service is None:
        _amap_service = AmapService()
    return _amap_service
