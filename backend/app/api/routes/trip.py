"""旅行规划API路由"""

from fastapi import APIRouter, Depends, HTTPException
from ...models.schemas import (
    TripRequest,
    TripPlan,
    TripPlanResponse,
    ErrorResponse
)
from ...agents.trip_planner_agent import get_trip_planner_agent
from ...security import ensure_safe_response, security_guard
from ...security.exceptions import SecurityInterceptionError
from ...services.trip_plan_store import get_trip_plan_store

router = APIRouter(prefix="/trip", tags=["旅行规划"])


@router.post(
    "/plan",
    response_model=TripPlanResponse,
    summary="生成旅行计划",
    description="根据用户输入的旅行需求,生成详细的旅行计划",
    dependencies=[Depends(security_guard("trip-plan-request"))],
)
async def plan_trip(request: TripRequest):
    """
    生成旅行计划

    Args:
        request: 旅行请求参数

    Returns:
        旅行计划响应
    """
    try:
        print(f"\n{'='*60}")
        print(f"📥 收到旅行规划请求:")
        print(f"   城市: {request.city}")
        print(f"   日期: {request.start_date} - {request.end_date}")
        print(f"   天数: {request.travel_days}")
        print(f"{'='*60}\n")

        # 获取Agent实例
        print("🔄 获取多智能体系统实例...")
        agent = get_trip_planner_agent()

        # 生成旅行计划
        print("🚀 开始生成旅行计划...")
        trip_plan = agent.plan_trip(request)
        ensure_safe_response(trip_plan.model_dump(), source="/api/trip/plan", policy_name="trip-plan-response")

        store = get_trip_plan_store()
        plan_id = store.create(trip_plan)

        print("✅ 旅行计划生成成功,准备返回响应\n")

        return TripPlanResponse(
            success=True,
            message="旅行计划生成成功",
            plan_id=plan_id,
            data=trip_plan
        )

    except SecurityInterceptionError:
        raise
    except Exception as e:
        print(f"❌ 生成旅行计划失败: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"生成旅行计划失败: {str(e)}"
        )


@router.get(
    "/plans/{plan_id}",
    response_model=TripPlanResponse,
    summary="获取已保存的旅行计划",
    description="根据计划ID获取已持久化的旅行计划"
)
async def get_trip_plan(plan_id: str):
    """Load a stored trip plan by identifier."""
    try:
        trip_plan = get_trip_plan_store().get(plan_id)
        return TripPlanResponse(
            success=True,
            message="获取旅行计划成功",
            plan_id=plan_id,
            data=trip_plan,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="未找到对应的旅行计划")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取旅行计划失败: {str(e)}")


@router.put(
    "/plans/{plan_id}",
    response_model=TripPlanResponse,
    summary="更新已保存的旅行计划",
    description="更新持久化存储中的旅行计划",
    dependencies=[Depends(security_guard("trip-plan-update-request"))],
)
async def update_trip_plan(plan_id: str, request: TripPlan):
    """Update a stored trip plan by identifier."""
    try:
        ensure_safe_response(request.model_dump(), source=f"/api/trip/plans/{plan_id}", policy_name="trip-plan-update-response")
        store = get_trip_plan_store()
        store.update(plan_id, request)
        return TripPlanResponse(
            success=True,
            message="旅行计划更新成功",
            plan_id=plan_id,
            data=request,
        )
    except SecurityInterceptionError:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"更新旅行计划失败: {str(e)}")


@router.get(
    "/health",
    summary="健康检查",
    description="检查旅行规划服务是否正常"
)
async def health_check():
    """健康检查"""
    try:
        # 检查Agent是否可用
        agent = get_trip_planner_agent()

        return {
            "status": "healthy",
            "service": "trip-planner",
            "agents": [
                agent.attraction_agent.name,
                agent.weather_agent.name,
                agent.hotel_agent.name,
                agent.planner_agent.name
            ],
            "tools_count": len(agent.attraction_agent.list_tools())
        }
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"服务不可用: {str(e)}"
        )
