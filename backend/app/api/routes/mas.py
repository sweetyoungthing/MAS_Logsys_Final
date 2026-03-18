from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
import os
import glob
from pathlib import Path
from ...mas_logviz.visualizer import visualize_log

router = APIRouter(prefix="/mas", tags=["MAS可视化"])

@router.get("/latest-trace", summary="获取最新MAS运行轨迹图")
async def get_latest_trace():
    """
    获取最新的MAS执行轨迹可视化图表
    """
    try:
        # 定位日志目录
        # backend/app/api/routes/mas.py -> backend/logs
        backend_dir = Path(__file__).resolve().parent.parent.parent.parent
        log_dir = backend_dir / "logs"
        
        if not log_dir.exists():
            raise HTTPException(status_code=404, detail="日志目录不存在")
            
        # 获取日志列表（按修改时间倒序），优先使用最新可解析日志
        log_pattern = str(log_dir / "autogen_trace_*.jsonl")
        log_files = sorted(glob.glob(log_pattern), key=os.path.getmtime, reverse=True)
        if not log_files:
            raise HTTPException(status_code=404, detail="未找到执行日志")
            
        # 定义可视化工件缓存目录，避免重复生成大量文件夹
        viz_cache_dir = log_dir / "viz_cache"
        if not viz_cache_dir.exists():
            viz_cache_dir.mkdir(parents=True, exist_ok=True)
            
        last_error = None
        for log_file in log_files:
            try:
                # visualize_log 会返回生成的图片绝对路径
                img_path = visualize_log(log_file, output_dir=str(viz_cache_dir), show=False)
                if img_path and os.path.exists(img_path):
                    return FileResponse(
                        img_path,
                        media_type="image/png",
                        headers={"Cache-Control": "no-store"}
                    )
            except Exception as viz_error:
                last_error = viz_error
                continue

        if last_error:
            raise HTTPException(status_code=500, detail=f"生成轨迹图失败: {str(last_error)}")
        raise HTTPException(status_code=500, detail="生成轨迹图失败")
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"可视化生成错误: {str(e)}")
