"""配置管理模块"""

import os
from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# 加载环境变量
# 1. 尝试加载项目根目录的 .env 文件
project_root = Path(__file__).parent.parent.parent
env_file = project_root / ".env"
if env_file.exists():
    load_dotenv(env_file, override=True)
    print(f"✅ 已加载环境变量: {env_file}")
else:
    # 2. 回退到加载当前目录的 .env
    load_dotenv()

# 3. 然后尝试加载HelloAgents的.env(如果存在)
helloagents_env = project_root / "HelloAgents" / ".env"
if helloagents_env.exists():
    load_dotenv(helloagents_env, override=False)  # 不覆盖已有的环境变量


class Settings(BaseSettings):
    """应用配置"""

    # 应用基本配置
    app_name: str = "HelloAgents智能旅行助手"
    app_version: str = "1.0.0"
    debug: bool = False

    # 服务器配置
    host: str = "0.0.0.0"
    port: int = 8000

    # CORS配置 - 使用字符串,在代码中分割
    cors_origins: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"

    # 高德地图API配置
    amap_api_key: str = ""

    # Unsplash API配置
    unsplash_access_key: str = ""
    unsplash_secret_key: str = ""

    # LLM配置 (从环境变量读取,使用LLM_*变量以兼容hello-agents)
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""
    llm_timeout: int = 180
    llm_retry_attempts: int = 2
    llm_retry_backoff_seconds: int = 2

    # 日志配置
    log_level: str = "INFO"

    # MAS日志可视化配置
    enable_mas_logviz: bool = True
    enable_mas_security: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,  # 允许使用字段名或别名填充
    )

    def __init__(self, **kwargs):
        # 在初始化时手动设置 LLM 相关配置
        super().__init__(**kwargs)
        # 强制从环境变量读取 LLM 配置
        self.llm_api_key = os.getenv("LLM_API_KEY", self.llm_api_key)
        self.llm_base_url = os.getenv("LLM_BASE_URL", self.llm_base_url)
        self.llm_model = os.getenv("LLM_MODEL_ID", self.llm_model)

    def get_cors_origins_list(self) -> List[str]:
        """获取CORS origins列表"""
        origins = {
            origin.strip().rstrip("/")
            for origin in self.cors_origins.split(',')
            if origin.strip()
        }

        # 本地开发自动兼容 localhost 和 127.0.0.1，避免因地址差异触发CORS失败
        expanded = set(origins)
        for origin in list(origins):
            if "localhost" in origin:
                expanded.add(origin.replace("localhost", "127.0.0.1"))
            if "127.0.0.1" in origin:
                expanded.add(origin.replace("127.0.0.1", "localhost"))

        return sorted(expanded)


# 创建全局配置实例
settings = Settings()


def get_settings() -> Settings:
    """获取配置实例"""
    return settings


# 验证必要的配置
def validate_config():
    """验证配置是否完整"""
    errors = []
    warnings = []

    if not settings.amap_api_key:
        errors.append("AMAP_API_KEY未配置")

    # HelloAgentsLLM会自动从LLM_API_KEY读取,不强制要求OPENAI_API_KEY
    llm_api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not llm_api_key:
        warnings.append("LLM_API_KEY或OPENAI_API_KEY未配置,LLM功能可能无法使用")

    if errors:
        error_msg = "配置错误:\n" + "\n".join(f"  - {e}" for e in errors)
        raise ValueError(error_msg)

    if warnings:
        print("\n⚠️  配置警告:")
        for w in warnings:
            print(f"  - {w}")

    return True


# 打印配置信息(用于调试)
def print_config():
    """打印当前配置(隐藏敏感信息)"""
    print(f"应用名称: {settings.app_name}")
    print(f"版本: {settings.app_version}")
    print(f"服务器: {settings.host}:{settings.port}")
    print(f"高德地图API Key: {'已配置' if settings.amap_api_key else '未配置'}")

    # 检查LLM配置
    llm_api_key = os.getenv("LLM_API_KEY") or settings.llm_api_key
    llm_base_url = os.getenv("LLM_BASE_URL") or settings.llm_base_url
    llm_model = os.getenv("LLM_MODEL_ID") or settings.llm_model

    print(f"LLM API Key: {'已配置' if llm_api_key else '未配置'}")
    print(f"LLM Base URL: {llm_base_url}")
    print(f"LLM Model: {llm_model}")
    print(f"LLM Timeout: {settings.llm_timeout}s")
    print(f"LLM Retry Attempts: {settings.llm_retry_attempts}")
    print(f"日志级别: {settings.log_level}")
    print(f"MAS日志可视化: {'开启' if settings.enable_mas_logviz else '关闭'}")
    print(f"MAS运行安全分析: {'开启' if settings.enable_mas_security else '关闭'}")
