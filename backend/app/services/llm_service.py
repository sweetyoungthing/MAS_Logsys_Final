"""LLM服务模块"""

import logging

from openai import OpenAI
from hello_agents import HelloAgentsLLM
from ..config import get_settings

# 全局LLM实例
_llm_instance = None


def get_llm() -> HelloAgentsLLM:
    """
    获取LLM实例(单例模式)
    
    Returns:
        HelloAgentsLLM实例
    """
    global _llm_instance
    
    if _llm_instance is None:
        settings = get_settings()
        
        # HelloAgentsLLM会自动从环境变量读取配置
        # 包括OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL等
        _llm_instance = HelloAgentsLLM(timeout=settings.llm_timeout)

        provider = getattr(_llm_instance, "provider", "unknown")
        if str(provider).lower() == "deepseek":
            _llm_instance._client = OpenAI(
                api_key=_llm_instance.api_key,
                base_url=_llm_instance.base_url,
                timeout=settings.llm_timeout,
                max_retries=0,
            )
            logging.getLogger("openai._base_client").setLevel(logging.WARNING)
        
        model = getattr(_llm_instance, "model", "unknown")
        print(f"✅ LLM服务初始化成功")
        print(f"   提供商: {provider}")
        print(f"   模型: {model}")
        print(f"   超时: {settings.llm_timeout}s")
        if str(provider).lower() == "deepseek":
            print(f"   SDK内部重试: 已关闭")
    
    return _llm_instance


def reset_llm():
    """重置LLM实例(用于测试或重新配置)"""
    global _llm_instance
    _llm_instance = None
