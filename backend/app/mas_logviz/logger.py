import json
import time
import uuid
import hashlib
import re
import os
import functools
from datetime import datetime
from typing import Any, Dict, Callable, Optional
from ..config import get_settings

# --- 1. Global Context & Config ---

class RunContext:
    def __init__(self):
        self.run_id = uuid.uuid4().hex
        self.event_seq = 0
        self.msg_seq = 0
        self.span_seq = 0
        self.current_step = "Init"
        self.enabled = False
        self.log_path = ""

_CTX = RunContext()

from pathlib import Path

# ...

def init_context(enabled: bool = True):
    global _CTX
    _CTX = RunContext()
    _CTX.enabled = enabled
    if enabled:
        # Create log file path in backend/logs
        # logger.py is in backend/app/mas_logviz/
        # We want backend/logs
        base_dir = Path(__file__).resolve().parent.parent.parent
        log_dir = base_dir / "logs"
        
        if not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)
            
        _CTX.log_path = str(log_dir / f"autogen_trace_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
        print(f"🔍 MAS Logging Enabled. Log file: {_CTX.log_path}")

def set_current_step(step_name: str):
    global _CTX
    _CTX.current_step = step_name

def get_log_path():
    return _CTX.log_path

# --- 2. Sanitization & Writing ---

def sanitize(obj: Any) -> Any:
    if isinstance(obj, str):
        patterns = [
            (r'(sk-[a-zA-Z0-9-]{10,})', '[REDACTED_OPENAI_KEY]'),
            (r'(tvly-[a-zA-Z0-9-]{10,})', '[REDACTED_TAVILY_KEY]'),
            (r'(Bearer\s+[a-zA-Z0-9-._]+)', '[REDACTED_BEARER]'),
        ]
        for pat, repl in patterns:
            obj = re.sub(pat, repl, obj)
        if len(obj) > 5000: # Slightly relaxed limit
            preview = obj[:300]
            sha = hashlib.sha256(obj.encode("utf-8")).hexdigest()
            return f"{preview}... [TRUNCATED len={len(obj)} sha256={sha}]"
        return obj
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    return obj

def write_event(event: Dict[str, Any]) -> None:
    global _CTX
    if not _CTX.enabled or not _CTX.log_path:
        return

    _CTX.event_seq += 1
    base_event = {
        "run_id": _CTX.run_id,
        "event_id": _CTX.event_seq,
        "ts": time.time()
    }
    full_event = {**base_event, **event}
    safe_event = sanitize(full_event)
    try:
        with open(_CTX.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(safe_event, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"Error writing to MAS log: {e}")

def log_message(sender_name: str, content: Any, tool_calls: bool = False, role: str = None):
    """Log a message event"""
    global _CTX
    if not _CTX.enabled:
        return

    _CTX.msg_seq += 1
    
    if role is None:
        role = "user" if "User" in sender_name else "assistant"
    
    content_str = str(content)
    
    write_event({
        "type": "message",
        "msg_id": _CTX.msg_seq,
        "agent": sender_name,
        "role": role,
        "content": content_str,
        "content_preview": content_str[:1000],
        "content_len": len(content_str),
        "content_sha256": hashlib.sha256(content_str.encode("utf-8")).hexdigest(),
        "step": _CTX.current_step,
        "tool_calls_present": tool_calls
    })

def log_tool_start(name: str, args: tuple, kwargs: dict) -> int:
    """Log tool start and return span_id"""
    global _CTX
    if not _CTX.enabled:
        return 0

    _CTX.span_seq += 1
    span_id = _CTX.span_seq
    parent_msg_id = _CTX.msg_seq 
    
    write_event({
        "type": "tool_call_start",
        "tool": name,
        "span_id": span_id,
        "parent_msg_id": parent_msg_id,
        "args": args,
        "kwargs": kwargs
    })
    return span_id

def log_tool_end(name: str, span_id: int, result: Any, start_time: float, error: Exception = None):
    """Log tool end"""
    global _CTX
    if not _CTX.enabled or span_id == 0:
        return

    status = "SUCCESS"
    error_type = None
    if error:
        status = "FAILED"
        error_type = type(error).__name__
        result_to_log = f"Error({error_type}): {str(error)}"
    else:
        result_to_log = result

    duration_ms = (time.time() - start_time) * 1000
    result_str = str(result_to_log)
    res_len = len(result_str)
    res_sha = hashlib.sha256(result_str.encode("utf-8")).hexdigest()
    res_preview = result_str[:300] + ("..." if res_len > 300 else "")
    
    write_event({
        "type": "tool_call_end",
        "tool": name,
        "span_id": span_id,
        "status": status,
        "duration_ms": duration_ms,
        "error_type": error_type,
        "result": result_to_log, 
        "result_preview": res_preview,
        "result_len": res_len,
        "result_sha256": res_sha
    })

def log_tool_decorator(name: str) -> Callable:
    def deco(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            span_id = log_tool_start(name, args, kwargs)
            try:
                result = func(*args, **kwargs)
                log_tool_end(name, span_id, result, start_time)
                return result
            except Exception as e:
                log_tool_end(name, span_id, None, start_time, error=e)
                raise e
        return wrapper
    return deco
