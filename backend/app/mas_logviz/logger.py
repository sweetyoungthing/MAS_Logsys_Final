import functools
import hashlib
import json
import re
import time
import uuid
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from ..security.cata_log import (
    analyze_event_sequence_with_config,
    compute_event_hash,
    enrich_event_security,
    get_method_config,
    init_security_state,
    with_ablation,
)

# --- 1. Global Context & Config ---

class RunContext:
    def __init__(self):
        self.run_id = uuid.uuid4().hex
        self.event_seq = 0
        self.msg_seq = 0
        self.span_seq = 0
        self.current_step = "Init"
        self.enabled = False
        self.persist_logs = False
        self.log_path = ""
        self.schema_version = "maslog.v2"
        self.prev_event_hash = "GENESIS"
        self.raw_events = []
        self.security_state = None
        self.last_security_summary = None

_CTX = RunContext()

# ...

def _infer_actor_role(event_type: str, agent: str) -> str:
    if event_type in {"tool_call_start", "tool_call_end"}:
        return "tool_runtime"
    if event_type == "security_summary":
        return "security_monitor"
    if event_type == "final":
        return "planner_agent"
    if "User" in (agent or ""):
        return "user"
    if agent in {"System", "Runtime", "Orchestrator"}:
        return "system"
    if "Agent" in (agent or ""):
        return "planner_agent"
    return "system"


def _infer_decision_phase(step_name: str, event_type: str) -> str:
    step = (step_name or "").lower()
    if "attraction" in step or "景点" in step:
        return "information_collection.attraction"
    if "weather" in step or "天气" in step:
        return "information_collection.weather"
    if "hotel" in step or "酒店" in step:
        return "information_collection.hotel"
    if "final" in step or "行程" in step:
        return "decision_synthesis.final_report"
    if event_type == "final":
        return "decision_synthesis.final_output"
    if event_type == "security_summary":
        return "security_post_analysis"
    return "runtime"


def _infer_interaction_scope(channel: str, trust_level: str) -> str:
    ch = (channel or "").lower()
    trust = (trust_level or "").lower()
    if "tool_result" in ch or "untrusted" in trust:
        return "external_to_internal_boundary"
    if "user_instruction" in ch:
        return "user_to_agent_boundary"
    if "agent_message" in ch:
        return "internal_agent_channel"
    return "system_channel"


def _build_runtime_security_state() -> Dict[str, Any]:
    state = init_security_state()
    config = deepcopy(get_method_config())
    config.setdefault("pi_detector", {})["allow_fallback"] = True

    try:
        import sentence_transformers  # type: ignore  # noqa: F401
    except Exception:
        config = with_ablation(config, "no_semantic")

    state["config"] = config
    return state


def init_context(
    enabled: bool = True,
    *,
    persist_logs: Optional[bool] = None,
    security_enabled: Optional[bool] = None,
):
    global _CTX
    _CTX = RunContext()
    _CTX.persist_logs = bool(enabled) if persist_logs is None else bool(persist_logs)
    security_on = bool(enabled) if security_enabled is None else bool(security_enabled)
    _CTX.enabled = bool(_CTX.persist_logs or security_on)
    if security_on:
        _CTX.security_state = _build_runtime_security_state()
    if _CTX.persist_logs:
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
    if not _CTX.enabled:
        return

    _CTX.event_seq += 1
    event_type = str(event.get("type", "unknown"))
    agent = str(event.get("agent", "System"))
    channel = str(event.get("channel", ""))
    trust_level = str(event.get("trust_level", ""))

    causal_parents = event.get("causal_parents")
    if causal_parents is None:
        causal_parents = [_CTX.event_seq - 1] if _CTX.event_seq > 1 else []

    base_event = {
        "schema_version": _CTX.schema_version,
        "run_id": _CTX.run_id,
        "event_id": _CTX.event_seq,
        "ts": time.time(),
        "step": _CTX.current_step,
        "decision_phase": _infer_decision_phase(_CTX.current_step, event_type),
        "actor_role": _infer_actor_role(event_type, agent),
        "interaction_scope": _infer_interaction_scope(channel, trust_level),
        "causal_parents": causal_parents,
        "prev_event_hash": _CTX.prev_event_hash,
    }
    full_event = {**base_event, **event}
    _CTX.raw_events.append(deepcopy(full_event))

    if _CTX.security_state is not None:
        full_event = enrich_event_security(full_event, _CTX.security_state)

    event_hash = compute_event_hash(full_event, _CTX.prev_event_hash)
    full_event["event_hash"] = event_hash
    _CTX.prev_event_hash = event_hash

    if _CTX.persist_logs and _CTX.log_path:
        safe_event = sanitize(full_event)
        try:
            with open(_CTX.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(safe_event, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"Error writing to MAS log: {e}")

def log_message(
    sender_name: str,
    content: Any,
    tool_calls: bool = False,
    role: str = None,
    *,
    receiver: Optional[str] = None,
    channel: Optional[str] = None,
    trust_level: Optional[str] = None,
):
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
        "receiver": receiver,
        "role": role,
        "content": content_str,
        "content_preview": content_str[:1000],
        "content_len": len(content_str),
        "content_sha256": hashlib.sha256(content_str.encode("utf-8")).hexdigest(),
        "step": _CTX.current_step,
        "tool_calls_present": tool_calls,
        "channel": channel,
        "trust_level": trust_level,
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
        "kwargs": kwargs,
        "channel": "tool_request",
        "trust_level": "internal_agent_output",
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
        "result_full": result_str,
        "result_preview": res_preview,
        "result_len": res_len,
        "result_sha256": res_sha,
        "channel": "tool_result",
        "trust_level": "untrusted_tool_output",
    })


def log_final(answer: Any, agent: str = "PlannerAgent") -> None:
    """Log the final planner output for sequence-level security analysis."""
    answer_str = str(answer)
    write_event({
        "type": "final",
        "agent": agent,
        "answer": answer_str,
        "answer_preview": answer_str[:1000],
        "answer_len": len(answer_str),
        "channel": "final_output",
        "trust_level": "internal_agent_output",
    })


def summarize_run_security() -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    """Re-run sequence-level analysis on the current execution trace."""
    global _CTX
    config = None
    if _CTX.security_state is not None:
        config = deepcopy(_CTX.security_state.get("config"))
    annotated, summary = analyze_event_sequence_with_config(list(_CTX.raw_events), config=config)
    _CTX.last_security_summary = summary
    return annotated, summary


def log_security_summary(summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Persist a terminal security summary event and return the summary."""
    if summary is None:
        _, summary = summarize_run_security()

    content = (
        f"MAS security summary: max_risk={summary.get('max_risk_score', 0)} "
        f"successful={summary.get('successful_attack_chain_count', 0)} "
        f"attempted={summary.get('attempted_attack_chain_count', 0)}"
    )
    write_event({
        "type": "security_summary",
        "agent": "SecurityMonitor",
        "content": content,
        "summary": summary,
        "channel": "security_monitoring",
        "trust_level": "internal_system",
    })
    _CTX.last_security_summary = summary
    return summary


def finalize_execution(answer: Any, agent: str = "PlannerAgent") -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    """Log the final output and produce a sequence-level security summary."""
    log_final(answer, agent=agent)
    annotated, summary = summarize_run_security()
    log_security_summary(summary)
    return annotated, summary

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
