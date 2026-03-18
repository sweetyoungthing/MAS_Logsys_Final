import functools
from typing import Any
from .logger import log_message, log_tool_decorator, set_current_step

def instrument_agent(agent: Any, agent_name: str = None):
    """
    Wrap an agent's run method to log messages.
    """
    if not hasattr(agent, "run"):
        print(f"Warning: Agent {agent_name} has no run method, skipping instrumentation.")
        return agent

    original_run = agent.run
    name = agent_name or getattr(agent, "name", "UnknownAgent")

    @functools.wraps(original_run)
    def wrapped_run(query: Any, *args, **kwargs):
        # Log the user query (input to agent)
        # We assume the caller is "User" or the system. 
        # In a chain, it might be ambiguous, but for now we log it as "User" -> Agent interaction.
        # But wait, if we log "User", we might duplicate if the caller already logged it.
        # In trip_planner_agent.py, the planner prints steps.
        # We'll rely on the instrumented run to log the INPUT as a message from "User" (or context)
        # and OUTPUT as a message from Agent.
        
        # Check if we should log the input.
        # If the input is a string, log it.
        if isinstance(query, str):
             log_message("User", query, role="user")
        
        result = original_run(query, *args, **kwargs)
        
        # Log the result
        if result:
            log_message(name, result, role="assistant")
            
        return result

    agent.run = wrapped_run
    return agent

def instrument_mcp_tool(tool: Any):
    """
    Try to instrument an MCPTool.
    We assume MCPTool has an 'execute' or 'run' method, or it's a callable.
    """
    # Since we don't know the exact API of MCPTool, we inspect it.
    # If it has a 'func' attribute (common in LangChain tools), we wrap it.
    # If it calls a server, it might use a method like `call_tool`.
    
    # Strategy: Inspect standard methods.
    # For hello_agents MCPTool, let's assume it might have a method that does the work.
    # If we can't find it, we print a warning.
    
    # Note: If MCPTool just defines the tool and the Agent/Executor calls the MCP server directly 
    # via some internal mechanism, we might not be able to intercept it easily here.
    # But if there is a python method being called, we can wrap it.
    
    # Check for 'run' or 'execute'
    for method_name in ['run', 'execute', '__call__']:
        if hasattr(tool, method_name):
            original_method = getattr(tool, method_name)
            if callable(original_method):
                # Wrap it
                # We need a name.
                tool_name = getattr(tool, "name", "UnknownTool")
                
                # Use our decorator
                decorated_method = log_tool_decorator(tool_name)(original_method)
                
                # Set it back
                setattr(tool, method_name, decorated_method)
                print(f"Instrumented tool method: {tool_name}.{method_name}")
                return tool
    
    print(f"Warning: Could not instrument tool {getattr(tool, 'name', 'Unknown')}")
    return tool
