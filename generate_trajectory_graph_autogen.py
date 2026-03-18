import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Any

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.lines import Line2D

from mas_security import analyze_event_sequence


def _risk_color_and_badge(event: Dict[str, Any], default_color: str) -> Tuple[str, str]:
    sec = event.get("security", {})
    risk = sec.get("risk_level", "none")
    score = sec.get("risk_score", 0)
    if risk == "critical":
        return "#b2182b", f" [CRITICAL {score}]"
    if risk == "high":
        return "#ef8a62", f" [HIGH {score}]"
    if risk == "medium":
        return "#fddbc7", f" [MEDIUM {score}]"
    if risk == "low":
        return "#d1e5f0", f" [LOW {score}]"
    return default_color, ""


def _event_node_id(event: Dict[str, Any], fallback_prefix: str, seq: int) -> str:
    eid = event.get("event_id")
    if isinstance(eid, int):
        return f"E{eid}"
    return f"{fallback_prefix}_{seq}"


def _is_hidden_plot_agent(agent: Any) -> bool:
    a = str(agent or "").strip().lower()
    return a == "system" or a.startswith("security")


def parse_log_to_graph(log_path: str):
    raw_events: List[Dict[str, Any]] = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                raw_events.append(json.loads(line))

    events, security_summary = analyze_event_sequence(raw_events)

    G = nx.DiGraph()
    node_details: Dict[str, Dict[str, Any]] = {}
    event_to_node: Dict[int, str] = {}

    start_id = "Start"
    G.add_node(start_id, label="Start", color="#f0f0f0", shape="o")
    node_details[start_id] = {"info": "系统初始化", "agent": ""}
    last_node_id = start_id

    pending_tool_calls: Dict[Any, Dict[str, Any]] = {}
    last_agent_name = "UnknownAgent"

    misc_seq = 0

    for event in events:
        event_type = event.get("type")
        sec = event.get("security", {})
        findings = sec.get("findings", [])

        if event_type == "message":
            node_id = _event_node_id(event, "Msg", misc_seq)
            misc_seq += 1
            agent = event.get("agent") or event.get("name") or "Unknown"
            role = event.get("role", "assistant")

            content = event.get("content") or event.get("content_preview") or ""
            display_content = (content[:42] + "...") if len(content) > 42 else content

            if role == "user":
                action_type = "User Message"
            elif role == "tool":
                action_type = "Tool Output"
            else:
                action_type = "Agent Message"

            node_color, badge = _risk_color_and_badge(event, "#cfe8ff")
            label = f"{agent}{badge}\n{action_type}\n{display_content}"

            G.add_node(node_id, label=label, color=node_color, shape="s")
            G.add_edge(last_node_id, node_id, edge_type="timeline")

            node_details[node_id] = {
                "step_type": "Message",
                "agent": agent,
                "role": role,
                "action": action_type,
                "content": content,
                "timestamp": event.get("ts"),
                "event_id": event.get("event_id"),
                "risk_level": sec.get("risk_level"),
                "risk_score": sec.get("risk_score"),
                "security_findings": findings,
                "decision_phase": event.get("decision_phase"),
                "causal_parents": event.get("causal_parents", []),
            }

            if isinstance(event.get("event_id"), int):
                event_to_node[event["event_id"]] = node_id

            last_node_id = node_id
            last_agent_name = agent

        elif event_type == "tool_call_start":
            pending_tool_calls[event.get("span_id")] = {
                "tool": event.get("tool"),
                "kwargs": event.get("kwargs"),
                "caller": last_agent_name,
                "start_event_id": event.get("event_id"),
            }

        elif event_type == "tool_call_end":
            span_id = event.get("span_id")
            start_info = pending_tool_calls.pop(span_id, {})

            tool_name = start_info.get("tool") or event.get("tool") or "UnknownTool"
            caller = start_info.get("caller") or "UnknownAgent"
            status = event.get("status")
            result = event.get("result")
            if result is None:
                result = event.get("result_preview")

            node_id = _event_node_id(event, "Tool", misc_seq)
            misc_seq += 1
            args_str = str(start_info.get("kwargs", ""))
            display_args = (args_str[:28] + "...") if len(args_str) > 28 else args_str
            result_str = str(result)
            display_result = (result_str[:42] + "...") if len(result_str) > 42 else result_str

            default_color = "#c7f0d8" if status == "SUCCESS" else "#f8c9c9"
            color, badge = _risk_color_and_badge(event, default_color)
            label = (
                f"{caller}{badge}\nCall {tool_name}\n"
                f"status={status}\nargs={display_args}\nres={display_result}"
            )
            G.add_node(node_id, label=label, color=color, shape="d")
            G.add_edge(last_node_id, node_id, edge_type="timeline")

            node_details[node_id] = {
                "step_type": "Tool Execution",
                "agent": caller,
                "tool_name": tool_name,
                "action": "Call Tool",
                "input_args": start_info.get("kwargs"),
                "status": status,
                "detailed_result": result,
                "timestamp": event.get("ts"),
                "event_id": event.get("event_id"),
                "risk_level": sec.get("risk_level"),
                "risk_score": sec.get("risk_score"),
                "security_findings": findings,
                "decision_phase": event.get("decision_phase"),
                "causal_parents": event.get("causal_parents", []),
            }

            if isinstance(event.get("event_id"), int):
                event_to_node[event["event_id"]] = node_id

            # Add a call-return relation when start event is known in graph.
            start_eid = start_info.get("start_event_id")
            if isinstance(start_eid, int) and start_eid in event_to_node:
                G.add_edge(event_to_node[start_eid], node_id, edge_type="call_return")

            last_node_id = node_id

        elif event_type == "security_notice":
            node_id = _event_node_id(event, "Risk", misc_seq)
            misc_seq += 1
            node_color, badge = _risk_color_and_badge(event, "#f4b183")
            label = f"SecurityMonitor{badge}\nNotice\n{event.get('content', '')[:42]}"
            G.add_node(node_id, label=label, color=node_color, shape="^")
            G.add_edge(last_node_id, node_id, edge_type="timeline")
            node_details[node_id] = {
                "step_type": "Security Notice",
                "agent": "SecurityMonitor",
                "content": event.get("content"),
                "event_id": event.get("event_id"),
                "risk_level": sec.get("risk_level"),
                "risk_score": sec.get("risk_score"),
                "security_findings": findings,
            }
            if isinstance(event.get("event_id"), int):
                event_to_node[event["event_id"]] = node_id
            last_node_id = node_id

        elif event_type == "security_summary":
            node_id = _event_node_id(event, "Summary", misc_seq)
            misc_seq += 1
            summary_text = event.get("summary")
            if isinstance(summary_text, dict):
                summary_preview = json.dumps(summary_text, ensure_ascii=False)[:80]
            else:
                summary_preview = str(summary_text)[:80]

            node_color, badge = _risk_color_and_badge(event, "#d9ead3")
            label = f"Security Summary{badge}\n{summary_preview}"
            G.add_node(node_id, label=label, color=node_color, shape="h")
            G.add_edge(last_node_id, node_id, edge_type="timeline")
            node_details[node_id] = {
                "step_type": "Security Summary",
                "agent": "SecurityMonitor",
                "content": summary_text,
                "event_id": event.get("event_id"),
                "risk_level": sec.get("risk_level"),
                "risk_score": sec.get("risk_score"),
                "security_findings": findings,
            }
            if isinstance(event.get("event_id"), int):
                event_to_node[event["event_id"]] = node_id
            last_node_id = node_id

        elif event_type == "final":
            node_id = _event_node_id(event, "Final", misc_seq)
            misc_seq += 1
            node_color, badge = _risk_color_and_badge(event, "#f0f0f0")
            label = f"End{badge}"
            G.add_node(node_id, label=label, color=node_color, shape="o")
            G.add_edge(last_node_id, node_id, edge_type="timeline")
            node_details[node_id] = {
                "step_type": "Final Report",
                "agent": event.get("agent", "ReporterAgent"),
                "final_result": event.get("answer"),
                "event_id": event.get("event_id"),
                "risk_level": sec.get("risk_level"),
                "risk_score": sec.get("risk_score"),
                "security_findings": findings,
                "decision_phase": event.get("decision_phase"),
                "causal_parents": event.get("causal_parents", []),
            }
            if isinstance(event.get("event_id"), int):
                event_to_node[event["event_id"]] = node_id
            last_node_id = node_id

    # Draw explicit causal links from causal_parents fields.
    for event in events:
        eid = event.get("event_id")
        if not isinstance(eid, int):
            continue
        child_node = event_to_node.get(eid)
        if not child_node:
            continue
        for parent in event.get("causal_parents", []) or []:
            if not isinstance(parent, int):
                continue
            parent_node = event_to_node.get(parent)
            if parent_node and not G.has_edge(parent_node, child_node):
                G.add_edge(parent_node, child_node, edge_type="causal")

    return G, node_details, security_summary, event_to_node


def optimize_agent_order(G: nx.DiGraph, node_details: Dict[str, Dict[str, Any]]) -> List[str]:
    agents = set()
    for n in G.nodes():
        details = node_details.get(n, {})
        agent = details.get("agent")
        if agent and not _is_hidden_plot_agent(agent):
            agents.add(agent)
    agents = list(agents)

    if len(agents) <= 2:
        if "User" in agents:
            agents.remove("User")
            agents.insert(0, "User")
        return agents

    G_int = nx.Graph()
    G_int.add_nodes_from(agents)

    sorted_nodes = sorted(
        G.nodes(),
        key=lambda n: (
            node_details.get(n, {}).get("event_id")
            if isinstance(node_details.get(n, {}).get("event_id"), int)
            else -1 if n == "Start" else 10**9
        ),
    )

    for i in range(len(sorted_nodes) - 1):
        u, v = sorted_nodes[i], sorted_nodes[i + 1]
        agent_u = node_details.get(u, {}).get("agent")
        agent_v = node_details.get(v, {}).get("agent")
        if agent_u and agent_v and agent_u != agent_v:
            w = G_int.get_edge_data(agent_u, agent_v, default={"weight": 0})["weight"]
            G_int.add_edge(agent_u, agent_v, weight=w + 10)

    try:
        pos_spectral = nx.spectral_layout(G_int, weight="weight", dim=1, scale=len(agents))
        agent_scores = {agent: float(pos_spectral[agent][0]) for agent in agents}
        sorted_agents = sorted(agents, key=lambda a: agent_scores[a])
    except Exception:
        sorted_agents = sorted(agents)

    if "User" in sorted_agents:
        sorted_agents.remove("User")
        sorted_agents.insert(0, "User")
    return sorted_agents


def _extract_chain_edges(summary: Dict[str, Any], event_to_node: Dict[int, str]) -> List[Tuple[str, str]]:
    chain_edges: List[Tuple[str, str]] = []
    chains = summary.get("attack_chains") or []
    for ch in chains:
        path_ids = ch.get("path_event_ids") or []
        path_nodes = [event_to_node.get(eid) for eid in path_ids if isinstance(eid, int)]
        path_nodes = [n for n in path_nodes if n]
        for i in range(len(path_nodes) - 1):
            chain_edges.append((path_nodes[i], path_nodes[i + 1]))
    return chain_edges


def draw_graph(
    G: nx.DiGraph,
    output_img_path: str,
    node_details: Dict[str, Dict[str, Any]],
    security_summary: Dict[str, Any],
    event_to_node: Dict[int, str],
    source_log_name: str = "",
):
    visible_nodes = []
    for n in G.nodes():
        if n == "Start":
            visible_nodes.append(n)
            continue
        agent = node_details.get(n, {}).get("agent")
        if _is_hidden_plot_agent(agent):
            continue
        visible_nodes.append(n)

    G_plot = G.subgraph(visible_nodes).copy()
    node_count = max(1, len(G_plot.nodes))
    fig_height = max(12, node_count * 1.0)
    plt.figure(figsize=(19, fig_height))

    plt.rcParams["font.sans-serif"] = ["Arial Unicode MS", "SimHei", "sans-serif"]
    plt.rcParams["axes.unicode_minus"] = False

    sorted_agents = optimize_agent_order(G_plot, node_details)
    if len(sorted_agents) > 1:
        x_step = 12.0 / (len(sorted_agents) - 1)
        agent_x_map = {agent: -6 + i * x_step for i, agent in enumerate(sorted_agents)}
        lane_boundaries = [(-6 + i * x_step - x_step / 2, -6 + i * x_step + x_step / 2) for i in range(len(sorted_agents))]
    else:
        agent_x_map = {sorted_agents[0]: 0} if sorted_agents else {}
        lane_boundaries = [(-6, 6)]

    # Sort by event id for stable vertical order.
    ordered_nodes = sorted(
        G_plot.nodes(),
        key=lambda n: (
            node_details.get(n, {}).get("event_id")
            if isinstance(node_details.get(n, {}).get("event_id"), int)
            else -1 if n == "Start" else 10**9
        ),
    )

    pos = {}
    for i, node in enumerate(ordered_nodes):
        agent = node_details.get(node, {}).get("agent", "Unknown")
        if node == "Start":
            x = 0
        else:
            x = agent_x_map.get(agent, 0)
        pos[node] = (x, -i)

    y_min = -len(ordered_nodes) + 0.5
    y_max = 1.8
    ax = plt.gca()
    lane_colors = ["#f7f7f7", "#ececec"]
    for i, (left, right) in enumerate(lane_boundaries):
        rect = plt.Rectangle((left, y_min), right - left, y_max - y_min, color=lane_colors[i % 2], alpha=0.4, zorder=0, linewidth=0)
        ax.add_patch(rect)
        agent_name = sorted_agents[i] if i < len(sorted_agents) else ""
        plt.text(
            (left + right) / 2,
            1.1,
            agent_name,
            fontsize=12,
            fontweight="bold",
            ha="center",
            va="bottom",
            color="#333333",
            bbox=dict(facecolor="white", alpha=0.9, edgecolor="gray", boxstyle="round,pad=0.4"),
        )

    labels = nx.get_node_attributes(G_plot, "label")

    shapes = set(nx.get_node_attributes(G_plot, "shape").values())
    if not shapes:
        shapes = {"o"}

    for shape in shapes:
        nodelist = [n for n, attr in G_plot.nodes(data=True) if attr.get("shape", "o") == shape]
        if not nodelist:
            continue
        colors = [G_plot.nodes[n].get("color", "white") for n in nodelist]
        nx.draw_networkx_nodes(
            G_plot,
            pos,
            nodelist=nodelist,
            node_color=colors,
            node_size=2600,
            alpha=1.0,
            edgecolors="black",
            linewidths=1.0,
            node_shape=shape,
        )

    timeline_edges = [(ordered_nodes[i], ordered_nodes[i + 1]) for i in range(len(ordered_nodes) - 1)]
    causal_edges = [(u, v) for u, v, d in G_plot.edges(data=True) if d.get("edge_type") == "causal"]
    call_return_edges = [(u, v) for u, v, d in G_plot.edges(data=True) if d.get("edge_type") == "call_return"]

    nx.draw_networkx_edges(
        G_plot,
        pos,
        edgelist=timeline_edges,
        arrowstyle="-|>",
        arrowsize=18,
        edge_color="#666666",
        width=1.4,
        connectionstyle="arc3,rad=0",
    )

    if causal_edges:
        nx.draw_networkx_edges(
            G_plot,
            pos,
            edgelist=causal_edges,
            arrowstyle="-|>",
            arrowsize=14,
            edge_color="#4c78a8",
            style="dashed",
            width=1.2,
            connectionstyle="arc3,rad=0.06",
        )

    if call_return_edges:
        nx.draw_networkx_edges(
            G_plot,
            pos,
            edgelist=call_return_edges,
            arrowstyle="-|>",
            arrowsize=14,
            edge_color="#59a14f",
            style="dashdot",
            width=1.2,
            connectionstyle="arc3,rad=-0.08",
        )

    chain_edges = _extract_chain_edges(security_summary, event_to_node)
    visible_node_set = set(G_plot.nodes())
    chain_edges = [(u, v) for u, v in chain_edges if u in visible_node_set and v in visible_node_set]
    if chain_edges:
        nx.draw_networkx_edges(
            G_plot,
            pos,
            edgelist=chain_edges,
            arrowstyle="-|>",
            arrowsize=22,
            edge_color="#d62728",
            width=2.8,
            connectionstyle="arc3,rad=0.12",
        )

    nx.draw_networkx_labels(G_plot, pos, labels, font_size=8, font_family="sans-serif")

    legend_elements = [
        Line2D([0], [0], marker="o", color="w", label="Start/End", markerfacecolor="#f0f0f0", markersize=12, markeredgecolor="black"),
        Line2D([0], [0], marker="s", color="w", label="Message", markerfacecolor="#cfe8ff", markersize=12, markeredgecolor="black"),
        Line2D([0], [0], marker="d", color="w", label="Tool", markerfacecolor="#c7f0d8", markersize=12, markeredgecolor="black"),
        Line2D([0], [0], color="#4c78a8", lw=1.2, linestyle="dashed", label="Causal Edge"),
        Line2D([0], [0], color="#d62728", lw=2.8, label="Attack Chain"),
        Line2D([0], [0], color="#666666", lw=1.4, label="Timeline Edge"),
    ]
    ax.legend(handles=legend_elements, loc="upper right", title="Legend", framealpha=0.92, edgecolor="gray", fontsize=9, title_fontsize=10)

    chain_count = security_summary.get("attack_chain_count", 0)
    succ_count = security_summary.get("successful_attack_chain_count", 0)
    method_info = security_summary.get("method", {}) if isinstance(security_summary.get("method"), dict) else {}
    method_name = method_info.get("name", "UnknownMethod")
    method_ver = method_info.get("version", "N/A")
    plt.title(
        f"MAS Execution Trajectory: {source_log_name}\n"
        f"method={method_name} v{method_ver} | "
        f"attack_chains={chain_count}, successful={succ_count}, max_risk={security_summary.get('max_risk_score', 0)}",
        fontsize=15,
        pad=18,
    )

    plt.xlim(-7, 7)
    plt.ylim(-node_count - 1, 3)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_img_path, dpi=320, bbox_inches="tight")
    print(f"Graph image saved to: {output_img_path}")


def save_details(node_details: Dict[str, Dict[str, Any]], output_txt_path: str):
    with open(output_txt_path, "w", encoding="utf-8") as f:
        f.write("=== MAS Execution Trajectory Details ===\n\n")
        for node_id, details in node_details.items():
            f.write(f"Node ID: {node_id}\n")
            for k, v in details.items():
                f.write(f"  {k}: {v}\n")
            f.write("-" * 70 + "\n")
    print(f"Detailed logs saved to: {output_txt_path}")


def save_security_report(
    summary: Dict[str, Any],
    node_details: Dict[str, Dict[str, Any]],
    output_json_path: str,
    output_txt_path: str,
    chain_txt_path: str,
):
    incidents = []
    for node_id, details in node_details.items():
        findings = details.get("security_findings") or []
        if not findings:
            continue
        incidents.append(
            {
                "node_id": node_id,
                "event_id": details.get("event_id"),
                "agent": details.get("agent"),
                "risk_level": details.get("risk_level"),
                "risk_score": details.get("risk_score"),
                "findings": findings,
            }
        )

    report = {
        "summary": summary,
        "incidents": incidents,
    }

    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    with open(output_txt_path, "w", encoding="utf-8") as f:
        f.write("=== MAS Security Summary ===\n")
        f.write(json.dumps(summary, ensure_ascii=False, indent=2))
        f.write("\n\n=== High-Risk Incidents ===\n")
        if not incidents:
            f.write("No incidents detected.\n")
        else:
            for inc in incidents:
                f.write(
                    f"- node={inc['node_id']} event={inc['event_id']} agent={inc['agent']} "
                    f"risk={inc['risk_level']}({inc['risk_score']}) findings={len(inc['findings'])}\n"
                )
                for fd in inc["findings"]:
                    f.write(
                        f"  * {fd.get('category')} sev={fd.get('severity')} conf={fd.get('confidence')} "
                        f"dim={fd.get('dimension')} evidence={fd.get('evidence')}\n"
                    )

    chains = summary.get("attack_chains") or []
    with open(chain_txt_path, "w", encoding="utf-8") as f:
        f.write("=== MAS Attack Chains ===\n")
        if not chains:
            f.write("No attack chains detected.\n")
        else:
            for i, ch in enumerate(chains, start=1):
                f.write(
                    f"[{i}] type={ch.get('attack_type')} status={ch.get('status')} "
                    f"conf={ch.get('confidence')} source={ch.get('source_event_id')} "
                    f"sink={ch.get('sink_event_id')}\n"
                )
                f.write(f"    path={ch.get('path_event_ids')}\n")
                f.write(f"    entities={ch.get('evidence_entities')}\n")

    print(f"Security report saved to: {output_json_path}")
    print(f"Security summary text saved to: {output_txt_path}")
    print(f"Attack chain text saved to: {chain_txt_path}")


# ================= 配置区域 =================
# 在这里显式指定要分析的日志文件
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_TO_ANALYZE = os.path.join(SCRIPT_DIR, "autogen_trace_20260316_145652.jsonl")


if __name__ == "__main__":
    if not LOG_FILE_TO_ANALYZE:
        print("Error: LOG_FILE_TO_ANALYZE is empty.")
        sys.exit(1)

    log_file = os.path.abspath(LOG_FILE_TO_ANALYZE)
    print(f"Using configured log file: {log_file}")

    log_basename = os.path.splitext(os.path.basename(log_file))[0]
    generate_time = datetime.now().strftime("%Y%m%d_%H%M%S")

    base_dir = SCRIPT_DIR
    output_folder_name = f"trajectory_output_{generate_time}_{log_basename}"
    output_dir = os.path.join(base_dir, output_folder_name)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")

    img_file = os.path.join(output_dir, f"{log_basename}_graph.png")
    details_file = os.path.join(output_dir, f"{log_basename}_details.txt")
    security_json_file = os.path.join(output_dir, f"{log_basename}_security_report.json")
    security_txt_file = os.path.join(output_dir, f"{log_basename}_security_summary.txt")
    attack_chain_txt_file = os.path.join(output_dir, f"{log_basename}_attack_chains.txt")

    if not os.path.exists(log_file):
        print(f"Error: File not found {log_file}")
        sys.exit(1)

    print(f"Processing log file: {log_file}...")
    print(f"Output Image: {img_file}")
    print(f"Output Details: {details_file}")
    print(f"Output Security JSON: {security_json_file}")
    print(f"Output Security TXT: {security_txt_file}")
    print(f"Output Chain TXT: {attack_chain_txt_file}")

    G, details, security_summary, event_to_node = parse_log_to_graph(log_file)
    draw_graph(
        G,
        img_file,
        details,
        security_summary=security_summary,
        event_to_node=event_to_node,
        source_log_name=log_basename,
    )
    save_details(details, details_file)
    save_security_report(
        security_summary,
        details,
        security_json_file,
        security_txt_file,
        attack_chain_txt_file,
    )
    print("Done.")
