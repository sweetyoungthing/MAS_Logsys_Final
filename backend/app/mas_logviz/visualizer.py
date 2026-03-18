import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import textwrap
from datetime import datetime
import os
from matplotlib.lines import Line2D
import glob
import sys

def parse_log_to_graph(log_path):
    """
    解析日志文件并构建有向图
    """
    events = []
    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    G = nx.DiGraph()
    
    # 节点列表，用于按顺序存储详细信息
    node_details = {}
    
    last_node_id = "Start"
    G.add_node(last_node_id, label="Start", color="lightgray", shape="o")
    node_details[last_node_id] = {"info": "系统初始化"}

    pending_tool_calls = [] # 栈结构处理嵌套或并发（虽然本例主要是串行）
    last_agent_name = "System"

    msg_count = 0
    tool_count = 0

    for i, event in enumerate(events):
        event_type = event.get("type")
        
        if event_type == "message":
            agent = event.get("agent") or event.get("name") or "Unknown"
            # 忽略作为工具输出回传的 message，因为我们通过 tool_call_end 已经记录了结果
            # 但有时候 tool output message 包含额外解释，这里为了简化图结构，
            # 如果 role 是 tool，我们可以选择跳过，或者作为普通消息连接
            role = event.get("role")
            
            # 创建消息节点
            node_id = f"Msg_{msg_count}"
            msg_count += 1
            
            content = event.get("content") or event.get("content_preview") or ""
            # 截断过长的内容用于显示
            display_content = (content[:30] + '...') if content and len(content) > 30 else content
            
            # 根据 role 区分 Action 类型
            if role == "tool":
                action_type = "Tool Output"
            elif role == "system":
                action_type = "System Info"
            else:
                action_type = "Speak"

            label = f"Agent: {agent}\nAction: {action_type}\nMsg: {display_content}"
            
            G.add_node(node_id, label=label, color="lightblue", shape="s")
            G.add_edge(last_node_id, node_id)
            
            # 记录详细信息
            node_details[node_id] = {
                "step_type": "Message",
                "agent": agent,
                "input_context": f"Previous step: {last_node_id}",
                "action": "Send Message",
                "content": content,
                "timestamp": event.get("ts")
            }
            
            last_node_id = node_id
            last_agent_name = agent # 更新最近的发言者，可能是工具调用者

        elif event_type == "tool_call_start":
            pending_tool_calls.append({
                "tool": event.get("tool"),
                "args": event.get("args"),
                "kwargs": event.get("kwargs"),
                "caller": last_agent_name, # 归因为上一个发言的智能体
                "ts": event.get("ts")
            })

        elif event_type == "tool_call_end":
            if pending_tool_calls:
                start_info = pending_tool_calls.pop()
                tool_name = start_info["tool"]
                caller = start_info["caller"]
                
                status = event.get("status")
                result = event.get("result")
                
                # 创建工具节点
                node_id = f"Tool_{tool_count}"
                tool_count += 1
                
                # 处理参数显示
                args_str = str(start_info.get("kwargs", ""))
                display_args = (args_str[:20] + '...') if len(args_str) > 20 else args_str
                
                display_result = (str(result)[:30] + '...') if result and len(str(result)) > 30 else str(result)
                
                label = f"Agent: {caller}\nAction: Call Tool\nTool: {tool_name}\nArgs: {display_args}\nStatus: {status}\nRes: {display_result}"                
                color = "lightgreen" if status == "SUCCESS" else "salmon"
                G.add_node(node_id, label=label, color=color, shape="d") # d for diamond
                G.add_edge(last_node_id, node_id)
                
                # 记录详细信息
                node_details[node_id] = {
                    "step_type": "Tool Execution",
                    "agent": caller,
                    "tool_name": tool_name,
                    "action": "Call Tool",
                    "input_args": start_info["kwargs"],
                    "status": status,
                    "detailed_result": result,
                    "timestamp": event.get("ts")
                }
                
                last_node_id = node_id

        elif event_type == "final":
            # 结束节点
            node_id = "End"
            G.add_node(node_id, label="End", color="lightgray", shape="o")
            G.add_edge(last_node_id, node_id)
            node_details[node_id] = {"info": "任务结束", "final_result": event.get("answer")}

    return G, node_details

def optimize_agent_order(G, node_details):
    """
    使用谱布局算法 (Spectral Layout) 优化 Agent 的排列顺序，
    使得交互频繁的 Agent 在泳道中相邻，减少连线跨度。
    """
    # 1. 识别所有 Agent
    agents = set()
    for nid, details in node_details.items():
        if "agent" in details:
            agents.add(details["agent"])
    agents = list(agents)
    
    if len(agents) <= 2:
        # 如果少于等于2个，直接按默认排序，User在前
        if "User" in agents:
            agents.remove("User")
            agents.insert(0, "User")
        return agents

    # 2. 构建 Agent 交互图 (Interaction Graph)
    G_int = nx.Graph()
    G_int.add_nodes_from(agents)
    
    # 遍历时序图的边，累加 Agent 间的权重
    
    # 提取节点按时间顺序排列的列表
    sorted_nodes = sorted(G.nodes(), key=lambda n: int(n.split('_')[1]) if '_' in n else -1 if n=="Start" else 99999)
    
    # 增加时序链上的权重
    for i in range(len(sorted_nodes)-1):
        u = sorted_nodes[i]
        v = sorted_nodes[i+1]
        
        agent_u = node_details.get(u, {}).get("agent")
        agent_v = node_details.get(v, {}).get("agent")
        
        if agent_u and agent_v and agent_u != agent_v:
             # 增加权重
             w = G_int.get_edge_data(agent_u, agent_v, default={'weight': 0})['weight']
             G_int.add_edge(agent_u, agent_v, weight=w + 10) # 大幅增加直接时序相邻的权重

    # 3. 使用 Spectral Layout 计算一维嵌入
    # scale=len(agents) 可以让坐标分布更开
    try:
        pos_spectral = nx.spectral_layout(G_int, weight='weight', dim=1, scale=len(agents))
        # pos_spectral 返回字典 {agent: array([x])}
        
        # 提取坐标并排序
        agent_scores = {agent: pos_spectral[agent][0] for agent in agents}
        sorted_agents = sorted(agents, key=lambda a: agent_scores[a])
    except Exception as e:
        print(f"Spectral layout failed, falling back to simple sort: {e}")
        sorted_agents = sorted(agents)

    # 4. 强制 User 在最左侧 (可选优化)
    # 虽然 Spectral 找到了最优相对位置，但为了阅读习惯，我们常希望 User 作为起点
    if "User" in sorted_agents:
        sorted_agents.remove("User")
        sorted_agents.insert(0, "User")
        
    return sorted_agents

def draw_graph(G, output_img_path, node_details, source_log_name="", show=False):
    """
    绘制并保存图片
    """
    # 根据节点数量动态计算图片高度，防止节点重叠
    node_count = len(G.nodes)
    fig_height = max(12, node_count * 1.2)
    plt.figure(figsize=(18, fig_height)) # 加宽
    
    # 设置字体以支持中文显示
    # Mac/Linux/Windows 兼容性处理
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'SimHei', 'sans-serif'] 
    plt.rcParams['axes.unicode_minus'] = False
    
    # === 智能泳道布局 (Smart Swimlane Layout) ===
    # 1. 使用算法优化 Agent 顺序
    sorted_agents = optimize_agent_order(G, node_details)
    
    # 2. 创建 Agent 到 X 坐标的映射
    # 范围分布在 [-6, 6] 之间
    if len(sorted_agents) > 1:
        x_step = 12.0 / (len(sorted_agents) - 1)
        # 为每个 Agent 分配一个中心 X 坐标
        agent_x_map = {agent: -6 + i * x_step for i, agent in enumerate(sorted_agents)}
        
        # 计算泳道边界（用于绘制背景）
        lane_boundaries = []
        for i in range(len(sorted_agents)):
            center = -6 + i * x_step
            left = center - x_step / 2
            right = center + x_step / 2
            lane_boundaries.append((left, right))
    else:
        agent_x_map = {sorted_agents[0]: 0} if sorted_agents else {}
        lane_boundaries = [(-6, 6)]
        
    pos = {}
    for i, node in enumerate(G.nodes()):
        # 获取该节点的 Agent
        details = node_details.get(node, {})
        agent = details.get("agent", "Unknown")
        
        # 特殊处理 Start 和 End，放在正中间
        if node in ["Start", "End"]:
            x = 0
        else:
            x = agent_x_map.get(agent, 0)
            
        # y随着索引递减
        pos[node] = (x, -i)
    
    # === 绘制泳道背景 (Swimlane Backgrounds) ===
    # 获取 Y 轴范围
    y_min = -len(G.nodes) + 0.5
    y_max = 1.5
    
    ax = plt.gca()
    colors = ['#f0f0f0', '#e0e0e0'] # 交替颜色
    for i, (left, right) in enumerate(lane_boundaries):
        # 绘制矩形背景
        rect = plt.Rectangle((left, y_min), right-left, y_max-y_min, 
                             color=colors[i % 2], alpha=0.3, zorder=0, linewidth=0)
        ax.add_patch(rect)
        
        # 顶部标注 Agent 名字
        agent_name = sorted_agents[i] if i < len(sorted_agents) else ""
        plt.text((left+right)/2, 1, agent_name, fontsize=14, fontweight='bold', 
                 ha='center', va='bottom', color='#333333',
                 bbox=dict(facecolor='white', alpha=0.9, edgecolor='gray', boxstyle='round,pad=0.5'))

    # 提取节点属性
    labels = nx.get_node_attributes(G, 'label')
    
    # === 按形状分组绘制节点 ===
    # NetworkX 的 draw_networkx_nodes 一次只能画一种形状
    # 形状映射: 'o' -> Circle, 's' -> Square, 'd' -> Diamond, '^' -> Triangle
    
    # 1. 整理不同形状的节点列表
    shapes = set(nx.get_node_attributes(G, 'shape').values())
    if not shapes:
        shapes = {'o'} # 默认圆形
        
    for shape in shapes:
        # 筛选出当前形状的节点
        nodelist = [n for n, attr in G.nodes(data=True) if attr.get('shape', 'o') == shape]
        if not nodelist:
            continue
            
        # 获取这些节点的颜色
        colors = [G.nodes[n].get('color', 'white') for n in nodelist]
        
        # 绘制
        nx.draw_networkx_nodes(G, pos, 
                             nodelist=nodelist,
                             node_color=colors, 
                             node_size=3000, 
                             alpha=1.0, # 不透明
                             edgecolors='black', # 黑色边框更清晰
                             linewidths=1.0,
                             node_shape=shape) # 关键：应用形状
    
    # 绘制边
    # 优化：全部使用直线，确保不乱且不报错。
    # 在单行单节点的时序图中，直线是最清晰且绝对不会交叉的路径。
    
    nx.draw_networkx_edges(G, pos, arrowstyle='-|>', arrowsize=20, 
                           edge_color='#555555', width=1.5, 
                           connectionstyle="arc3,rad=0")
    
    # 绘制标签
    nx.draw_networkx_labels(G, pos, labels, font_size=9, font_family='sans-serif')
    
    # === 添加图例 (Legend) ===
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', label='Start/End', 
               markerfacecolor='lightgray', markersize=15, markeredgecolor='black'),
        Line2D([0], [0], marker='s', color='w', label='Message', 
               markerfacecolor='lightblue', markersize=15, markeredgecolor='black'),
        Line2D([0], [0], marker='d', color='w', label='Tool Success', 
               markerfacecolor='lightgreen', markersize=15, markeredgecolor='black'),
        Line2D([0], [0], marker='d', color='w', label='Tool Failed', 
               markerfacecolor='salmon', markersize=15, markeredgecolor='black'),
    ]
    ax.legend(handles=legend_elements, loc='upper right', title="Node Types", 
              framealpha=0.9, edgecolor='gray', fontsize=10, title_fontsize=11)

    plt.title(f"MAS Execution Trajectory: {source_log_name}", fontsize=18, pad=20)
    
    # 调整坐标轴范围
    plt.xlim(-7, 7)
    plt.ylim(-node_count - 1, 3)
    plt.axis('off')
    
    plt.tight_layout()
    plt.savefig(output_img_path, dpi=300, bbox_inches='tight')
    print(f"Graph image saved to: {output_img_path}")

    if show:
        try:
            plt.show()
        except Exception as e:
            print(f"Failed to pop up interactive window: {e}")

def save_details(node_details, output_txt_path):
    """
    保存详细的节点信息到文本文件
    """
    with open(output_txt_path, 'w', encoding='utf-8') as f:
        f.write("=== MAS Execution Trajectory Details ===\n\n")
        for node_id, details in node_details.items():
            f.write(f"Node ID: {node_id}\n")
            for k, v in details.items():
                f.write(f"  {k}: {v}\n")
            f.write("-" * 50 + "\n")
    print(f"Detailed logs saved to: {output_txt_path}")

def visualize_log(log_file, output_dir=None, show=True):
    """
    主入口：可视化指定的日志文件
    """
    if not os.path.exists(log_file):
        print(f"Error: File not found {log_file}")
        return

    # 转换为绝对路径
    log_file = os.path.abspath(log_file)
    
    # 获取文件名（不带扩展名）作为输出文件的前缀
    log_basename = os.path.splitext(os.path.basename(log_file))[0]
    
    # 生成时间戳
    generate_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_dir is None:
        # 输出文件目录
        base_dir = os.path.dirname(log_file)
        output_folder_name = f"trajectory_output_{generate_time}_{log_basename}"
        output_dir = os.path.join(base_dir, output_folder_name)
    
    # 创建文件夹
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")

    # 输出文件路径
    img_file = os.path.join(output_dir, f"{log_basename}_graph.png")
    details_file = os.path.join(output_dir, f"{log_basename}_details.txt")

    print(f"Processing log file: {log_file}...")
    print(f"Output Image: {img_file}")
    print(f"Output Details: {details_file}")
    
    G, details = parse_log_to_graph(log_file)
    draw_graph(G, img_file, details, source_log_name=log_basename, show=show)
    save_details(details, details_file)
    print("Visualization Done.")
    return img_file

def get_latest_log_file(log_dir):
    """获取最新的日志文件"""
    pattern = os.path.join(log_dir, "autogen_trace_*.jsonl")
    log_files = glob.glob(pattern)
    if not log_files:
        return None
    return max(log_files, key=os.path.getmtime)
