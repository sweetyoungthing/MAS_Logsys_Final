# MAS Logsys Final

基于 FastAPI、Vue 3 和多智能体编排的智能旅行规划毕业设计系统。项目同时包含旅行规划、地图服务、安全拦截、MAS 运行轨迹可视化，以及若干工程化脚本，目标是提供一个可演示、可扩展、可维护的完整系统，而不是单纯的实验代码集合。

## 项目概览

系统主要提供以下能力：

- 智能旅行规划：根据城市、日期、偏好等信息生成多日行程。
- 地图与 POI 服务：集成高德地图，支持 POI 搜索、天气查询、路线规划和地理编码。
- 安全防护：对请求与响应进行统一风险识别和拦截，避免 Prompt Injection、越权指令和敏感信息泄露。
- 结果页工程化：旅行计划支持后端持久化，页面刷新后可恢复。
- MAS 可观测性：记录多智能体运行日志，并生成最新轨迹图。

## 技术栈

### 后端

- FastAPI
- Pydantic / pydantic-settings
- httpx
- HelloAgents
- Matplotlib / NetworkX / Pandas

### 前端

- Vue 3
- TypeScript
- Vite
- Vue Router
- Ant Design Vue
- Axios

## 项目结构

```text
MAS_Logsys_Final/
├── backend/                    # FastAPI 后端
│   ├── app/
│   │   ├── agents/            # 多智能体旅行规划
│   │   ├── api/               # 路由与应用入口
│   │   ├── mas_logviz/        # MAS 日志可视化
│   │   ├── models/            # Pydantic 数据模型
│   │   ├── security/          # 安全分析、中间件、依赖与异常
│   │   └── services/          # Amap / Unsplash / LLM / Plan Store
│   ├── data/                  # 持久化旅行计划
│   ├── logs/                  # MAS 运行日志与轨迹图缓存
│   ├── tests/                 # 后端测试
│   ├── .env.example
│   ├── requirements.txt
│   └── run.py
├── frontend/                  # Vue 3 前端
│   ├── src/
│   │   ├── services/          # API 请求层与前端测试
│   │   ├── stores/            # 本地状态缓存
│   │   ├── types/             # 前端类型定义
│   │   └── views/             # 页面
│   ├── .env.example
│   └── package.json
├── scripts/                   # 工程辅助脚本
│   ├── autogen_system.py
│   ├── generate_trajectory_graph_autogen.py
│   └── security_experiment.py
├── .gitignore
└── README.md
```

## 系统架构

### 后端分层

- API 层：`backend/app/api/routes/`
  - 暴露旅行规划、地图、POI、MAS 轨迹等接口。
- Security 层：`backend/app/security/`
  - 通过中间件、依赖和统一异常把安全识别与业务逻辑解耦。
- Service 层：`backend/app/services/`
  - 封装高德地图、Unsplash、LLM 调用和旅行计划持久化。
- Agent 层：`backend/app/agents/`
  - 组织景点、天气、酒店和总规划 Agent 协作。

### 前端分层

- View 层：`frontend/src/views/`
  - `Home.vue` 负责用户输入。
  - `Result.vue` 负责结果展示、编辑、导出和轨迹图查看。
- Service 层：`frontend/src/services/api.ts`
  - 统一处理接口调用、异常包装和安全拦截提示。
- Store 层：`frontend/src/stores/tripPlan.ts`
  - 缓存 `planId` 和旅行计划，配合后端持久化恢复页面状态。

## 核心能力说明

### 1. 安全拦截

系统在关键接口上启用了统一安全防护：

- 请求侧：对高风险输入进行风险分析并阻断。
- 响应侧：对生成内容和外部服务返回内容做二次扫描。
- 前端侧：当后端返回 `403 + SECURITY_RISK_BLOCKED` 时，统一弹出全局错误提示。

相关代码位置：

- `backend/app/security/`
- `frontend/src/services/api.ts`
- `backend/tests/test_security_integration.py`
- `frontend/src/services/api.test.ts`

### 2. Amap 服务

`backend/app/services/amap_service.py` 已封装高德 REST API 调用，并补充了：

- 输入参数校验
- 超时与网络异常处理
- 限流与上游错误映射
- 结构化日志记录

当前已实现的核心能力：

- POI 搜索
- 天气查询
- 路线规划
- 地理编码
- POI 详情查询

### 3. 旅行计划持久化

旅行规划接口在生成结果后会把计划保存到：

- `backend/data/trip_plans/`

前端结果页通过 `planId` 拉取数据，因此刷新页面后仍可恢复旅行计划。

### 4. MAS 轨迹可视化

系统会将多智能体运行过程记录为日志，并支持生成最新轨迹图：

- 原始日志目录：`backend/logs/`
- 可视化缓存目录：`backend/logs/viz_cache/`
- 接口：`GET /api/mas/latest-trace`

## MAS 日志记录机制

主系统的 MAS 日志能力位于 `backend/app/mas_logviz/`，核心由三部分组成：

- `logger.py`
  - 负责初始化本次运行上下文、生成日志文件路径、脱敏并按 JSONL 逐行写入事件。
- `instrument.py`
  - 负责给 Agent 和工具打“埋点”，把运行过程中的输入、输出、工具调用自动转成日志事件。
- `visualizer.py`
  - 负责读取日志、还原时序关系并绘制轨迹图。

### 记录链路

在旅行规划主流程中，`backend/app/agents/trip_planner_agent.py` 会在开始规划时调用 `init_context()` 初始化日志上下文，并根据配置决定是否启用 MAS 日志记录。

之后，系统通过两种方式写日志：

- Agent 日志
  - `instrument_agent()` 包装各个 Agent 的 `run()` 方法。
  - 在 Agent 接收输入时记录一条 `message` 事件。
  - 在 Agent 产出结果时再记录一条 `message` 事件。
- 工具日志
  - `instrument_mcp_tool()` 尝试包装工具的 `run`、`execute` 或 `__call__` 方法。
  - 工具调用开始时记录 `tool_call_start`。
  - 工具调用结束时记录 `tool_call_end`，包含状态、耗时、结果摘要和异常类型。

### 日志事件结构

主系统当前记录的核心事件类型包括：

- `message`
  - 记录消息发送者、角色、消息内容预览、长度和当前步骤。
- `tool_call_start`
  - 记录工具名称、参数、父消息编号和调用跨度 `span_id`。
- `tool_call_end`
  - 记录调用状态、耗时、返回结果摘要、返回值哈希等信息。
- `final`
  - 作为任务结束节点参与轨迹图构建。

日志文件采用 JSONL 格式，便于后续追加写入、离线分析和图形转换。为了避免日志泄露敏感信息，`logger.py` 在写入前会对疑似 Key、Bearer Token 等内容做脱敏，并对超长文本进行截断。

## MAS 轨迹图生成机制

轨迹图的目标不是简单“画流程图”，而是把一次多智能体执行中的消息流、工具调用和最终结果按时序还原成有向图。

### 分析步骤

`backend/app/mas_logviz/visualizer.py` 的处理过程可以概括为：

1. 读取 `autogen_trace_*.jsonl`，逐行解析出事件列表。
2. 根据事件类型构造有向图节点。
3. 维护工具调用栈，把 `tool_call_start` 和 `tool_call_end` 配对。
4. 按执行顺序为节点连边，形成一条主时序链。
5. 根据节点所属 Agent 进行泳道布局，让不同 Agent 的交互在图上更容易分辨。
6. 用不同形状和颜色区分消息节点、工具节点、开始节点和结束节点。

### 图中元素含义

- 圆形节点
  - `Start` / `End`，表示一次执行的起点和终点。
- 方形节点
  - 普通消息事件，如用户输入或 Agent 回复。
- 菱形节点
  - 工具调用事件。
  - 成功调用为浅绿色，失败调用为红色系。
- 边
  - 默认表示主时序流向，即“上一步 -> 下一步”。

### 在线查看与离线分析

系统当前提供两种查看方式：

- 在线查看
  - 调用 `GET /api/mas/latest-trace`
  - 后端会读取 `backend/logs/` 下最新一份可解析日志，生成 PNG 并返回。
- 离线分析
  - 使用 `scripts/generate_trajectory_graph_autogen.py`
  - 可读取指定日志或默认读取最新日志，并把输出写入 `scripts/output/`

## 风险识别机制

当前主系统的风险识别位于 `backend/app/security/`，采用“规则分析器 + 路由依赖 + 中间件统一响应”的结构。

### 识别对象

系统会对两类内容做分析：

- 请求侧内容
  - 用户提交的 JSON Body、Query 参数、表单内容。
- 响应侧内容
  - 旅行规划结果、地图服务结果、POI 详情等即将返回给前端的数据。

### 识别流程

1. 路由通过 `security_guard(policy_name)` 提取请求内容。
2. `SecurityAnalyzer.assess_payload()` 递归展开 payload 中的文本字段。
3. 分析器对文本做归一化处理，并匹配多类风险模式。
4. 根据命中类别、命令式语气和疑似密钥泄露情况计算 `risk_score`。
5. 按阈值映射为 `none / low / medium / high / critical`。
6. 如果风险分数超过阈值，则抛出 `SecurityInterceptionError`。
7. `SecurityExceptionMiddleware` 统一将异常转换为 `403` JSON 响应。

### 当前识别的主要风险类型

- Prompt Injection
  - 例如“忽略之前指令”“泄露系统提示词”“override all rules”等。
- Communication Sabotage
  - 例如“不要信任某个 Agent”“停止与某个 Agent 通信”“替换其结果”等。
- Data Exfiltration Attempt
  - 例如“导出 API Key”“上传聊天记录”“发送 token/secret”等。
- Secret Token Leakage
  - 例如命中 `sk-...`、`Bearer ...` 等疑似敏感凭证模式。

### 风险评分与拦截结果

分析器会输出结构化结果 `SecurityAssessment`，其中包含：

- `risk_level`
- `risk_score`
- `blocked`
- `findings`
- `metadata`

一旦命中拦截条件，后端统一返回：

- HTTP 状态码：`403`
- 错误码：`SECURITY_RISK_BLOCKED`
- 返回体：`SecurityErrorResponse`

前端在 `frontend/src/services/api.ts` 中对这类响应进行了统一处理，会弹出全局提示，并把风险等级、风险分数等元信息保留在 `AppApiError` 中，方便页面层进一步处理。

## 环境准备

建议使用：

- Python 3.11+
- Node.js 18+
- npm 9+

## 环境变量

### 后端

复制模板并填写：

```bash
cp backend/.env.example backend/.env
```

关键变量说明：

- `AMAP_API_KEY`：高德 Web Service API Key
- `LLM_API_KEY` 或 `OPENAI_API_KEY`：模型服务 Key
- `LLM_BASE_URL`：模型服务地址
- `LLM_MODEL_ID`：模型名称
- `HOST` / `PORT`：后端监听地址
- `CORS_ORIGINS`：允许访问的前端地址
- `UNSPLASH_ACCESS_KEY`：景点图片服务 Key，可选

### 前端

复制模板并填写：

```bash
cp frontend/.env.example frontend/.env
```

关键变量说明：

- `VITE_API_BASE_URL`：后端接口基地址，开发环境建议保持 `/`
- `VITE_AMAP_WEB_KEY`：高德 Web API Key
- `VITE_AMAP_WEB_JS_KEY`：高德 JS API Key
- `VITE_AMAP_SECURITY_JS_CODE`：高德安全密钥，可选

## 快速开始

### 1. 启动后端

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

启动后可访问：

- API 文档：[http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc：[http://localhost:8000/redoc](http://localhost:8000/redoc)
- 健康检查：[http://localhost:8000/health](http://localhost:8000/health)

### 2. 启动前端

```bash
cd frontend
npm install
npm run dev
```

默认开发地址通常为：

- [http://localhost:5173](http://localhost:5173)

## 主要接口

### 旅行规划

- `POST /api/trip/plan`：生成旅行计划
- `GET /api/trip/plans/{plan_id}`：获取已保存旅行计划
- `PUT /api/trip/plans/{plan_id}`：更新旅行计划
- `GET /api/trip/health`：旅行规划服务健康检查

### 地图服务

- `GET /api/map/poi`
- `GET /api/map/weather`
- `POST /api/map/route`
- `GET /api/map/health`

### POI

- `GET /api/poi/detail/{poi_id}`
- `GET /api/poi/search`
- `GET /api/poi/photo`

### MAS 可视化

- `GET /api/mas/latest-trace`

## 测试

### 后端安全拦截测试

```bash
cd backend
.venv/bin/python -m unittest discover -s tests -p 'test_security_integration.py'
```

### 前端 API 拦截测试

```bash
cd frontend
npm run test
```

### 前端构建检查

```bash
cd frontend
npm run build
```

## 脚本说明

`scripts/` 目录中的文件属于工程辅助脚本，不参与主站运行链路：

- `scripts/autogen_system.py`
  - 独立运行多智能体样例并生成日志。
- `scripts/generate_trajectory_graph_autogen.py`
  - 读取日志并生成轨迹图。
- `scripts/security_experiment.py`
  - 运行安全识别相关的样本和评估逻辑。

这些脚本已经从仓库根目录迁移到 `scripts/`，目的是保持主系统与辅助工具的职责边界清晰。

## 数据与运行产物

以下目录通常是运行时生成，不建议提交到版本库：

- `backend/logs/`
- `backend/memory/traces/`
- `backend/data/trip_plans/`
- `scripts/output/`
- `frontend/node_modules/`
- `frontend/dist/`

项目已经在根目录 `.gitignore` 中对这些内容做了忽略配置。

## 常见问题

### 1. 后端启动时报配置缺失

请优先检查：

- `backend/.env` 是否存在
- `AMAP_API_KEY` 是否已配置
- `LLM_API_KEY` 或 `OPENAI_API_KEY` 是否已配置

### 2. 前端无法请求后端

请检查：

- 后端是否已启动在 `8000` 端口
- `frontend/.env` 中的 `VITE_API_BASE_URL` 是否正确
- `backend/.env` 中的 `CORS_ORIGINS` 是否包含当前前端地址

### 3. 结果页刷新后数据为空

当前设计依赖后端保存的 `planId` 和本地缓存恢复数据。若计划尚未成功保存，或本地缓存被清空，结果页将无法恢复先前内容。

### 4. MAS 轨迹图为空

请先确认：

- 已执行过一次旅行规划或相关脚本
- `backend/logs/` 下存在 `autogen_trace_*.jsonl`

## License

当前仓库未声明开源许可证。如需公开发布，建议补充明确的 License 文件。
