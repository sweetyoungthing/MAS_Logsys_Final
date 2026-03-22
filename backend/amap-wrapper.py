#!/usr/bin/env python
"""包装 amap_mcp_server，确保使用修改过的 server.py"""
import sys
import os

# 不要修改 sys.path，让 Python 自动选择正确的路径
# /opt/anaconda3/bin/python 的 sys.path 中 .local 会在 anaconda 之前

# 从 amap_mcp_server 导入 main
from amap_mcp_server import main

if __name__ == '__main__':
    sys.exit(main())
