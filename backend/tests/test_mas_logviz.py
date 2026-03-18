import unittest
import os
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

# Force matplotlib to use non-interactive backend
import matplotlib
matplotlib.use('Agg')

# Add backend to path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from app.mas_logviz.logger import init_context, log_message, log_tool_start, log_tool_end, RunContext
from app.mas_logviz.visualizer import parse_log_to_graph, draw_graph
from app.mas_logviz.instrument import instrument_agent

class TestMASLogViz(unittest.TestCase):
    def setUp(self):
        # Create temp dir for logs
        self.test_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.test_dir, "test_trace.jsonl")
        
        # Mock RunContext to point to temp file
        # We need to access the global _CTX in logger
        import app.mas_logviz.logger as logger
        logger._CTX = RunContext()
        logger._CTX.enabled = True
        logger._CTX.log_path = self.log_path

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_logging(self):
        log_message("User", "Hello Agent")
        log_message("Agent1", "Hello User")
        
        # Verify file content
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 2)
            event1 = json.loads(lines[0])
            self.assertEqual(event1['type'], 'message')
            self.assertEqual(event1['agent'], 'User')
            self.assertEqual(event1['content'], 'Hello Agent')

    def test_visualization(self):
        # Generate some logs
        log_message("User", "Start Task")
        span_id = log_tool_start("my_tool", ("arg1",), {"k": "v"})
        log_tool_end("my_tool", span_id, "result", 0)
        log_message("Agent1", "Task Done")
        
        # Parse
        G, details = parse_log_to_graph(self.log_path)
        
        self.assertTrue("Start" in G.nodes)
        self.assertTrue("End" not in G.nodes) # We didn't write 'final' event manually here
        
        # Check message node
        msg_nodes = [n for n in G.nodes if n.startswith("Msg_")]
        self.assertEqual(len(msg_nodes), 2)
        
        # Check tool node
        tool_nodes = [n for n in G.nodes if n.startswith("Tool_")]
        self.assertEqual(len(tool_nodes), 1)
        
        # Draw (smoke test)
        img_path = os.path.join(self.test_dir, "graph.png")
        draw_graph(G, img_path, details, show=False)
        self.assertTrue(os.path.exists(img_path))

    def test_instrumentation(self):
        class MockAgent:
            def __init__(self, name):
                self.name = name
            def run(self, query):
                return f"Response to {query}"

        agent = MockAgent("TestAgent")
        instrumented_agent = instrument_agent(agent)
        
        # Run
        response = instrumented_agent.run("Hi")
        self.assertEqual(response, "Response to Hi")
        
        # Check logs
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
            # Expect: User msg (input), Agent msg (output)
            # instrument_agent logs input as User msg
            # instrument_agent logs output as Agent msg
            self.assertEqual(len(lines), 2)
            e1 = json.loads(lines[0])
            self.assertEqual(e1['agent'], 'User')
            self.assertEqual(e1['content'], 'Hi')
            
            e2 = json.loads(lines[1])
            self.assertEqual(e2['agent'], 'TestAgent')
            self.assertEqual(e2['content'], 'Response to Hi')

if __name__ == '__main__':
    unittest.main()
