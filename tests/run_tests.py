#!/usr/bin/env python3
# coding: utf-8
"""运行全部单元测试（无第三方依赖）。

用法: python tests/run_tests.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

loader = unittest.TestLoader()
suite = loader.discover(str(Path(__file__).resolve().parent), pattern="test_*.py")
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
sys.exit(0 if result.wasSuccessful() else 1)