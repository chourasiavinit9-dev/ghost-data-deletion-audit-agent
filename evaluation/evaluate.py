"""Entry point named evaluate.py: runs the evaluation workflow (see main.py)."""
import runpy, os, sys
sys.exit(runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py"), run_name="__main__").get("__exit__", 0))
