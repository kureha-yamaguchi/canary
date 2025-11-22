"""Red Team Agent Package"""
from .agent import RedTeamAgent, activate_agent
from .config import config

# Import run function for easy access
try:
    from .run import run, DEFAULT_WEBSITE
    __all__ = ["RedTeamAgent", "activate_agent", "config", "run", "DEFAULT_WEBSITE"]
except ImportError:
    __all__ = ["RedTeamAgent", "activate_agent", "config"]

