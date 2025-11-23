"""Configuration for TTP Master Agent - loads .env from multiple locations"""
import os
from pathlib import Path
from dotenv import load_dotenv
from typing import Optional

# Get project root (parent of ttp-master directory)
PROJECT_ROOT = Path(__file__).parent.parent
TTP_MASTER_DIR = Path(__file__).parent

# Load .env files - check both project root and ttp-master directory
# Later files override earlier ones (so ttp-master/.env takes precedence)
env_files = [
    PROJECT_ROOT / ".env",
    TTP_MASTER_DIR / ".env",
]

for env_file in env_files:
    if env_file.exists():
        load_dotenv(env_file, override=False)

# Also try loading from current working directory
load_dotenv(override=False)


class Config:
    """Configuration settings for TTP Master Agent"""
    
    # OpenRouter settings
    # Check for both OPENROUTER_API_KEY and OPEN_ROUTER_API (backwards compatibility)
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPEN_ROUTER_API", "")
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    
    # Default model
    DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "openai/gpt-4o")
    
    # Agent settings
    TEMPERATURE: float = float(os.getenv("AGENT_TEMPERATURE", "0.3"))  # Lower temp for more precise TTP matching
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "10"))
    
    # MITRE ATT&CK base URL
    MITRE_BASE_URL: str = "https://attack.mitre.org/techniques/enterprise/"
    
    @classmethod
    def validate(cls) -> None:
        """Validate that required configuration is present"""
        if not cls.OPENROUTER_API_KEY:
            raise ValueError(
                "OPENROUTER_API_KEY not found in environment variables. "
                f"Checked .env files in: {[str(f) for f in env_files if f.exists()]}"
            )


# Create global config instance
config = Config()

