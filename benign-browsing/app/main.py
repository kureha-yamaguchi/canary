# app/main.py - adapted from the browser-use example

import asyncio
import os
import sys
import argparse
from dotenv import load_dotenv
from browser_use import Agent, ChatOpenAI

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', help='Website URL to browse')
    parser.add_argument('--model', help='Model name')
    args = parser.parse_args()

    # Load .env if running locally
    if os.path.exists('.env'):
        load_dotenv()

    # Get values from args, fallback to env vars, then to defaults
    url = args.url or os.getenv('TARGET_URL')
    model = args.model or os.getenv('MODEL', 'openai/gpt-4o-mini')
    api_key = os.getenv('OPENROUTER_API_KEY')

    # Validate required values
    if not url:
        print("❌ ERROR: URL is required!")
        sys.exit(1)
    if not api_key:
        print("❌ ERROR: OPENROUTER_API_KEY not found!")
        sys.exit(1)


    print("Config:")
    print(f"   URL: {url}")
    print(f"   Model: {model}")

    llm = ChatOpenAI(
        model=model,
        base_url='https://openrouter.ai/api/v1',
        api_key=os.getenv('OPENROUTER_API_KEY'),
    )

    task = f"""
    Browse {url} naturally like a real user would:
    - Click on interesting internal links you find
    - ALWAYS IGNORE links to external sites
    - Scroll through pages to read content
    - Explore different sections of the website
    - Navigate between pages naturally
    - Act curious and human-like in your exploration
    """

    agent = Agent(
        task=task,
        llm=llm,
    )

    asyncio.run(agent.run(max_steps=10))

if __name__ == "__main__":
    main()
