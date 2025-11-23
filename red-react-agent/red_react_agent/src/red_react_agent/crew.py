"""CrewAI setup for the security-focused red-react agent."""
from typing import List

from crewai import Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from red_react_agent.tools import ALL_TOOLS


@CrewBase
class RedReactAgent:
    """RedReactAgent crew."""

    agents: List[BaseAgent]
    tasks: List[Task]

    @agent
    def recon_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["recon_agent"],  # type: ignore[index]
            verbose=True,
            tools=ALL_TOOLS,
            multimodal=True,
            reasoning=True,
            max_reasoning_attempts=3,
        )

    @agent
    def tester_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["tester_agent"],  # type: ignore[index]
            verbose=True,
            tools=ALL_TOOLS,
            multimodal=True,
            # reasoning=True,
            # max_reasoning_attempts=3,
        )

    @agent
    def auditor_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["auditor_agent"],  # type: ignore[index]
            verbose=True,
            multimodal=True,
            reasoning=True,
            max_reasoning_attempts=3,
        )

    @agent
    def reporter_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["reporter_agent"],  # type: ignore[index]
            verbose=True,
            multimodal=True,
            # reasoning=True,
            # max_reasoning_attempts=3,
        )

    @task
    def recon_task(self) -> Task:
        return Task(
            config=self.tasks_config["recon_task"],  # type: ignore[index]
        )

    @task
    def exploit_task(self) -> Task:
        return Task(
            config=self.tasks_config["exploit_task"],  # type: ignore[index]
        )

    @task
    def audit_task(self) -> Task:
        return Task(
            config=self.tasks_config["audit_task"],  # type: ignore[index]
        )

    @task
    def report_task(self) -> Task:
        return Task(
            config=self.tasks_config["report_task"],  # type: ignore[index]
        )

    @crew
    def crew(self) -> Crew:
        """Creates the RedReactAgent crew."""
        return Crew(
            agents=self.agents,  # Automatically created by the @agent decorator
            tasks=self.tasks,  # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,
        )
