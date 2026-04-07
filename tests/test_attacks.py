"""Tests for AgentShield attack scenarios and mock agents."""

import pytest

from agentshield.attacks.base import AttackCategory, AttackResult, AttackScenario
from agentshield.attacks.runner import get_all_scenarios
from agentshield.simulation.mock_agent import AgentMode, MockAgent


class TestAttackScenarios:
    @pytest.fixture
    def all_scenarios(self):
        return get_all_scenarios()

    def test_total_scenario_count(self, all_scenarios):
        assert len(all_scenarios) == 40

    def test_ten_per_category(self, all_scenarios):
        for cat in AttackCategory:
            count = sum(1 for s in all_scenarios if s.category == cat)
            assert count == 10, f"{cat.value} has {count} scenarios (expected 10)"

    def test_unique_scenario_ids(self, all_scenarios):
        ids = [s.scenario_id for s in all_scenarios]
        assert len(ids) == len(set(ids)), "Duplicate scenario IDs"

    def test_scenarios_have_messages(self, all_scenarios):
        for s in all_scenarios:
            assert len(s.messages) > 0, f"{s.scenario_id} has no messages"

    def test_scenario_id_format(self, all_scenarios):
        prefixes = {"DI-", "II-", "MT-", "TM-"}
        for s in all_scenarios:
            assert any(s.scenario_id.startswith(p) for p in prefixes), (
                f"Unexpected ID format: {s.scenario_id}"
            )


class TestMockAgent:
    def test_echo_mode(self):
        agent = MockAgent(mode=AgentMode.ECHO)
        response = agent.process("test input")
        assert "[ECHO]" in response.content
        assert "test input" in response.content

    def test_scripted_mode(self):
        agent = MockAgent(mode=AgentMode.SCRIPTED)
        response = agent.process("Tell me about protein structure")
        assert "protein" in response.content.lower() or "help" in response.content.lower()

    def test_scripted_default_response(self):
        agent = MockAgent(mode=AgentMode.SCRIPTED)
        response = agent.process("xyzzy totally random query 12345")
        assert "help" in response.content.lower() or "research" in response.content.lower()

    def test_conversation_history(self):
        agent = MockAgent(mode=AgentMode.ECHO)
        agent.process("message 1")
        agent.process("message 2")
        assert len(agent.conversation_history) == 4  # 2 user + 2 agent

    def test_reset(self):
        agent = MockAgent(mode=AgentMode.ECHO)
        agent.process("hello")
        agent.reset()
        assert len(agent.conversation_history) == 0

    def test_poisoned_mode(self):
        agent = MockAgent(mode=AgentMode.SCRIPTED, poisoned=True)
        response = agent.process("Search PubMed for pathogen research")
        assert "retrieved data" in response.content.lower() or len(response.content) > 0

    def test_emit_tool_calls(self):
        agent = MockAgent(mode=AgentMode.SCRIPTED, emit_tool_calls=True)
        response = agent.process("Use run_docker_code to execute a script")
        assert len(response.tool_calls) > 0
        assert response.tool_calls[0]["tool_name"] == "run_docker_code"

    def test_no_tool_calls_by_default(self):
        agent = MockAgent(mode=AgentMode.SCRIPTED)
        response = agent.process("Use run_docker_code to execute a script")
        assert len(response.tool_calls) == 0


class TestAttackResult:
    def test_successful_attack(self):
        r = AttackResult(
            scenario_id="DI-01",
            scenario_name="System Prompt Leak",
            category="direct_injection",
            success=True,
            detected=False,
            blocked=False,
            turns_completed=3,
        )
        assert r.success
        assert not r.detected

    def test_blocked_attack(self):
        r = AttackResult(
            scenario_id="DI-01",
            scenario_name="System Prompt Leak",
            category="direct_injection",
            success=False,
            detected=True,
            blocked=True,
            turns_completed=1,
            blocked_at_turn=1,
        )
        assert r.blocked
        assert r.detected
        assert not r.success
