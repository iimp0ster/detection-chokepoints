"""Replay inert requests against an in-memory policy and compare audit outcomes."""

from __future__ import annotations

import unittest
from dataclasses import dataclass, replace
from itertools import product
from pathlib import Path
from urllib.parse import urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]
TARGET = "fixture-inventory"
PRINCIPAL = "fixture-user"
SESSION = "fixture-session"
OPERATIONS = {
    "identity": ("identify", "allow"),
    "a-1": ("check-a", "deny"),
    "a-2": ("check-a", "deny"),
    "b": ("check-b", "allow"),
    "marker": ("write-marker", "allow"),
}
CONSOLE = {
    "identity": "Identity",
    "a-1": "Check A",
    "a-2": "Check A",
    "b": "Check B",
    "marker": "Write Marker",
}
CLIENT = {
    "identity": "identity.read",
    "a-1": "permission.a",
    "a-2": "permission.a",
    "b": "permission.b",
    "marker": "marker.write",
}
NORMALIZED_OPERATION = {
    raw: OPERATIONS[attempt][0]
    for adapter in (CONSOLE, CLIENT)
    for attempt, raw in adapter.items()
}
AUTHORIZATION = dict(OPERATIONS.values())
LOGICAL_REQUEST = {
    "identity": "identify",
    "a-1": "probe-a",
    "a-2": "probe-a",
    "b": "probe-b",
    "marker": "objective",
}


@dataclass(frozen=True)
class Event:
    attempt_id: str
    logical_request: str
    operation: str
    decision: str
    effect: str | None
    started_at: float
    event_time: float
    arrival_time: float
    target: str = TARGET
    principal: str = PRINCIPAL
    session: str = SESSION

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.target, self.principal, self.session)


def replay(style: str, *, allow_marker: bool = True) -> tuple[Event, ...]:
    # Each step finishes before its result enters the target audit stream.
    if style == "human":
        adapter = CONSOLE
        steps = (("identity", 0, 0), ("a-1", 14, 15), ("a-2", 44, 45),
                 ("b", 99, 100), ("marker", 139, 140))
    elif style == "script":
        adapter = CLIENT
        steps = (("identity", 0, 0), ("a-1", 0.5, 1), ("a-2", 1.5, 2),
                 ("b", 3.5, 4), ("marker", 7.5, 8))
    elif style == "agent":
        adapter = CLIENT
        steps = (("identity", 0, 0), ("b", 0.5, 1), ("a-1", 0.75, 2),
                 ("marker", 7.5, 8))
    else:
        raise ValueError(style)

    # The label "agent" denotes a deterministic fixture. Its simulated feedback
    # branch schedules a retry after the mock target denies the first A check.
    pending = list(steps)
    marker_written = False
    events = []
    while pending:
        pending.sort(key=lambda step: step[2])
        attempt, started, completed = pending.pop(0)
        tool = CONSOLE if style == "agent" and attempt == "a-2" else adapter
        operation = NORMALIZED_OPERATION[tool[attempt]]
        decision = AUTHORIZATION[operation]
        if operation == "write-marker":
            decision = "allow" if allow_marker else "deny"
        effect = None
        if operation == "write-marker" and decision == "allow" and not marker_written:
            marker_written = True
            effect = "marker-written"
        events.append(Event(attempt, LOGICAL_REQUEST[attempt], operation, decision, effect,
                            started, completed, completed))
        if style == "agent" and attempt == "a-1" and decision == "deny":
            pending.append(("a-2", completed + 0.5, completed + 1))
    return tuple(events)


def matching_checks(events, window):
    denials = [event for event in events if (event.operation, event.decision) == ("check-a", "deny")]
    allows = [event for event in events if (event.operation, event.decision) == ("check-b", "allow")]
    for denial, allow in product(denials, allows):
        if denial.key == allow.key and abs(denial.event_time - allow.event_time) <= window:
            yield denial, allow


def early_warnings(events, window):
    alerts = {}
    for denial, allow in matching_checks(events, window):
        available_at = max(denial.arrival_time, allow.arrival_time)
        alerts[denial.key] = min(alerts.get(denial.key, available_at), available_at)
    return alerts


def boundary_effects(events, approved_changes=frozenset()):
    return {
        (event.key, event.attempt_id): event.arrival_time
        for event in events
        if event.operation == "write-marker"
        and event.decision == "allow"
        and event.effect == "marker-written"
        and event.key not in approved_changes
    }


def confirmations(events, window, *, ordered=False, retention=10, approved_changes=frozenset()):
    alerts = {}
    checks = tuple(matching_checks(events, window))
    objectives = boundary_effects(events, approved_changes)
    for marker in events:
        key = (marker.key, marker.attempt_id)
        if key not in objectives:
            continue
        for denial, allow in checks:
            if denial.key != marker.key or (ordered and denial.event_time >= allow.event_time):
                continue
            first = min(denial.event_time, allow.event_time)
            last = max(denial.event_time, allow.event_time)
            if last >= marker.event_time or marker.event_time - first > window:
                continue
            available_at = max(denial.arrival_time, allow.arrival_time, marker.arrival_time)
            if available_at <= marker.arrival_time + retention:
                alerts[key] = min(alerts.get(key, available_at), available_at)
    return alerts


def aws_denial_breadth(events):
    """Project the checked-in AWS Hunt breadth and ratio gates for one window and principal."""
    denials = [namespace for namespace, decision in events if decision == "deny"]
    return len(set(denials)) >= 5 and len(denials) * 2 >= len(events)


def first_per_arrival_bucket(events, seconds):
    accepted = {}
    for event in sorted(events, key=lambda record: record.arrival_time):
        bucket = (event.principal, event.arrival_time // seconds)
        accepted.setdefault(bucket, event)
    return tuple(accepted.values())


class AgenticActionExecutionTests(unittest.TestCase):
    def test_same_actions_have_equivalent_target_observables(self):
        expected = {
            (attempt, operation, result, "marker-written" if attempt == "marker" else None)
            for attempt, (operation, result) in OPERATIONS.items()
        }
        for style in ("human", "script", "agent"):
            with self.subTest(style=style):
                events = replay(style)
                self.assertEqual({event.key for event in events}, {(TARGET, PRINCIPAL, SESSION)})
                self.assertEqual(len(events), 5)
                self.assertEqual({event.logical_request for event in events},
                                 {"identify", "probe-a", "probe-b", "objective"})
                self.assertEqual(
                    {(event.attempt_id, event.operation, event.decision, event.effect) for event in events},
                    expected,
                )
                self.assertEqual(len(boundary_effects(events)), 1)

    def test_agent_overlaps_operations_and_retries_after_feedback(self):
        events = {event.attempt_id: event for event in replay("agent")}
        self.assertLess(events["a-1"].started_at, events["b"].event_time)
        self.assertLess(events["b"].started_at, events["a-1"].event_time)
        self.assertGreater(events["a-2"].started_at, events["a-1"].event_time)
        self.assertEqual(events["a-1"].logical_request, events["a-2"].logical_request)
        self.assertGreater(events["marker"].started_at, events["b"].event_time)

    def test_event_time_windows_and_order_change_confirmation(self):
        # Ordered narrow, ordered wide, order independent narrow and wide.
        expected = {"human": (0, 1, 0, 1), "script": (1, 1, 1, 1), "agent": (0, 0, 1, 1)}
        for style, counts in expected.items():
            with self.subTest(style=style):
                events = replay(style)
                observed = tuple(
                    len(confirmations(events, window, ordered=ordered))
                    for ordered, window in product((True, False), (10, 180))
                )
                self.assertEqual(observed, counts)

    def test_early_warning_and_response_lead_time(self):
        expected = {"human": (None, 100, 40), "script": (4, 4, 4), "agent": (2, 2, 6)}
        for style, (short, long, lead) in expected.items():
            with self.subTest(style=style):
                events = replay(style)
                key = events[0].key
                warning = early_warnings(events, 180)[key]
                self.assertEqual(early_warnings(events, 10).get(key), short)
                self.assertEqual(warning, long)
                marker = next(event for event in events if event.effect == "marker-written")
                self.assertEqual(marker.event_time - warning, lead)
                self.assertEqual(warning + 5 < marker.event_time, style != "script")

    def test_late_delivery_and_missing_sensor(self):
        events = replay("script")
        late = tuple(
            replace(event, arrival_time=event.event_time + 11)
            if event.operation == "check-a" else event
            for event in events
        )
        self.assertEqual(tuple(early_warnings(late, 10).values()), (12,))
        self.assertEqual(tuple(confirmations(late, 10).values()), (12,))
        self.assertEqual(confirmations(late, 10, retention=2), {})
        missing = tuple(event for event in events if event.operation != "check-b")
        self.assertEqual(early_warnings(missing, 10), {})
        self.assertEqual(confirmations(missing, 10), {})
        self.assertEqual(len(boundary_effects(missing)), 1)

    def test_collector_limits_can_remove_attempts_or_break_a_join(self):
        events = replay("script")
        two_seconds = first_per_arrival_bucket(events, 2)
        self.assertEqual([event.attempt_id for event in two_seconds],
                         ["identity", "a-2", "b", "marker"])
        self.assertEqual(len(confirmations(two_seconds, 10)), 1)
        six_seconds = first_per_arrival_bucket(events, 6)
        self.assertEqual([event.attempt_id for event in six_seconds], ["identity", "marker"])
        self.assertEqual(confirmations(six_seconds, 10), {})
        self.assertEqual(len(boundary_effects(six_seconds)), 1)

    def test_aws_hunt_subset_is_sensitive_to_breadth_and_ratio(self):
        for style in ("human", "script", "agent"):
            with self.subTest(style=style):
                observations = [("fixture-inventory", event.decision) for event in replay(style)]
                self.assertFalse(aws_denial_breadth(observations))

        denied_namespaces = [(f"fixture-service-{index}", "deny") for index in range(5)]
        allowed = [("fixture-inventory", "allow")] * 5
        self.assertTrue(aws_denial_breadth(denied_namespaces + allowed))
        self.assertFalse(aws_denial_breadth(denied_namespaces + allowed * 2))

    def test_approved_automation_admin_burst_and_cross_session_controls(self):
        events = replay("script")
        approved_agent = replay("agent")
        for benign in (events, approved_agent):
            approved = frozenset({benign[0].key})
            self.assertEqual(len(early_warnings(benign, 10)), 1)
            self.assertEqual(boundary_effects(benign, approved), {})
            self.assertEqual(confirmations(benign, 10, approved_changes=approved), {})

        burst = tuple(event for event in events if event.operation != "write-marker")
        self.assertEqual(len(early_warnings(burst, 10)), 1)
        self.assertEqual(boundary_effects(burst), {})
        self.assertEqual(confirmations(burst, 10), {})

        # Authorized assessment tooling can see a denial at the same boundary.
        authorized_assessment = tuple(
            replace(event, principal="fixture-assessor")
            for event in replay("script", allow_marker=False)
        )
        assessment_approval = frozenset({authorized_assessment[0].key})
        self.assertEqual(len(early_warnings(authorized_assessment, 10)), 1)
        self.assertEqual(boundary_effects(authorized_assessment, assessment_approval), {})
        self.assertEqual(confirmations(authorized_assessment, 10, approved_changes=assessment_approval), {})

        split = tuple(
            replace(event, session="other-fixture-session")
            if event.operation == "check-a" else event
            for event in events
        )
        self.assertEqual(early_warnings(split, 180), {})
        self.assertEqual(confirmations(split, 180), {})
        self.assertEqual(len(boundary_effects(split)), 1)

    def test_denied_objective_is_an_attempt_without_a_confirmed_effect(self):
        events = replay("script", allow_marker=False)
        denied = next(event for event in events if event.operation == "write-marker")
        self.assertEqual((denied.decision, denied.effect), ("deny", None))
        self.assertEqual(boundary_effects(events), {})
        self.assertEqual(confirmations(events, 10), {})

    def test_research_profile_contract_and_local_references(self):
        draft = ROOT / "drafts" / "agentic-action-execution.yml"
        profile = yaml.safe_load(draft.read_text(encoding="utf-8"))
        self.assertIs(profile["published"], False)
        self.assertEqual(profile["PromotionVerdict"], "EVIDENCE-GAP")
        self.assertNotIn("PageStandardVersion", profile)
        self.assertEqual([tier["Level"] for tier in profile["Detections"]], ["Research", "Hunt", "Analyst"])
        self.assertTrue(profile["NoStandaloneSigmaRationale"])
        for path in profile["ValidationContract"].values():
            self.assertTrue((ROOT / path).is_file(), path)
        for source in profile["Sources"].values():
            self.assertEqual(urlsplit(source["URL"]).scheme, "https")
        for procedure in profile["Procedures"]:
            with self.subTest(procedure=procedure["Procedure"]):
                evidence = procedure["Evidence"]
                self.assertIn(evidence["Source"], profile["Sources"])
                if "CapabilitySource" in evidence:
                    self.assertIn(evidence["CapabilitySource"], profile["Sources"])
                    self.assertTrue(evidence["CapabilityLocator"])
                if "Corroboration" in evidence:
                    corroboration = evidence["Corroboration"]
                    self.assertIn(corroboration["Source"], profile["Sources"])
                    self.assertTrue(corroboration["Locator"])
                    self.assertTrue(corroboration["Observed"])
                for field in ("Locator", "Capability", "Observed"):
                    self.assertTrue(evidence[field])
                for field in ("Operation", "Source", "Bridge", "Sink", "RequiredTelemetry",
                              "ExpectedObservable", "Limits", "Confidence"):
                    self.assertTrue(procedure[field])
                for mapping in procedure["Catalog"]:
                    self.assertTrue((ROOT / mapping["Path"]).is_file(), mapping)


if __name__ == "__main__":
    unittest.main()
