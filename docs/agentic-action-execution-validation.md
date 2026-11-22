---
title: Agentic Action Execution validation
published: false
---

# Agentic Action Execution validation

**Verdict: EVIDENCE-GAP.** Keep the [candidate](../drafts/agentic-action-execution.yml) as a cross-cutting research profile. The sources support operation-specific environmental boundaries. An additional mandatory boundary and incremental canonical detection coverage are unverified.

## Observation model

**Attacker architecture, conceptual only.** Objective → LLM or agent → harness → selected tool → target operation. The controller, prompts, tool calls within the harness, memory, and reasoning are outside the defender's visibility in this model.

**Defender-observable execution.** Tool-generated request or action → monitored environmental interface and authority → recorded attempt, service decision, or attributable effect. For the same operation and authority model, the target applies the same requirements regardless of who or what selected the action. A tool change can alter the operation and the resulting boundary. Authorization can come from existing application privileges or a public interface. A fresh authentication event, connection, process, module, or command line is therefore conditional. Write down which sensor observed each stage and which stages remain unknown.

## Source and mapping checks

The YAML records each procedure's locator, evidence class, Source → Bridge → Sink, required sensor, expected outcome and confidence. The ATT&CK links here identify the procedure, independently of attribution.

| Reported procedure | ATT&CK and catalog overlap | Evidence boundary |
| --- | --- | --- |
| ARTEX AWS permission probing | [T1580](https://attack.mitre.org/techniques/T1580/) for resource-discovery attempts. [AWS Stolen Credential Permission Enumeration](../chokepoints/discovery/aws-credential-permission-enumeration.yml) covers authorization testing. | GTIG reports a burst of 27 events over 23 seconds and separately documents EC2 permission checks. Datadog independently reports denied discovery requests under a different role-based procedure. The authorization outcome is observable where logged. Resource discovery or change requires its own evidence. |
| ARTEX attempted WinRM movement | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) attempted. [Remote Execution Tools](../chokepoints/lateral-movement/remote-execution-tools.yml) documents WinRM. Its linked Sigma rules require a service installation event (7045), which a blocked request need not produce. | GTIG lists WinRM among several attempted methods and reports endpoint protection blocking execution during that activity. A specific WinRM-to-block linkage and a successful remote process remain unverified. |
| ARTEX web-shell iterations | [T1505.003](https://attack.mitre.org/techniques/T1505/003/). [Web Shell Persistence](../chokepoints/persistence/web-shells.yml) overlaps where the web server spawns a child OS interpreter. | GTIG reports failed iterations and eventual output. The public account supports web-mediated execution and leaves the process lineage unverified. Look for request-correlated execution evidence. |
| ARTEX HTTP tasking and results | [T1071.001](https://attack.mitre.org/techniques/T1071/001/). [C2 Service Relationship Correlation](../chokepoints/command-and-control/c2-service-relationship-correlation.yml) covers the role-compatible relationship. | GTIG reports an outbound exchange. Validate the service role and direction independently in the environment. An endpoint name or generic HTTP traffic is insufficient. |
| CAIRN | Procedure-level ATT&CK and catalog mapping remain unverified. | GTIG reports intrusion use and separately describes a shared-state design. The public case summary leaves the actual operation and victim-side effects unspecified. |
| Customized PentAGI deployment | [T1595.002](https://attack.mitre.org/techniques/T1595/002/). The catalog has no direct mapping for the reported external scanning behavior. | GTIG reports vulnerability scanning for this deployment. A received probe and a service response can support this mapping. Exact scan implementation, successful exploitation and protected access are unverified for the case. |
| Claude Code-based custom harness | [T1078](https://attack.mitre.org/techniques/T1078/) when harvested credentials were used successfully. A direct catalog match is unverified. | Anthropic reports credential testing and database access. The report also documents erroneous model claims. The target's authentication and resource audit trail would establish the actual result. No Entra, Graph API or AiTM procedure is established by this case. |

GTIG describes the ARTEX timing observation in *Observations in the Wild* and the dry-run checks in the lifecycle table's *Initial Recon* row. The burst is one interval with no matched human or script baseline. Datadog's *Activity cluster 2* provides separate evidence of the authorization boundary for discovery requests. GTIG's November *Multi-Agent Frameworks in Cyber Intrusions* section covers CAIRN and PentAGI. Anthropic's executive summary and phases 4 and 5 describe its campaign observations. [GTIG and Mandiant technical report](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks) · [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/) · [GTIG November tracker](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold) · [Anthropic technical report](https://assets.claude.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf)

## Detection tiers

- **Research.** Normalize target, principal, session or request identity, operation, target decision, and observed effect where available. Preserve event and arrival timestamps. Record whether the source covers that operation, result and time interval. For example, some CloudTrail services report errors in response elements and error fields are optional. [AWS CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- **Hunt.** Use available service, identity, network, application and endpoint evidence to correlate activity within the right target and authority context. Establish baselines for routine administrative bursts and automation. Look for retries after failure and unusually compressed or concurrent operations. Parallel or fast activity can raise priority while leaving the origin unverified.
- **Analyst.** Require target-bound evidence and enough context to classify attempted or completed unauthorized activity. A denial can establish a specific attempt. A claim of success needs the corresponding state change, resource access, process or application effect. Report malicious behavior and any separately supported controller attribution as separate conclusions.

**Sigma rationale.** No single event can encode the cross-source evidence, applicable authority, identity joins and procedure-specific evidence of effect across this profile. A source-specific event may independently detect a known unauthorized action. Existing catalog rules or environment-specific correlation are the appropriate place to implement those detections.

## Deterministic replay

Run the [fixture](../tests/test_agentic_action_execution.py) with Python and PyYAML, from the repository root.

```text
python -m unittest discover -s tests -p "test_agentic_action_execution.py" -v
```

The test uses an in-memory inventory service and generated records. Every positive fixture uses the same mock principal, session, target, five attempts, four logical requests, decisions and goal. The record write is harmless and stands in for an unauthorized objective. The mock service's policy allows the marker write. A separate, complete fixture change register controls whether that activity is administratively approved. In a deployed environment, absence from a change register alone is weak evidence.

| Style | Completion time in seconds | Orchestration differences |
| --- | --- | --- |
| Human-paced | Identity 0, denial A 15, retry A 45, allow B 100, marker 140 | Console-style adapter and deliberate pauses. |
| Deterministic script | Identity 0, denial A 1, retry A 2, allow B 4, marker 8 | Fixed serial schedule and client-style adapter. |
| Simulated agent | Identity 0, allow B 1, denial A 2, retry A 3, marker 8 | A and B overlap. After the denial, a deterministic feedback branch retries A via the alternate adapter. |

Adapter labels describe fixture inputs. The target maps both adapters to the same operation and outcome fields. Every attempt has a unique attempt ID in the replay, and both A attempts share one logical request. The mock tracks request completion and collector arrival separately. Real retries are often harder to identify, and request-start intervals may be unavailable.

### Expectations before execution

- An objective detector that uses the marker effect and fixture change context should match all three positive runs. An attempt to write a denied marker should remain a denial without an effect.
- An ordered A-deny → B-allow → marker join should miss the reordered agent run. A 10-second event-time window should miss the paced run, while a 180-second window should recover it. The order-independent join should cover all runs at 180 seconds.
- An early warning on A and B before the marker should be sensitive to pacing and collector arrival time. Replay the script run with both A records delivered late, and compare partial-state retention of 2 and 10 seconds after marker arrival.
- Approved scripted automation, an approved agent workflow, a harmless administrative burst and an authorized assessment should produce hunt warnings without confirmed unauthorized objectives. Split-session records should produce no correlated match.
- A collector accepting one event per principal per two-second arrival bucket should lose the script's first A denial and retain the retry. A six-second bucket should lose both denials and the B allow while retaining the marker. The [AWS Hunt rule's](../sigma-rules/aws-credential-permission-enumeration/hunt.yml) breadth and ratio gates should miss all three single-namespace runs.

### Observed synthetic outcomes

All three positive fixtures produced equivalent normalized operation, decision and effect records when timing and order were set aside. Each produced one boundary-effect alert. Each valid sequence produced one confirmation per target, principal, session and marker event despite the retry.

| Style | Ordered match, 10 s / 180 s | Either-order match, 10 s / 180 s | Early warning at 180 s | Lead to marker | 5 s triage before marker |
| --- | --- | --- | --- | --- | --- |
| Human-paced | 0 / 1 | 0 / 1 | 100 s | 40 s | Yes |
| Deterministic script | 1 / 1 | 1 / 1 | 4 s | 4 s | No |
| Simulated agent | 0 / 0 | 1 / 1 | 2 s | 6 s | Yes |

The 10-second early warning missed the human-paced run and matched the two compressed runs at 4 and 2 seconds. Delaying the two A records to 12 and 13 seconds, with the marker still arriving at 8 seconds, moved both early warning and 10-second-retention confirmation to 12 seconds. The shorter retention missed confirmation. Removing the B sensor record suppressed both joins and preserved the independent marker-effect alert.

Approved scripted automation, the approved agent workflow, the harmless administrative burst and the authorized-assessment fixture each produced one early warning and zero confirmations or boundary-effect alerts. The authorized assessment uses a separate principal and change approval while the application still denies its marker. The split-session control produced zero correlated matches. Its independently observed, unapproved marker still produced one boundary-effect alert. In the unapproved denied-marker run, the denial preserved evidence of the attempt and produced no effect alert or confirmation.

The two-second collector limit dropped the first A denial and retained one confirmation. The six-second limit retained only identity and marker records, so confirmation was lost and the independent marker-effect alert survived. This models record loss under a simple collection budget.

For the AWS catalog comparison, the Python fixture projects the Hunt query's minimum of five distinct denied namespaces and its denial ratio of at least 0.5. Each main replay occupies one synthetic namespace in one preselected principal/window and failed that gate. A separate control with five denied namespaces and five allowed records passed. Adding five more allows put it below the ratio threshold and it failed. These checks exercise the documented thresholds on normalized decisions. Testing the full Athena query, AWS identity and error-code normalization, production throughput and other catalog rules requires representative telemetry and a matching backend.

The results measure the test's reference detectors and selected fixture timings. They provide no comparison of real attacker speeds, production detection rates, operational false-positive rates or actual response times. The five-second triage interval is a model input. Production comparison would need paired target-side traces, verified sensor coverage, genuine administrative baselines, clock and ingestion measurements, and observed queue-to-containment latency.

## Promotion assessment

- **Distinct boundary and added coverage.** AWS evaluation, WinRM authentication and service execution, the web application interpreter, and an authenticated database session are different boundaries. The model provides a common way to reason about them. A single additional mandatory, defender-observable boundary is unverified. The synthetic replay demonstrates correlation tradeoffs and contributes no new technique coverage.
- **Substitution and sensor loss.** A human, script or agent can generate the same target event. A new tool can also use a different operation to attain the same objective and avoid a method-specific signal. Without process or module visibility, a process lineage assertion stays unverified. Missing network or cloud audit data leaves affected joins coverage-limited. An independently recorded effect can remain actionable.
- **Independent cases and falsification.** Google, Datadog and Anthropic provide independent observations of operation-specific boundaries. The AWS reports corroborate service authorization across different procedures. Evidence of an additional shared observable is still missing. A comparison that holds the actual operation and authority model constant and finds a repeatable, controller-dependent, required boundary would challenge this disposition. So would a substantiated protected effect with no operation-level authority boundary, after excluding missing telemetry and preexisting authorization.
- **Disposition.** Keep this profile in `drafts/`. The repository's canonical promotion validator requires independent variations of the same proposed invariant and a complete page contract. This profile sits outside that contract and is checked by the focused tests above. Use existing catalog entries to select candidate detections, then verify the actual rule predicates and available telemetry.
