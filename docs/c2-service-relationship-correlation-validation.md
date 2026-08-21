# Validation contract: C2 Service Relationship Correlation

This contract distinguishes an observable expectation from a confirmed
detection outcome. It tests the client-to-service relationship invariant—not
whether a certificate or service fingerprint is malicious. It is an offline,
synthetic review contract only; it contains no live indicators, provider
responses, raw logs, or target interaction.

## Research fixture — expected observations

| Field group | Required expectation | Fail / hold condition |
| --- | --- | --- |
| Client-to-service relationship | Normalized event time and source semantics, client identity, destination host/address, destination port, transport/application protocol, direction, and process/proxy context when available | Missing time semantics; inbound/unknown direction; no client-to-service relationship; source publication date only |
| Role and provenance | Source-defined candidate-service role or an independently extracted configuration binding, with a record of source lineage | Certificate, header, port, provider, title, favicon, or generic framework alone |
| Conditional identity corroboration | If used, at least two exact compatible artifact classes in one time-bound service tuple with SNI/Host context where applicable | Partial/cross-service match; copied source; public demonstration; authorized engagement; identity treated as required for C2 |
| Exclusions | CDN, shared cloud, proxy, sinkhole, authorized deployment, generic framework/default, controller/delivery/resolver role, and source-time assessment | Any unresolved shared-service, role, or temporal explanation |

## Hunt fixture — expected correlation

```yaml
fixture: source-bound-client-service-candidate
endpoint_egress:
  direction: outbound_client_to_remote_service
  timestamp_semantics: normalized-and-retained
  destination_tuple: present
  process_or_proxy_context: present-or-coverage-limited
role_evidence:
  source_defined_service_role_or_extracted_configuration: true
conditional_identity:
  used: true
  same_service_artifact_class_count_gte: 2
  source_time_compatible: true
  shared_service_assessment: resolved
expected_outcome: analyst_review_candidate
```

## Pass and reject assertions

```yaml
fixtures:
  - name: pass_same_service_time_bound_relationship
    requires:
      - outbound endpoint-to-service event with normalized time and destination tuple
      - role-compatible source or configuration evidence
      - if identity is used, two exact artifact classes from that same service tuple
      - no unresolved shared-service or role-confusion exclusion
    expect: analyst_review_candidate

  - name: reject_certificate_only
    has:
      - certificate-derived or TLS identity field without endpoint relationship
    expect: research_context_only

  - name: reject_cross_service_or_out_of_window_identity
    has:
      - artifacts from different service tuples or incompatible observation windows
    expect: reject

  - name: hold_uninstrumented_or_relay_obscured_path
    has:
      - absent relationship telemetry or unresolved relay/CDN/proxy role
    expect: coverage_limited
```

## Analyst fixture — promotion boundary

```yaml
join:
  client_to_service_relationship: time-bounded-and-role-compatible
  independent_relation: endpoint-to-service-or-extracted-config-or-second-lineage
  traffic_direction: compatible-with-declared-role
  conditional_identity: optional-corroboration-only
expected_outcome: analyst_investigation
reject_if:
  - source-only-confirmation
  - certificate-or-header-only-correlation
  - generic-default-or-shared-service
  - delivery-controller-resolver-proxy-or-test-role-conflation
  - absent-or-out-of-window-timestamp
```

An analyst investigation may establish a time-bounded relationship. It does not
automatically establish campaign expansion or operator ownership.
