# ClickGrab — Free ClickFix Payload Intelligence

**URL:** https://mhaggis.github.io/ClickGrab/
**Maintained by:** [@mhaggis](https://github.com/mhaggis)
**Related Chokepoint:** [ClickFix Techniques](../chokepoints/initial-access/clickfix-techniques.yml)

---

## What is ClickGrab?

ClickGrab is a community-maintained collection of payloads captured from active
ClickFix infrastructure. It aggregates the actual malicious commands that threat
actors instruct victims to copy and paste, making it a free, practical intelligence
source for threat hunters and detection engineers.

**Key value:** Instead of hunting blindly for "scripting interpreter with browser parent",
you can search your environment for specific indicators extracted from real campaigns.

---

## What's in ClickGrab

For each captured payload, ClickGrab typically provides:

- **Raw payload** — the exact command a victim would paste and execute
- **Decoded payload** — base64/obfuscated commands decoded for analysis
- **C2 infrastructure** — domains and IPs the payload connects to
- **Hosting domain** — the site that delivered the payload
- **Capture date** — when it was collected (useful for campaign timing)
- **Payload type** — PowerShell, cmd, mshta, etc.

---

## How to Use ClickGrab for Threat Hunting

### 1. Hunt for Known C2 Domains

Extract the C2 domains from ClickGrab payloads and search your DNS/proxy logs:

```
# Example hunt query (KQL / Microsoft Sentinel)
DnsEvents
| where Name has_any (
    "domain1.example.com",   // From ClickGrab payload #1
    "domain2.example.com"    // From ClickGrab payload #2
)
| project TimeGenerated, Computer, Name, ClientIP

# Example hunt query (Splunk)
index=dns
| search query IN ("domain1.example.com", "domain2.example.com")
| table _time, src_ip, query, answer
```

### 2. Hunt for Known C2 IPs

```
# Sysmon network connections to ClickGrab-identified IPs
index=sysmon EventCode=3
| search DestinationIp IN ("1.2.3.4", "5.6.7.8")  // IPs from ClickGrab
| table _time, Computer, Image, DestinationIp, DestinationPort
```

### 3. Hunt for Payload Fragments

Many ClickFix payloads use consistent strings or URL patterns across campaigns.
Search for these fragments in process command line telemetry:

```
# Sysmon process creation with payload fragment
index=sysmon EventCode=1
| search CommandLine="*specific-fragment-from-clickgrab*"
| table _time, Computer, Image, CommandLine, ParentImage
```

### 4. Build a Campaign Timeline

Compare ClickGrab capture dates to your own alert history:
- Did the campaign reach your environment before ClickGrab catalogued it?
- Are there undetected hits in your logs from the same time window?

---

## Integrating ClickGrab into Your Detection Workflow

```
ClickGrab Payload → Extract IOCs → Hunt in SIEM → Tune Detection Rules
       ↓                                                    ↓
  New Campaign                                    Update Sigma Analyst Rule
  Identified                                      with Campaign-Specific Filters
```

**Recommended cadence:** Check ClickGrab weekly. New ClickFix variants emerge
every 6-8 weeks; fresh C2 infrastructure rotates more frequently.

---

## Related Resources

- [AITMFEED ClickFix Infrastructure Tracking](https://www.aitmfeed.com/blog/blog-1/tracking-clickfix-infrastructure-4) — Complementary infrastructure tracking
- [Huntress: Don't Sweat ClickFix Techniques](https://huntress.com/blog/dont-sweat-clickfix-techniques) — Analysis of the chokepoint
- [ClickFix Detection Rules](../sigma-rules/clickfix/) — Research, Hunt, and Analyst sigma rules
- [ClickFix Chokepoint Entry](../chokepoints/initial-access/clickfix-techniques.yml) — Full chokepoint documentation

---

## See Also

For detecting the execution side of ClickFix campaigns (independent of specific
C2 infrastructure), see the sigma rules in `sigma-rules/clickfix/`:

| Rule | Level | What it catches |
|------|-------|-----------------|
| `research.yml` | Research | Any scripting interpreter → external connection |
| `hunt.yml` | Hunt | Browser parent → scripting interpreter |
| `analyst.yml` | Analyst | Browser parent → encoded command → outbound |

The ClickGrab IOCs and the sigma rules complement each other:
- Sigma rules catch the **behavior** (new campaigns, unknown C2)
- ClickGrab IOCs catch the **known infrastructure** (confirmed campaigns)
