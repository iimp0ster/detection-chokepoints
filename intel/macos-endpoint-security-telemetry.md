# macOS Endpoint Security Telemetry Lab

**URL:** https://enleak.dev/writing/where-does-macos-telemetry-come-from
**Author:** [@enleak](https://github.com/enleak)
**Related Chokepoint:** [Infostealer Browser Credential Theft](../chokepoints/credential-access/browser-credential-theft.yml)

---

## What this resource covers

This lab is a practical introduction to the telemetry macOS exposes through the
Endpoint Security Framework (ESF). It uses Mac Monitor and a controlled Bash
script to generate and inspect process and filesystem activity, including:

- `EXEC`, `FORK`, and `EXIT` process events
- `CREATE`, `RENAME`, and `UNLINK` filesystem events
- Process ancestry and code-signing metadata
- Filtering a noisy JSON export into a focused execution timeline
- Capturing notification events from the command line with `eslogger`

The test does not emulate credential theft. Its value is validating the macOS
telemetry needed before adapting a chokepoint detection to an ESF-backed sensor.

## Applying it to browser credential theft

The browser credential-theft chokepoint depends on observing a non-browser
process interacting with credential stores and correlating that access with its
execution context. On macOS, an ESF client can provide the process and file-event
side of that investigation.

Use the lab workflow to answer these questions in your own environment:

1. Does the sensor retain the ESF event types required for the detection?
2. Are file paths, process ancestry, and code-signing fields preserved?
3. Can activity from one root process be followed across its descendants?
4. How much unrelated activity must be filtered before the sequence is usable?

Mac Monitor is useful for interactive inspection. Apple's built-in `eslogger`
offers a second way to capture selected notification events as JSON for testing:

```bash
sudo eslogger exec fork create rename unlink exit > esf-events.jsonl
```

Both approaches help validate visibility. Production retention, enrichment, and
query fields still depend on the EDR or Endpoint Security client in use.

## Related resources

- [Apple: What's new in Endpoint Security](https://developer.apple.com/videos/play/wwdc2022/110345/)
- [Mac Monitor](https://github.com/Brandon7CC/mac-monitor)
- [Browser credential-theft Sigma rules](../sigma-rules/browser-credential-theft/)
