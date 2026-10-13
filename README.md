# Next.js Server Actions Inspector

Standalone Burp Suite extension using the Montoya API. It passively records requests carrying `Next-Action` or recognizable Flight/action markers, formats newline-delimited Flight rows as readable JSON where possible, and lists action IDs and references.

## Build

Requires JDK 21 and Gradle 8. Build and run the parser tests with:

```powershell
gradle test jar
```

Load `build/libs/nextjs-server-actions-inspector-1.0.0.jar` in Burp under **Extensions**.

## Workflow

1. Select a request in Burp and use **Load as Server Action replay target**.
2. Select representative authenticated requests for each user and use **Capture request headers as a role**. Role labels and credentials remain in memory for this Burp session only.
3. Select one or more roles in the suite tab. The replay uses the target action request and replaces only the configured identity headers (default: `Cookie`, `Authorization`, and common CSRF headers) from each role sample.
4. Check the state-change confirmation and replay. Requests outside Burp scope are blocked. Replays are sent sequentially through Burp and response status/body fingerprints are shown for comparison.

The `Next.js Flight` tabs appear in Burp's HTTP request and response editors when matching traffic is selected. Parsing is best-effort: Flight is an implementation format and can vary between Next.js versions.