# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.3.x | Supported |
| 0.2.x and earlier | Unsupported; custom OAuth implementation removed |

## Report a vulnerability

Use [GitHub's private vulnerability reporting form](https://github.com/5queezer/mcp-oauth-template/security/advisories/new). If GitHub reports that private reporting is unavailable, ask the repository owner for a private contact channel through the contact method on their GitHub profile. Do not include vulnerability details in that request or open a public issue before maintainers have had time to investigate and prepare a fix.

Include the affected version, impact, reproduction steps, and any suggested mitigation. Remove credentials, bearer tokens, personal data, and live service URLs from the report. Maintainers do not offer a response-time guarantee.

## Security boundary

This project delegates OAuth protocol handling to FastMCP and owns the GitHub numeric-ID authorization policy, application factory, examples, and deployment configuration. Reports about those integration points belong here. Report vulnerabilities in FastMCP, the MCP SDK, GitHub, or a cloud platform to the upstream project as well.

The default encrypted FastMCP store is local to one container filesystem. The Cloud Run reference sets one maximum instance, but rollouts can overlap revisions and restarts lose local state. Operators must provide shared, durable, encrypted storage before scaling or relying on state across revisions. They must also protect OAuth client secrets, review dependency updates, and keep demo mode off on untrusted networks.

The public client-registration and consent routes have no project-level rate limiter or storage quota. Internet-facing deployments need edge abuse controls, storage monitoring, and a retention policy.

The repository's automated dependency audit checks published advisories. It does not certify the application or its deployment.
