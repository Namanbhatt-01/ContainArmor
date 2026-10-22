# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## Reporting a Vulnerability

Security is paramount to ContainArmor. If you discover a security vulnerability within ContainArmor itself (e.g. privilege escalation vector, unintended command execution, or netfilter injection flaw), please follow these guidelines:

1. **Do not create public GitHub issues** for security vulnerabilities.
2. Email the maintainers with a detailed proof-of-concept (PoC), reproduction steps, and impact assessment.
3. You will receive an acknowledgment within 48 hours.
4. We coordinate a remediation patch and assign appropriate CVE advisories before public disclosure.

---

## Security Model & Threat Boundaries

ContainArmor requires access to `/var/run/docker.sock` to inspect containers, read network configurations, and listen to Docker lifecycle events.

To protect the host when running ContainArmor:
* In production, deploy ContainArmor using a read-only Docker socket proxy or run as a dedicated security monitoring daemon.
* ContainArmor's remediation engine strictly executes validated container commands (`pause`, `stop`, `disconnect`) and sanitizes all generated iptables drop rules.
