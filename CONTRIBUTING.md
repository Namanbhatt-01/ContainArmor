# Contributing to ContainArmor

Contributions are welcome from the software engineering and cybersecurity communities. This guide outlines the development standards, workflow, and testing requirements for ContainArmor.

---

## Development Prerequisites

* .NET 9.0 SDK
* Docker Engine 24.0+ (with active daemon Unix socket at `/var/run/docker.sock`)
* Docker Compose v2.0+
* Git 2.30+

---

## Workspace Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/Namanbhatt-01/ContainArmor.git
   cd ContainArmor
   ```

2. Restore solution dependencies and build:
   ```bash
   dotnet restore ContainArmor.sln
   dotnet build ContainArmor.sln
   ```

3. Run the automated test suite:
   ```bash
   dotnet test ContainArmor.sln --logger "console;verbosity=detailed"
   ```

4. Launch the local development server:
   ```bash
   dotnet run --project src/ContainArmor.Blazor --urls http://127.0.0.1:5200
   ```

---

## Architecture Breakdown

* `src/ContainArmor.Engine/`: Core domain logic, Docker Unix Socket client, CIS benchmark evaluator, bridge isolation auditor, iptables netfilter auditor, and remediation service.
* `src/ContainArmor.Api/`: ASP.NET Core Minimal API with SignalR real-time event broadcasting hub.
* `src/ContainArmor.Blazor/`: Tactical cyber SOC dashboard with real-time SignalR live streaming and visual network topology SVG.
* `tests/ContainArmor.Tests/`: Unit test suite covering container security inspection, intra-bridge privilege asymmetry, iptables rule audits, and remediation pipelines.
* `tests/vulnerable-containers/`: Docker Compose test fleet with deliberate vulnerabilities for testing and demonstration.

---

## Engineering Standards

1. **Defensive Programming**: All parsing logic interfacing with the Docker daemon or netfilter subsystem must handle null, empty, or malformed data structures gracefully without process termination.
2. **Deterministic Security IDs**: Any new audit check must map directly to an established industry benchmark (CIS Docker Benchmark v1.6.0, MITRE ATT&CK for Containers, or NIST SP 800-190).
3. **No External Wrapper Dependencies**: Interfacing with `/var/run/docker.sock` must remain native using `SocketsHttpHandler` Unix Domain Sockets for lightweight, non-privileged, high-performance IPC.
4. **Test Verification**: All functional modifications or bug fixes must include corresponding xUnit test cases in `tests/ContainArmor.Tests/`.
