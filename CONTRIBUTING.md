# Contributing to ContainArmor

Thank you for your interest in contributing to **ContainArmor**! We welcome contributions from the cybersecurity and software engineering communities to help harden containerized infrastructures against intra-bridge traversal, privilege escalation, and netfilter vulnerabilities.

---

## 🛠️ Development Workflow

### Prerequisites
* [.NET 9.0 SDK](https://dotnet.microsoft.com/)
* [Docker Engine 24+](https://docs.docker.com/engine/install/) (with Unix Domain Socket access at `/var/run/docker.sock`)
* Docker Compose v2

### Clone & Build
```bash
git clone https://github.com/namanbhatt/ContainArmor.git
cd ContainArmor

# Restore and build all solution components
dotnet restore
dotnet build ContainArmor.sln
```

### Running Tests
All tests are implemented with xUnit:
```bash
dotnet test ContainArmor.sln --logger "console;verbosity=detailed"
```

### Launching the Dashboard Locally
```bash
# Launch interactive Blazor SOC dashboard on port 5200
dotnet run --project src/ContainArmor.Blazor --urls http://127.0.0.1:5200
```

---

## 🏛️ Repository Architecture

* `src/ContainArmor.Engine/`: Core domain logic, Docker Unix Socket client, CIS benchmark evaluator, bridge matrix calculation, iptables netfilter auditor, and remediation service.
* `src/ContainArmor.Api/`: ASP.NET Core Minimal API with SignalR real-time event broadcasting hub.
* `src/ContainArmor.Blazor/`: Tactical cyber SOC dashboard with real-time SignalR live streaming and visual network topology SVG.
* `tests/ContainArmor.Tests/`: Unit test suite covering container security inspection, intra-bridge privilege asymmetry, iptables rule audits, and remediation pipelines.
* `tests/vulnerable-containers/`: Docker Compose test fleet with deliberate vulnerabilities for testing and demonstration.

---

## 🛡️ Coding Guidelines

1. **Security-First Defensive Code**: Always handle potential null or malformed Docker daemon responses without crashing the background daemon.
2. **Deterministic CIS Benchmark Mappings**: Explicitly map new container inspection rules to official CIS Docker Benchmark IDs (e.g., `CIS-5.1`, `CIS-5.31`).
3. **No External Bloat**: Avoid third-party Docker daemon wrappers. The project relies on native `SocketsHttpHandler` Unix Domain Sockets for lightweight, non-privileged, high-performance IPC.
4. **Comprehensive Test Coverage**: Any new inspection rule or netfilter parser feature must include corresponding xUnit unit tests in `tests/ContainArmor.Tests/`.
