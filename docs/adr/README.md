# Architecture Decision Records

| ADR | Title | Status | Date |
|---|---|---|---|
| [0001](0001-private-prototype-scope.md) | Keep the first validation private and read-only | accepted | 2026-09-04 |
| [0002](0002-powershell-readonly-module-shape.md) | Use one PowerShell read-only module shape | accepted; input/remote-target allowance partially superseded by [ADR-0003](0003-reject-unc-private-prototype.md) | 2026-09-04 |
| [0003](0003-reject-unc-private-prototype.md) | Reject UNC paths in the private prototype | accepted; its network-silence implication is partially superseded by [ADR-0004](0004-stable-topology-boundary.md) | 2026-09-05 |
| [0004](0004-stable-topology-boundary.md) | Limit path evidence to stable, non-adversarial topology | accepted; partially supersedes [ADR-0003](0003-reject-unc-private-prototype.md) | 2026-09-13 |
| [0005](0005-native-identity-collection.md) | Hold native filesystem identities during collection | accepted native implementation | 2026-09-20 |

The initial private-scope distribution gate is superseded for experimental source releases by [ADR-0006](0006-experimental-public-release.md). Historical design context below is not the current installation guide.

ADRs record decisions in effect. A later decision that replaces one must mark the older ADR as superseded and link both directions.

- [ADR-0006: experimental public release](0006-experimental-public-release.md), accepted 2026-09-20.
