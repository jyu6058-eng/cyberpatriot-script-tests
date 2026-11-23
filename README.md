# CyberPatriot script tests

Runs `scripts/Audit.ps1`, `scripts/Harden.ps1` and `scripts/Users.ps1` on a throwaway
GitHub Actions Windows Server 2022 VM (Windows PowerShell 5.1).

1. `tests/plant.ps1` plants about 40 CyberPatriot-style vulnerabilities. It blocks inbound
   test ports first, so nothing planted is reachable from the internet.
2. Audit runs before; Harden `-DryRun` and the Users.ps1 dry run are checked to change nothing;
   then Users `-Apply` and Harden run; then Harden runs again with `-ExploitProtection`.
3. `tests/verify.ps1` checks what Audit detected and the real Windows state afterwards,
   and writes a pass/fail table to the job summary. Reports are uploaded as the `test-reports` artifact.

Not covered: the domain-controller paths (the VM cannot be promoted and rebooted). Harden's DNS
block is extracted and run on a standalone DNS server instead.
