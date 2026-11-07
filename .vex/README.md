# VEX statements for Docker Scout

OpenVEX documents (`*.json`) here tell the Docker Scout image scan
(`.github/workflows/security-gate.yml`, `security.yml`) that a reported
vulnerability does not affect Stackurity. Add one only with a concrete
justification (for example `vulnerable_code_not_in_execute_path`) and an
`impact_statement` saying why; Trivy's equivalent is `.trivyignore.yaml`.
Remove the statement once the package is upgraded.
