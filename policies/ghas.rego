package ghas

default deny = []

deny[reason] {
  some i
  input[i].rule.security_severity_level == "critical"
  reason := sprintf("Critical vulnerability found: %s", [input[i].rule.id])
}