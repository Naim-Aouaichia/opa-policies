package ghas

default pass := true

pass = false if {
  some i
  input[i].rule.security_severity_level == "high"
}
