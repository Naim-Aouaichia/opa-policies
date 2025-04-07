package ghas

default deny = false

deny = true if {
  some i
  input[i].rule.security_severity_level == "high"
}