package ghas

default pass := false

pass := true if {
	not some i
	input[i].rule.security_severity_level == "high"
}