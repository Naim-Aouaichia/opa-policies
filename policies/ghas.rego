package ghas

pass if {
	count([i | input[i].rule.security_severity_level == "critical"]) == 0
}
