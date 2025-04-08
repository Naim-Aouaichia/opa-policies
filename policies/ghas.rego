package ghas

pass := false

pass := true if {
	count([i | input[i].rule.security_severity_level == "medium"]) == 0
}
