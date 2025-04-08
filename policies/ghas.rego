package ghas

pass := count([i | input[i].rule.security_severity_level == "high"]) == 0
