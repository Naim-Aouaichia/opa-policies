package ghas

default deny = []

# Rules exemple : forbid criticals vulnerabilities not patched
deny_ci_run {
    some i
    input[i].rule.security_severity_level == "critical"
}