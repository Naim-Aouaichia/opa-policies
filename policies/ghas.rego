package ci.blocking

# Helper
cid_sum := to_number(input.product_context.product_confidentiality) +
           to_number(input.product_context.product_integrity) +
           to_number(input.product_context.product_availability)

# Product qualification
product_is_critical if {
    to_number(input.product_context.product_confidentiality) == 4
}
product_is_critical if {
    to_number(input.product_context.product_integrity) == 4
}
product_is_critical if {
    to_number(input.product_context.product_availability) == 4
}

product_is_sensible if {
    cid_sum >= 7
}

product_is_exposed if {
    input.product_context.product_is_public_exposed == true
}
product_is_exposed if {
    input.product_context.product_is_public_exposed == "true"
}

product_is_critical_and_exposed if {
    product_is_critical
    product_is_exposed
}

product_is_sensible_and_exposed if {
    product_is_sensible
    product_is_exposed
}

product_is_critical_not_exposed if {
    product_is_critical
    not product_is_exposed
}

product_is_sensible_not_exposed if {
    product_is_sensible
    not product_is_exposed
}

product_is_non_sensible_exposed if {
    cid_sum < 7
    product_is_exposed
}

product_is_non_sensible_non_exposed if {
    cid_sum < 7
    not product_is_exposed
}

# Vuln count (déclarés sous forme de règles)
vuln_count_critical := count([v | v := input.ghas_report[_]; v.rule.security_severity_level == "critical"])
vuln_count_high := count([v | v := input.ghas_report[_]; v.rule.security_severity_level == "high"])
vuln_count_medium := count([v | v := input.ghas_report[_]; v.rule.security_severity_level == "medium"])
vuln_count_low := count([v | v := input.ghas_report[_]; v.rule.security_severity_level == "low"])
vuln_count_secret := count([v | v := input.ghas_report[_]; v.rule.id == "secret-detected"])

vuln_has_significant if {
    vuln_count_critical > 0
}

vuln_has_critical_or_high if {
    vuln_count_critical > 0
}
vuln_has_critical_or_high if {
    vuln_count_high > 0
}

vuln_has_critical if {
    vuln_count_critical > 0
}

# Default deny
default allow := false

# Blocking rules
block if {
    vuln_count_secret > 0
}

block if {
    product_is_critical_and_exposed
    vuln_has_significant
}

block if {
    product_is_sensible_and_exposed
    vuln_has_significant
}

block if {
    product_is_critical_not_exposed
    vuln_has_significant
}

block if {
    product_is_sensible_not_exposed
    vuln_has_critical
}

allow := true if {
    not block
}