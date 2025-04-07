package ghas

default deny = []

# Exemple de règle : interdire les vulnérabilités critiques non corrigées
deny[message] {
  some i
  vuln := input[i]
  vuln.rule.severity == "critical"
  vuln.dismissed == false
  message := sprintf("Vuln critique non corrigée : %s", [vuln.rule.id])
}

# Exemple : blocage si vulnérabilité Semgrep sur des secrets
deny[message] {
  some i
  vuln := input[i]
  startswith(vuln.rule.id, "semgrep.secret.")
  message := sprintf("Fuite potentielle de secret détectée : %s", [vuln.rule.description])
}