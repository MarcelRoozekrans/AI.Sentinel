package sentinel

import rego.v1

# Bundle org-baseline: the rules every repository gets.

deny contains "recursive delete" if {
	input.kind == "shell"
	some c in input.shell.commands
	c.name == "rm"
	some a in c.args
	a in {"-rf", "-fr", "-r"}
}

deny contains "write outside the repository" if {
	input.kind in {"write", "edit"}
	some p in input.files
	not p.inside_repo
}

deny contains sprintf("critical finding from %s", [f.detector]) if {
	some f in input.findings
	f.severity == "critical"
}

ask contains "git push needs a person" if {
	input.kind == "shell"
	some c in input.shell.commands
	c.name == "git"
	c.args[0] == "push"
}

ask contains "network fetch needs a person" if input.kind == "fetch"
