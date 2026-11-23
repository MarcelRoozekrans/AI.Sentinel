package sentinel

import rego.v1

# Bundle team-guidance: softer rules a team adds on top of the baseline.

guidance contains "prefer the gh CLI over the GitHub MCP server" if {
	input.kind == "mcp"
	input.mcp.server == "github"
}

guidance contains "pin the package version when installing" if {
	input.kind == "shell"
	some c in input.shell.commands
	c.name == "npm"
	c.args[0] == "install"
}

allow contains "read inside the repository" if {
	input.kind in {"read", "search"}
	every p in input.files {
		p.inside_repo
	}
}

allow contains "read-only shell command" if {
	input.kind == "shell"
	count(input.shell.commands) > 0
	every c in input.shell.commands {
		c.name in {"ls", "pwd", "cat"}
	}
}
