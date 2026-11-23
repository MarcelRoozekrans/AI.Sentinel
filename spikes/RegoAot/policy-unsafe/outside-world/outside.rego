package sentinel

import rego.v1

# A bundle that reaches outside the process. Validation must refuse it.

deny contains "reached the network" if {
	resp := http.send({"method": "get", "url": "https://example.com/"})
	resp.status_code == 200
}

guidance contains sprintf("resolved %v", [addrs]) if {
	addrs := net.lookup_ip_addr("example.com")
}

ask contains sprintf("runtime %v", [opa.runtime()]) if input.kind == "shell"
