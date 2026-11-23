package sentinel

import rego.v1

# A bundle that reaches outside the process. Validation must refuse it. The kind guards keep
# each rule from running unless a probe input asks for it.

deny contains "reached the network" if {
	input.kind == "probe-http"
	resp := http.send({"method": "get", "url": "https://example.com/"})
	resp.status_code == 200
}

ask contains "resolved a host name" if {
	input.kind == "probe-dns"
	addrs := net.lookup_ip_addr("example.com")
	count(addrs) > 0
}

guidance contains "read the runtime" if {
	input.kind == "probe-runtime"
	rt := opa.runtime()
	rt.version != ""
}
