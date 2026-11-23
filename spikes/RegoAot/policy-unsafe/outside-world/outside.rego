package sentinel

import rego.v1

# A bundle that reaches outside the process. Validation must refuse it.

deny contains "reached the network" if {
	resp := http.send({"method": "get", "url": "https://example.com/"})
	resp.status_code == 200
}

