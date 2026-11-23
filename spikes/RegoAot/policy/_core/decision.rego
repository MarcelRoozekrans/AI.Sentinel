package sentinel

import rego.v1

# Host-provided: combines the outcomes of every bundle. Strictest first:
# deny, ask, guidance, allow, defer. The strictest outcome wins across bundles.

default outcome := "defer"

outcome := "deny" if count(deny) > 0

else := "ask" if count(ask) > 0

else := "guidance" if count(guidance) > 0

else := "allow" if count(allow) > 0

reasons := array.concat(
	array.concat([r | some r in deny], [r | some r in ask]),
	array.concat([r | some r in guidance], [r | some r in allow]),
)

decision := {"outcome": outcome, "reasons": reasons}
