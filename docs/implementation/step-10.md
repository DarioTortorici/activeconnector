# Step 10 — Group membership slice

First verified mutation E2E (resolve → preflight → mutate → same-DC
read-after-write, NO_OP idempotency). Owner: services track. API:
`POST /groups/{guid}/members:add|:remove`; worker e2e:
`tests/e2e/test_membership_flow.py`; contract: `test_gateway_contract.py`.
