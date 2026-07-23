# TDS proration API

Deploy this folder as a Python web service, then submit its public URL with `/charge` appended.

Example request:

```json
{"old_price":9,"new_price":39,"days_remaining":19,"days_in_actual_month":29,"spec":"v2"}
```

The expected response is `{"charge":19.655172413793103}`.
