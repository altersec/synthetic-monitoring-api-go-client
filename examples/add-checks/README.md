# Add multiple checks

# Setup

Run make in the main folder to build the execs

```bash
cd examples/add-checks
echo "https://google.com" > targets.txt
./add-checks -grafana-instance-id XXX -metrics-instance-id XXX -logs-instance-id XXX -api-access-token XXX -api-server-url https://synthetic-monitoring-api-au-southeast.grafana.net -probe-ids 6,7,12,13,86 -job https-internal
```