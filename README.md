# alien-metrics

## Running:

```bash
export ROUTER_PASSWORD='SEKRIT'
export BRIDGE_IP='192.168.188.1'
RUST_LOG=info cargo run
```

## Testing

```bash
curl -s http://localhost:9898/metrics
```

## Basic Grafana Dashboard

See the included `grafana.json` for an example dashboard

## Optional: Running Prometheus

Example `prometheus.yml`

```yaml
global:
  scrape_interval: 20s

scrape_configs:
  - job_name: 'prometheus'
    scrape_interval: 20s
    static_configs:
      - targets: ['host.docker.internal:9898']
```

Run Prometheus in Docker:

```bash
 docker run \
    -p 9090:9090 \
    -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
    prom/prometheus

```
