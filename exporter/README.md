# voltage-exporter (Python package)

Synthetic-probe Prometheus exporter for OpenText Voltage SecureData. Documentation,
docker-compose demo, alert rules, Grafana dashboard and the companion Ansible collection
live in the repository root: https://github.com/FlavioImbertDomingos/voltage-toolkit

```bash
pip install .
voltage-exporter -c config.yml
curl localhost:9743/metrics
```
