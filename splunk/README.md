# Splunk Configuration for Cert Lifecycle Demo

## Prerequisites

- Splunk Enterprise or Cloud with ITSI add-on
- "Red Hat Event Driven Ansible Add-on for Splunk" (v1.0.1+) from Splunkbase
- EDA controller endpoint accessible from Splunk

## ITSI KPI: Certificate Expiry

Create a KPI in Splunk ITSI to track certificate expiry across monitored endpoints.

### Saved Search

```spl
| tstats count where index=cert_monitoring sourcetype=cert_check by host, cert_cn, days_remaining
| eval health_score=case(
    days_remaining > 30, 100,
    days_remaining > 14, 75,
    days_remaining > 7, 50,
    days_remaining > 0, 25,
    days_remaining <= 0, 0
  )
| eval status=case(
    days_remaining > 30, "healthy",
    days_remaining > 7, "warning",
    days_remaining > 0, "critical",
    days_remaining <= 0, "expired"
  )
```

### Notable Event Action (ITSI -> EDA)

Configure a Notable Event Action in ITSI to send a webhook to EDA when the
cert_expiry KPI drops below 50 (< 7 days remaining):

**Webhook URL:** `https://<eda-controller>:5000/endpoint`

**Payload:**
```json
{
  "source": "splunk_itsi",
  "kpi": "cert_expiry",
  "host": "$result.host$",
  "cert_cn": "$result.cert_cn$",
  "days_remaining": "$result.days_remaining$",
  "severity": "$result.status$",
  "episode_id": "$result.episode_id$"
}
```

## Enterprise Security: TLS Failure Detection

### Correlation Search

```spl
index=web_logs sourcetype=nginx_error
  ("SSL_ERROR" OR "certificate verify failed" OR "expired certificate" OR "ssl_stapling")
| stats count by host, src_ip, error_msg
| where count > 5
| eval search_name="tls_failure_detection"
```

### Adaptive Response Action

Configure an Adaptive Response Action to send to EDA:

**Webhook URL:** `https://<eda-controller>:5000/endpoint`

**Payload:**
```json
{
  "source": "splunk_es",
  "search_name": "tls_failure_detection",
  "host": "$result.host$",
  "error_count": "$result.count$",
  "severity": "high"
}
```

## Certificate Monitoring Data Collection

To populate the cert_monitoring index, deploy a scripted input or use a
Splunk add-on that periodically checks TLS certificates on monitored endpoints.

Simple scripted input example:

```bash
#!/bin/bash
# Check cert expiry for a list of hosts
for host_port in "webserver:8443" "webserver:8444" "appserver:8445"; do
  host=$(echo $host_port | cut -d: -f1)
  port=$(echo $host_port | cut -d: -f2)
  expiry=$(echo | openssl s_client -connect $host:$port 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
  cn=$(echo | openssl s_client -connect $host:$port 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN = //')
  days=$(( ($(date -d "$expiry" +%s) - $(date +%s)) / 86400 ))
  echo "$(date +%Y-%m-%dT%H:%M:%S) host=$host cert_cn=$cn days_remaining=$days port=$port"
done
```
