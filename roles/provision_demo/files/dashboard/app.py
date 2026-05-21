"""
AIOps Certificate Lifecycle Dashboard - Backend API

Provides real-time cert status, invalidation triggers, event timeline,
and Splunk/EDA integration for the demo dashboard.
"""

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import httpx

app = FastAPI(title="Cert Lifecycle Dashboard")

DEMO_BASE = os.environ.get("DEMO_BASE_DIR", "/opt/cert-demo")
CERTS_DIR = os.environ.get("DEMO_CERTS_DIR", f"{DEMO_BASE}/certs")
KEYSTORES_DIR = os.environ.get("DEMO_KEYSTORES_DIR", f"{DEMO_BASE}/keystores")
EDA_WEBHOOK = os.environ.get("EDA_WEBHOOK_URL", "http://localhost:5000/endpoint")
SPLUNK_HEC = os.environ.get("SPLUNK_HEC_URL", "http://localhost:8088/services/collector/event")
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "cert-demo-hec-token")

AAP_HOST = os.environ.get("AAP_HOST", "")
AAP_USERNAME = os.environ.get("AAP_USERNAME", "admin")
AAP_PASSWORD = os.environ.get("AAP_PASSWORD", "")
AAP_PIPELINE_JT_ID = os.environ.get("AAP_PIPELINE_JT_ID", "111")
EDA_EVENT_STREAM_URL = os.environ.get("EDA_EVENT_STREAM_URL", "")
EDA_EVENT_STREAM_USER = os.environ.get("EDA_EVENT_STREAM_USER", "cert-demo")
EDA_EVENT_STREAM_PASS = os.environ.get("EDA_EVENT_STREAM_PASS", "")

SERVICES = json.loads(os.environ.get("DEMO_SERVICES", "[]"))

events_log = []


def add_event(event_type, service, message, details=None):
    event = {
        "id": len(events_log) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "service": service,
        "message": message,
        "details": details or {},
    }
    events_log.append(event)
    if len(events_log) > 100:
        events_log.pop(0)
    return event


def check_cert_status(host, port):
    try:
        result = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{host}:{port}",
                "-servername", host,
            ],
            input=b"",
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0 and b"BEGIN CERTIFICATE" not in result.stdout:
            return {
                "status": "error",
                "error": "TLS handshake failed",
                "days_remaining": -1,
            }

        cert_result = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate", "-subject", "-issuer", "-serial"],
            input=result.stdout,
            capture_output=True,
            timeout=5,
        )
        if cert_result.returncode != 0:
            return {
                "status": "error",
                "error": "Cannot parse certificate",
                "days_remaining": -1,
            }

        output = cert_result.stdout.decode()
        lines = {
            line.split("=", 1)[0]: line.split("=", 1)[1]
            for line in output.strip().split("\n")
            if "=" in line
        }

        expiry_str = lines.get("notAfter", "").strip()
        try:
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            days = -1

        subject = lines.get("subject", "unknown")
        issuer = lines.get("issuer", "unknown")
        is_self_signed = subject.strip() == issuer.strip()

        if days < 0:
            status = "expired"
        elif days <= 7:
            status = "critical"
        elif days <= 30:
            status = "warning"
        else:
            status = "valid"

        return {
            "status": status,
            "days_remaining": days,
            "expiry": expiry_str,
            "subject": subject.strip(),
            "issuer": issuer.strip(),
            "is_self_signed": is_self_signed,
            "serial": lines.get("serial", "unknown").strip(),
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "Connection timeout", "days_remaining": -1}
    except Exception as e:
        return {"status": "error", "error": str(e), "days_remaining": -1}


@app.get("/api/services")
async def get_services():
    results = []
    for svc in SERVICES:
        cert_info = check_cert_status("localhost", svc["port"])
        results.append({
            "name": svc["name"],
            "description": svc["description"],
            "port": svc["port"],
            "cert_type": svc["cert_type"],
            "expected_risk": svc.get("risk_level", "unknown"),
            "cert_cn": svc.get("cert_cn", ""),
            "cert_status": cert_info,
        })
    return {"services": results, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/api/invalidate/{service_name}")
async def invalidate_cert(service_name: str):
    svc = next((s for s in SERVICES if s["name"] == service_name), None)
    if not svc:
        raise HTTPException(status_code=404, detail=f"Service {service_name} not found")

    try:
        if svc["cert_type"] in ("self-signed", "ipa"):
            cert_dir = f"{CERTS_DIR}/{service_name}"
            # Generate an already-expired cert
            subprocess.run(
                [
                    "openssl", "req", "-new", "-x509", "-nodes",
                    "-keyout", f"{cert_dir}/tls.key",
                    "-out", f"{cert_dir}/tls.crt",
                    "-days", "1",
                    "-subj", f"/CN={svc['cert_cn']}/O=EXPIRED/OU=Demo",
                ],
                check=True, capture_output=True,
            )
            # Reload the nginx container
            subprocess.run(
                ["podman", "exec", service_name, "nginx", "-s", "reload"],
                check=True, capture_output=True,
            )

        elif svc["cert_type"] == "keystore":
            cert_dir = f"{CERTS_DIR}/{service_name}"
            ks_dir = f"{KEYSTORES_DIR}/{service_name}"
            ks_pass = svc.get("keystore_password", "changeit")

            # Generate expired cert
            subprocess.run(
                [
                    "openssl", "req", "-new", "-x509", "-nodes",
                    "-keyout", f"{cert_dir}/tls.key",
                    "-out", f"{cert_dir}/tls.crt",
                    "-days", "1",
                    "-subj", f"/CN={svc['cert_cn']}/O=EXPIRED/OU=Demo",
                ],
                check=True, capture_output=True,
            )
            # Create PKCS12 and import into keystore
            subprocess.run(
                [
                    "openssl", "pkcs12", "-export",
                    "-in", f"{cert_dir}/tls.crt",
                    "-inkey", f"{cert_dir}/tls.key",
                    "-out", f"{cert_dir}/expired.p12",
                    "-name", service_name,
                    "-passout", f"pass:{ks_pass}",
                ],
                check=True, capture_output=True,
            )
            # Remove old entry
            subprocess.run(
                [
                    "keytool", "-delete",
                    "-keystore", f"{ks_dir}/keystore.jks",
                    "-storepass", ks_pass,
                    "-alias", service_name,
                ],
                capture_output=True,
            )
            # Import expired cert
            subprocess.run(
                [
                    "keytool", "-importkeystore",
                    "-srckeystore", f"{cert_dir}/expired.p12",
                    "-srcstoretype", "PKCS12",
                    "-srcstorepass", ks_pass,
                    "-destkeystore", f"{ks_dir}/keystore.jks",
                    "-deststorepass", ks_pass,
                    "-noprompt",
                ],
                check=True, capture_output=True,
            )
            # Restart container
            subprocess.run(
                ["podman", "restart", service_name],
                check=True, capture_output=True,
            )

        event = add_event(
            "invalidate", service_name,
            f"Certificate invalidated for {service_name}. Sending failure event to Splunk.",
        )

        await send_splunk_event(service_name)
        add_event("observe", service_name, "Cert failure event sent to Splunk")

        job_id, error = await launch_aap_job()
        if job_id:
            add_event(
                "trigger", service_name,
                f"AIOps pipeline launched (AAP job #{job_id}). Scan > AI Classify > Renew > Validate.",
            )
        else:
            add_event("trigger", service_name, f"AAP launch failed: {error}")

        return {"status": "invalidated", "service": service_name, "aap_job_id": job_id, "event": event}

    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to invalidate: {e.stderr.decode() if e.stderr else str(e)}",
        )


async def send_splunk_event(service_name, event_type="cert_invalidated"):
    if not SPLUNK_HEC_TOKEN:
        return None, "Splunk HEC not configured"
    payload = {
        "event": {
            "source": "splunk_itsi",
            "kpi": "cert_expiry",
            "host": "localhost",
            "service": service_name,
            "status": "expired",
            "days_remaining": -1,
            "severity": "critical",
            "event_type": event_type,
        },
        "sourcetype": "cert_check",
    }
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(
                SPLUNK_HEC,
                headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
                json=payload,
                timeout=10,
            )
            return resp.status_code, None
    except Exception as e:
        return None, str(e)


async def launch_aap_job(job_template_id=None):
    if not AAP_HOST or not AAP_PASSWORD:
        return None, "AAP not configured"
    url = f"{AAP_HOST}/api/controller/v2/job_templates/{job_template_id or AAP_PIPELINE_JT_ID}/launch/"
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(
                url,
                auth=(AAP_USERNAME, AAP_PASSWORD),
                json={},
                timeout=15,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return data.get("id"), None
            return None, f"AAP returned {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return None, str(e)


@app.post("/api/trigger-scan")
async def trigger_scan():
    job_id, error = await launch_aap_job()
    if job_id:
        event = add_event(
            "trigger", "all",
            f"Full pipeline launched in AAP (job #{job_id})",
        )
        return {"status": "triggered", "aap_job_id": job_id, "event": event}
    else:
        event = add_event("trigger", "all", f"Pipeline trigger failed: {error}")
        return {"status": "error", "detail": error, "event": event}


@app.post("/api/trigger-renewal/{service_name}")
async def trigger_renewal(service_name: str):
    svc = next((s for s in SERVICES if s["name"] == service_name), None)
    if not svc:
        raise HTTPException(status_code=404, detail=f"Service {service_name} not found")

    job_id, error = await launch_aap_job()
    if job_id:
        event = add_event(
            "trigger", service_name,
            f"Renewal pipeline launched in AAP (job #{job_id}) for {service_name}",
        )
        return {"status": "triggered", "aap_job_id": job_id, "event": event}
    else:
        event = add_event("trigger", service_name, f"Trigger failed: {error}")
        return {"status": "error", "detail": error, "event": event}


@app.get("/api/events")
async def get_events(limit: int = 50):
    return {"events": events_log[-limit:], "total": len(events_log)}


@app.get("/api/metrics")
async def get_metrics():
    services = []
    total_certs = 0
    expired = 0
    critical = 0
    warning = 0
    valid = 0

    for svc in SERVICES:
        info = check_cert_status("localhost", svc["port"])
        total_certs += 1
        s = info["status"]
        if s == "expired":
            expired += 1
        elif s == "critical":
            critical += 1
        elif s == "warning":
            warning += 1
        elif s == "valid":
            valid += 1
        services.append({
            "name": svc["name"],
            "days_remaining": info.get("days_remaining", -1),
            "status": s,
        })

    return {
        "total_certs": total_certs,
        "expired": expired,
        "critical": critical,
        "warning": warning,
        "valid": valid,
        "services": services,
        "renewal_count": len([e for e in events_log if e["type"] == "renewal"]),
        "invalidation_count": len([e for e in events_log if e["type"] == "invalidate"]),
        "last_scan": next(
            (e["timestamp"] for e in reversed(events_log) if e["type"] == "scan"),
            None,
        ),
    }


@app.get("/")
async def index():
    return FileResponse(f"{os.path.dirname(__file__)}/static/index.html")


app.mount("/static", StaticFiles(directory=f"{os.path.dirname(__file__)}/static"), name="static")
