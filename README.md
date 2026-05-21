# AIOps Certificate Lifecycle Management

AI-driven certificate lifecycle management using Ansible Automation Platform as the execution and governance layer. Demonstrates the AIOps maturity journey from reactive cert management to intelligent, risk-based automation.

## What This Does

1. **Splunk** monitors TLS certificate health across the fleet (expiry KPIs, TLS error detection)
2. **Event-Driven Ansible** ingests Splunk alerts and triggers the pipeline
3. **AAP workflow** orchestrates: scan, AI classify, approval gate, renew, validate, report
4. **LLM** (Granite, Claude, or Gemini) classifies each cert by risk and recommends renewal strategy
5. **AAP job templates** execute the right renewal per cert type (self-signed, IPA, keystore)
6. **Mattermost** provides ChatOps approvals and war room for critical certs
7. **Dashboard** provides real-time visual status with "invalidate cert" button for demos

## Why This Is AIOps (Not Just EDA)

| Without AI | With AI |
|:-----------|:--------|
| Static threshold check | LLM evaluates cert type + service criticality + blast radius |
| One renewal workflow for all | LLM selects strategy: regen vs IPA vs keytool |
| Same approval for everything | Risk-based routing: auto, AAP approval, or war room |
| No blast radius awareness | LLM identifies dependent services |

## Architecture

```
Dashboard (port 8080)                 Splunk ITSI (port 8000)
  [Invalidate Cert]                     [Cert Expiry KPIs]
  [Trigger Renewal]                     [TLS Error Detection]
         |                                      |
         v                                      v
    ┌──────────────────────────────────────────────┐
    │           EVENT-DRIVEN ANSIBLE                │
    │  cert_expiry_events.yml (Splunk alerts)       │
    │  mattermost_approval.yml (ChatOps approvals)  │
    └──────────────────┬───────────────────────────┘
                       v
    ┌──────────────────────────────────────────────┐
    │     AAP WORKFLOW: Certificate Lifecycle       │
    │                                               │
    │  [Scan] -> [Classify] -> [Approval Gate]     │
    │                              |                │
    │                     [Full Pipeline]           │
    │                              |                │
    │                        [Validate]             │
    └──────────────────────────────────────────────┘
                       |
          ┌────────────┼────────────┐
          v            v            v
     Granite       Claude       Gemini
     (RHEL AI)     (API)        (API)
```

### AAP Resources Created

| Resource | Name | Purpose |
|:---------|:-----|:--------|
| Project | Cert Lifecycle Management | Git repo with all playbooks and roles |
| Inventory | Cert Demo Hosts | EC2 instance running demo services |
| Credential | Cert Demo Machine | SSH key for EC2 access |
| Credential | LLM - Granite/Claude/Gemini | API key for AI classification |
| Credential | Mattermost Cert Lifecycle | Webhook URL for notifications |
| Job Template | Cert Discovery Scanner | Scans hosts for PEM and keystore certs |
| Job Template | Cert AI Classifier | Sends cert data to LLM for risk analysis |
| Job Template | Renew Self-Signed Certificate | Regenerates self-signed certs |
| Job Template | Renew IPA Certificate | Renews via FreeIPA certmonger |
| Job Template | Renew Java Keystore Certificate | Issues from IPA, imports to keystore |
| Job Template | Validate Cert Renewal | TLS handshake and health checks |
| Job Template | Notify Mattermost | Posts lifecycle notifications |
| Job Template | Certificate Lifecycle Full Pipeline | End-to-end orchestration |
| Workflow | Certificate Lifecycle Pipeline | Scan > Classify > Approve > Renew > Validate |
| EDA Activation | Cert Expiry Events | Handles Splunk webhook alerts |
| EDA Activation | Mattermost Cert Approvals | Handles ChatOps approval reactions |

### Future: Agent Path (AAP MCP)

The same job templates can be invoked by an AI agent via AAP MCP server:

```
Agent queries AAP MCP: "list job templates matching cert"
Agent runs "Cert Discovery Scanner" via MCP
Agent analyzes results with its own reasoning
Agent requests approval in Mattermost
Agent launches renewal job templates via MCP
Agent validates and reports
```

Same automation library, different invocation method. See `agents/` directory.

## Quick Start

### 1. Provision Everything

```bash
# Full setup: EC2 instance + demo services + Splunk + dashboard + AAP configuration
ansible-playbook playbooks/provision.yml \
  -e ec2_key_name=your-key \
  -e aws_region=us-east-2 \
  -e aap_host=https://your-aap-controller \
  -e aap_password=your-aap-password

# Or run steps separately:
ansible-playbook playbooks/provision.yml --tags ec2    # Just the EC2 instance
ansible-playbook playbooks/provision.yml --tags demo   # Just the containers and services
ansible-playbook playbooks/provision.yml --tags aap    # Just the AAP configuration
```

This creates:
- One EC2 instance running 4 demo services with expiring certs, FreeIPA, Splunk, and dashboard
- Full AAP configuration: project, inventory, 8 job templates, workflow, 2 EDA activations

### 2. Run the Demo

Open the dashboard at `http://<ec2-ip>:8080`. You'll see 4 services with cert status.

**Demo flow:**
1. Click "Invalidate Cert" on a service
2. Dashboard shows the cert as expired (red)
3. Splunk detects the TLS failure (check at `http://<ec2-ip>:8000`)
4. Splunk fires webhook to EDA
5. EDA triggers the AAP workflow
6. Workflow runs: scan > classify with AI > approval gate > renew > validate
7. Dashboard updates to green
8. Mattermost shows the full conversation

Or launch the workflow directly from AAP: go to Templates > Certificate Lifecycle Pipeline > Launch.

### 3. Tear Down

```bash
ansible-playbook playbooks/teardown.yml
```

## Project Structure

```
roles/
  provision_demo/       # EC2: podman containers, certs, Splunk, dashboard
  provision_aap/        # AAP: credentials, project, inventory, templates, workflow, EDA
  cert_scanner/         # Discovers PEM and keystore certs
  cert_classifier/      # Sends cert data to LLM, parses risk/strategy
  cert_renew_selfsigned/  # Self-signed cert regeneration
  cert_renew_ipa/       # IPA/certmonger-based renewal
  cert_renew_keystore/  # Java keystore cert renewal
  cert_validator/       # TLS handshake + chain + health checks
  cert_reporter/        # Mattermost notifications

playbooks/
  provision.yml         # Full setup (EC2 + demo + AAP)
  scan.yml              # Run cert scanner
  classify.yml          # AI classification
  renew.yml             # Execute renewals by risk level
  renew_self_signed.yml # Single self-signed renewal (survey-driven)
  renew_ipa.yml         # Single IPA renewal (survey-driven)
  renew_keystore.yml    # Single keystore renewal (survey-driven)
  validate.yml          # Post-renewal validation
  notify.yml            # Mattermost notification
  full_pipeline.yml     # End-to-end orchestration
  teardown.yml          # Destroy demo environment

eda/rulebooks/
  cert_expiry_events.yml    # Splunk ITSI/ES -> pipeline trigger
  mattermost_approval.yml  # ChatOps approval -> renewal

agents/
  discover_certs_agent.py   # Future: agent using AAP MCP

splunk/
  README.md                 # Splunk ITSI KPI and alert configuration
```

## Demo Services

| Service | Port | Cert Type | Expires In | Risk |
|:--------|-----:|:----------|:-----------|:-----|
| webserver-dev | 8443 | Self-signed PEM | 2 days | Low |
| webserver-internal | 8444 | IPA-issued PEM | 5 days | Medium |
| api-server | 8445 | IPA-issued JKS keystore | 3 days | Critical |
| internal-api | 8446 | IPA-issued JKS keystore | 7 days | Medium |

## LLM Configuration

All providers use the OpenAI-compatible chat completions API. Set in `group_vars/all.yml`:

```yaml
llm_provider: granite  # granite | claude | gemini
```
