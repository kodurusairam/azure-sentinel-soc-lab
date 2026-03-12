# 🛡️ Microsoft Sentinel SOC Lab

> End-to-end SIEM deployment on Microsoft Azure — workspace setup, 
> data connectors, live incident generation, and KQL threat detection.

![Platform](https://img.shields.io/badge/Platform-Microsoft%20Azure-0078D4?logo=microsoftazure)
![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?logo=microsoft)
![Language](https://img.shields.io/badge/Query%20Language-KQL-00B4D8)
![Status](https://img.shields.io/badge/Status-Completed-107C10)

---

## 🏗️ Architecture

![SOC Architecture](architecture.svg)

## 📋 Project Overview

| Detail | Value |
|--------|-------|
| Platform | Microsoft Azure |
| SIEM | Microsoft Sentinel |
| Workspace | sentinal-workspace |
| Region | Central India |
| Data Connectors | 8 (Training Lab) + Azure Activity (manual) |
| Incidents Generated | 3 (1 High, 2 Medium) |
| KQL Queries | 4 SOC detection queries |

---

## 🔧 Lab Setup

### 1. Log Analytics Workspace
- Created Resource Group: `sentinal-rg`
- Deployed Log Analytics Workspace: `sentinal-workspace` (Central India)

### 2. Microsoft Sentinel Deployment
- Added Sentinel to `sentinal-workspace`
- Installed Microsoft Sentinel Training Lab Solution from Content Hub
- Training Lab provisioned 8 data connectors automatically
- Azure Activity connector was disconnected — manually reconfigured it

### 3. Incidents Generated
- 3 live incidents auto-generated from Training Lab attack simulation
- 1 High severity, 2 Medium severity

---

## 🔍 KQL Detection Queries

### 1. Brute Force Detection
```kql
DeviceLogonEvents
| where LogonType == "Network"
| summarize Attempts = count() by AccountName, DeviceName
| where Attempts > 5
| sort by Attempts desc
```

### 2. Suspicious Process Execution (LOLBins)
```kql
DeviceProcessEvents
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp desc
| take 20
```

### 3. Network Beaconing / C2 Detection
```kql
DeviceNetworkEvents
| summarize Connections = count() by DeviceName, RemoteIP, RemotePort
| where Connections > 10
| sort by Connections desc
| take 20
```

### 4. Impossible Travel / Login Anomaly
```kql
UserLoginEvents
| summarize LoginCount = count() by UserName, Location, IPAddress
| sort by LoginCount desc
| take 20
```

---

## 📸 Screenshots

### Sentinel Overview — Live Incidents
![Sentinel Overview](sentinal%20workspace/04-sentinel-overview-incidents-detected.png.png)

### Data Connectors
![Data Connectors](sentinal%20workspace/05-sentinel-data-connectors-8-connected.png.png)

### KQL — Brute Force Detection
![Brute Force](sentinal%20workspace/08-kql-network-logon-attempts-brute-force.png.png)

### KQL — Suspicious Process Execution
![Suspicious Process](sentinal%20workspace/09-kql-suspicious-process-execution.png.png)

### KQL — Network Beaconing
![Network Beaconing](sentinal%20workspace/10-kql-network-beaconing-detection.png.png)

### KQL — Login Anomaly
![Login Anomaly](sentinal%20workspace/11-kql-user-login-location-analysis.png.png)

---

## 🛠️ Skills Demonstrated

- Microsoft Azure — Resource Groups, Log Analytics, Subscriptions
- Microsoft Sentinel — Deployment, Data Connectors, Incident Management
- KQL — summarize, where, project, sort, dcount, make_set
- Threat Detection — Brute force, LOLBins, C2 beaconing, Impossible travel
- SOC Workflows — Incident triage, severity classification, threat hunting

---

## 📄 Documentation

Full project documentation with screenshots available in [Azure-Sentinel-SOC-Threat-Hunting-Lab.pdf](Azure-Sentinel-SOC-Threat-Hunting-Lab.pdf)

---

## 👤 Author

**Sairam Koduru**  
SOC Analyst | TryHackMe Top 1% | [github.com/kodurusairam](https://github.com/kodurusairam)
