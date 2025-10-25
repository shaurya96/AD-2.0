# 🛠️ Cybersecurity Project: Active Directory 2.0 — SOC Automation Lab

This document is the complete, updated project outline for Active Directory Project 2.0 (Parts 1–5). It describes the cloud lab, step-by-step build, Splunk ingestion and alerting, and SOAR automation with Shuffle + Slack to automatically remediate unauthorized successful logins.

## 🔍 Project Overview

Build a cloud-hosted SOC lab that demonstrates an end-to-end detection → analyst decision → automated response workflow:

- **Infrastructure**: Vultr cloud VMs (Windows Server 2022 DC, Windows Server test endpoint, Ubuntu Splunk server) inside a VPC.
- **Telemetry & Analysis**: Splunk Enterprise (indexing on port 9997) with Splunk Universal Forwarder on Windows endpoints.
- **Detection**: Splunk scheduled alert for unauthorized successful logins (Windows Event ID 4624 with logon type 7 or 10; source IP outside an "allowed" range).
- **Automation / Remediation**: Shuffle (SOAR) receives Splunk webhook, notifies via Slack + email to analyst, and — upon analyst "Yes" — disables domain user via LDAP/AD actions and posts confirmation to Slack.
- **Learning Outcomes**: AD administration, Splunk ingestion & searches, detection logic, SOAR playbook design, Slack integration, and operational troubleshooting.

## 📂 Project Parts

- **Part 1** — Diagram & Architecture (draw.io)
- **Part 2** — Cloud Deployment (Vultr VM provisioning, VPC, firewall)
- **Part 3** — Active Directory (AD DS install, domain creation, join endpoint)
- **Part 4** — Splunk & Telemetry (Splunk install, UF configuration, create alert)
- **Part 5** — SOAR Automation (Shuffle + Slack) (webhook, playbook, LDAP disable)

## ✅ Part 1 — Diagram & Architecture

**Tools**: draw.io

**Components drawn**:

### Infrastructure Components (VULTR Virtual Machines)

- **Domain Controller** — Windows Server (Domain: MyDFIR.local)
  - Acts as the Active Directory Domain Services host
  - Target for user account management and remediation actions
  
- **Test Machine** — Windows Server (Domain: MyDFIR.local)
  - Domain-joined endpoint for testing
  - Simulates production workstation with RDP access
  
- **Splunk Ubuntu Server** — Ubuntu 22.04 (Splunk Enterprise)
  - Central log aggregation and analysis platform
  - Hosts detection rules and scheduled alerts

- **Attacker Machine** — External/Internet-based threat actor
  - Simulates unauthorized access attempts
  - Triggers "Successful Authentication" events from non-whitelisted IPs

### External/Cloud Components

- **Shuffle** — SOAR automation platform
  - Receives webhook triggers from Splunk alerts
  - Orchestrates the incident response playbook
  - Integrates with Slack and Active Directory
  
- **Slack** — Communication platform
  - Receives alert notifications from Shuffle
  - Displays user account information and incident details
  - Posts confirmation messages after remediation actions

- **SOC Analyst** — Human decision-maker
  - Receives email notifications with incident details
  - Makes Yes/No decision on whether to disable compromised account
  - Triggers automated remediation workflow

### Data Flows

1. **Telemetry Collection**:
   - Both Domain Controller and Test Machine send Windows event logs to Splunk via Splunk Universal Forwarder

2. **Alert Detection**:
   - Splunk analyzes Event ID 4624 (successful logon) for unauthorized source IPs
   - Triggers "Successful Unauthorized Login Playbook" when detection rule matches

3. **Automation Workflow**:
   - **Trigger Playbook**: Splunk webhook → Shuffle
   - **Alert Notification**: Shuffle → Slack (posts to #alerts channel)
   - **Email Notification**: Shuffle → SOC Analyst with account details
   - **Decision Point**:
     - **YES** (Green diamond): Disable User → AD LDAP action disables account → Confirmation sent to Slack ("Account [Account Name] has been disabled")
     - **NO** (Pink diamond): Do Nothing

4. **Remediation Action**:
   - Shuffle executes LDAP disable_user command against Domain Controller
   - Verification step confirms account is disabled
   - Status update posted to Slack channel

### Playbook Logic (Decision Tree)

 ```text
Successful Unauthorized Login Detected
          ↓
    Alert Notification (Slack + Email)
          ↓
    SOC Analyst Decision?
          ↓
    ┌─────┴─────┐
   YES         NO
    ↓           ↓
Disable     Do Nothing
  User        
    ↓
Confirm in
  Slack
```

**Key Architecture Notes**:

- All VMs communicate over private VPC network (dotted lines represent telemetry)
- Attacker originates from public internet (successful authentication trigger)
- Shuffle acts as the central orchestration hub between detection (Splunk) and remediation (AD)
- Human-in-the-loop design ensures analyst approval before automated account disablement

<p align="center">
<img src="assets/screenshots/1.network diagram.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-1: Screenshot of Network diagram</em>
</p>

## 🔧 Part 2 — Cloud Deployment (Vultr)

**Create three VMs** :

  <p align="center">
  <img src="assets/screenshots/2.VM&apos;s-involved.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-2: Screenshot of VM's</em>
  </p>

- **MyDFIR-ADDC01**: Windows Server 2022, e.g., 2 vCPU / 4GB / 80GB
  <p align="center">
  <img src="assets/screenshots/3.AD-DC Configuration.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-3: Screenshot of AD DC VM Configuration</em>
  </p>

- **MyDFIR-Splunk**: Ubuntu 22.04, e.g., 4 vCPU / 8GB / 160GB
  <p align="center">
  <img src="assets/screenshots/7.Splunk Server Configuration.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-4: Screenshot of Splunk Server VM Configuration</em>
  </p>

- **Test Machine**: Windows Server 2022, e.g., 1 vCPU / 2GB / 55GB
  <p align="center">
  <img src="assets/screenshots/11.Test Machine Configuration.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-5: Screenshot of Test Machine (Windows) VM Configuration</em>
  </p>

**Enable VPC** (private network) for internal communication (e.g., 10.6.96.0/24).

  <p align="center">
  <img src="assets/screenshots/4.AD-DC VPC Configuration.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-6: Screenshot of AD DC VM VPC Configuration</em>
  </p>

  <p align="center">
  <img src="assets/screenshots/8.Splunk Server VPC Configuration.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-7: Screenshot of Splunk Server VM VPC Configuration</em>
  </p>

  <p align="center">
  <img src="assets/screenshots/12.Test Machine VPC Configuration.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-8: Screenshot of Test Machine (Windows) VM VPC Configuration</em>
  </p>

**Create firewall group**:

- **Allow SSH (22)** — restrict to your IP for secure management access
  - Protocol: SSH (TCP port 22)
  - Source: Your public IP
  - Note: First rule shows "Anyw..." (0.0.0.0/0) for initial setup, second rule locked to specific IP
  
- **Allow LDAP (389)** — for Active Directory/Shuffle LDAP communication
  - Protocol: TCP port 389
  - Source: 0.0.0.0/0 (open for lab; restrict to Shuffle IP in production)
  
- **Allow RDP (3389)** — initially restrict to your IP; later loosen to test alerts
  - Protocol: TCP (MS RDP) port 3389
  - Source: 0.0.0.0/0 (opened to allow unauthorized login attempts for alert testing)
  
- **Allow Splunk Web (8000)** — from analyst IP for web interface access
  - Protocol: TCP port 8000
  - Source: Your public IP for secure SOC analyst access

- **Allow Splunk indexer port (9997)** — from forwarders (internal VPC)
  - Protocol: TCP port 9997 (configure separately, not shown in screenshot)
  - Source: VPC private subnet (e.g., 10.22.96.0/24) or specific forwarder IPs

- **Default deny rule** — drop all other traffic
  - Action: drop
  - Protocol: any
  - Port range: 0-65535
  - Source: 0.0.0.0/0
  - Note: (default) — blocks all unspecified traffic

<p align="center">
<img src="assets/screenshots/15.VULTR Firewall Configuration.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-9: Screenshot of Firewall Rules in VULTR</em>
</p>

**Verify connectivity**: ping, RDP into Windows, `ssh root@<splunk-public-ip>`.
  
- **MyDFIR-ADDC01**:

<p align="center">
<img src="assets/screenshots/5.AD-DC IPV4-setup.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-10: Screenshot of AD DC VM IPv4 Setup</em>
</p>
<p align="center">
<img src="assets/screenshots/6.AD-DC RDP.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-11: Screenshot of IP Addresses (Public&Private) on AD DC VM</em>
</p>
<p align="center">
<img src="assets/screenshots/16.AD-DC Connectivity Check.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-12: Screenshot of Connectivity check via AD DC VM</em>
</p>

- **MyDFIR-Splunk**:

<p align="center">
<img src="assets/screenshots/9.Splunk Server SSH.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-13: Screenshot of Successful SSH on Splunk Server VM</em>
</p>
<p align="center">
<img src="assets/screenshots/10.Splunk Server IP Adresses.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-14: Screenshot of IP Addresses (Public&Private) on Splunk Server VM</em>
</p>
<p align="center">
<img src="assets/screenshots/17.Splunk Server Connectivity-Check-1.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-15: Screenshot of Connectivity check via Splunk Server VM</em>
</p>

- **Test Machine**:

<p align="center">
<img src="assets/screenshots/13.Test Machine IPV4-setup.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-16: Screenshot of Test Machine (Windows) VM IPv4 Setup</em>
</p>
<p align="center">
<img src="assets/screenshots/14.Tech Machine RDP.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-17: Screenshot of IP Addresses (Public&Private) on Test Machine (Windows) VM</em>
</p>
<p align="center">
<img src="assets/screenshots/18.Test Machine Connectivity-Check.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-18: Screenshot of Connectivity check via Test Machine (Windows) VM</em>
</p>

## 🧑‍💻 Part 3 — Active Directory setup

**Install Active Directory Domain Services** (Server Manager → Add Roles & Features → AD DS) and **Promote to Domain Controller** → create new forest:

- **Domain**: `MyDFIR.local`
- **DSRM password** : Set a super secure password of your choice

**Create test user**:

- Example: `JSmith`
  <p align="center">
  <img src="assets/screenshots/19.AD-DC User.png"Network Diagram" width="700"/><br>
  <em>📸 Figure-19: Screenshot of New User Created in AD environment</em>
  </p>

**Join Test-Machine to domain**:

- Configure Windows network adapter to use DC private IP as DNS
  <p align="center">
  <img src="assets/screenshots/20.Test Machine IPV4-setup.png"Network Diagram" width="700"/><br>
  <em>📸 Figure-20: Screenshot of setting AD DC VM Private IP as DNS</em>
  </p>

- System Properties → Computer Name → Change → Member of Domain `mydfir.local`
  <p align="center">
  <img src="assets/screenshots/21.Test Machine Domain Joined.png"Network Diagram" width="700"/><br>
  <em>📸 Figure-21: Screenshot of joining Test Machine to the AD Domain</em>
  </p>

- Restart and test authentication: `mydfir\JSmith` (or `JSmith@mydfir.local`)

  <p align="center">
  <img src="assets/screenshots/22.Testing Authentication.png"Network Diagram" width="700"/><br>
  <em>📸 Figure-22: Screenshot of authenticating to AD DC via Jenny Smith's Credentials</em>
  </p>
  <p align="center">
  <img src="assets/screenshots/23.Authentication Successful.png"Network Diagram" width="700"/><br>
  <em>📸 Figure-23: Screenshot of Successful Authentication</em>
  </p>

**Grant JSmith Remote Desktop permission**:

- System Properties → Remote → Select Users → Add `mydfir\JSmith`
  <p align="center">
  <img src="assets/screenshots/24.RDP Allow to Test Machine.png"Network Diagram" width="700"/><br>
  <em>📸 Figure-24: Screenshot of Allowing RDP to Test Machine</em>
  </p>

Again Verify successful domain join & logins.

## 🖥️ Part 4 — Splunk Installation & Telemetry Ingestion

### 1) Splunk Enterprise on Ubuntu (install & start)

**Update Linux host**:

```bash
sudo apt-get update && sudo apt-get upgrade -y
```

**Download Splunk Enterprise** for Linux from [Splunk.com](https://www.splunk.com/en_us/download/splunk-enterprise.html) on your Windows host machine.

- Example file: `splunk-10.0.0-e8eb0c4654f8-linux-amd64.deb`

**Prepare the VM**:

- SSH into your Ubuntu Splunk server and create a directory for the installation file:

```bash
  mkdir ~/share
```

**Transfer the .deb file to the VM**:

- From your Windows host (PowerShell/CMD):

```bash
  scp splunk-10.0.0-e8eb0c4654f8-linux-amd64.deb shaurya@PUBLIC-IP:/home/shaurya/share
```
  
  Replace `shaurya` with your username and `PUBLIC-IP` with your Splunk server's public IP.

**Install Splunk**:

- Inside the VM, navigate to the shared directory and install:

```bash
  cd ~/share
  sudo dpkg -i splunk-10.0.0-e8eb0c4654f8-linux-amd64.deb
```

- Splunk is now installed under `/opt/splunk`

**Start Splunk and accept license**:

```bash
cd /opt/splunk/bin
sudo ./splunk start --accept-license
```

- On first start, Splunk prompts you to create an admin username and password 
- Splunk Web listens on port 8000

**Enable auto-start on boot** (optional but recommended):

```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

**Access Splunk Web**:

- Open your browser and navigate to: `http://PUBLIC-IP:8000` (replace with your Splunk server's public IP)
- Ensure port 8000 is allowed in both your cloud firewall and Ubuntu UFW:

```bash
  sudo ufw allow 8000
```

**Login** with the admin credentials you created during the first start.

  <p align="center">
  <img src="assets/screenshots/25.Splunk Login Success.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-25: Screenshot of Splunk Web Interface</em>
  </p>
  <p align="center">
  <img src="assets/screenshots/26.Splunk Login Success-2.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-26: Screenshot of Successful Login to Splunk Web Interface</em>
  </p>

### 2) Splunk: Apps, Index & Receiver

In Splunk Web:

- **Preferences** → set timezone (GMT recommended)
- **Apps** → Find more apps → install **Splunk Add-on for Microsoft Windows**
- **Settings → Indexes** → Create index: `ad_2_0`
- **Settings → Forwarding and receiving** → Configure receiving → New receiving port **9997** (default indexer ingestion port)

Ensure Splunk host firewall allows 9997:

```bash
sudo ufw allow 9997
```

### 3) Splunk Universal Forwarder (Windows) — install + inputs

Download **Splunk Universal Forwarder** (Windows x64) from Splunk site.

**Install on Test-Machine and ADDC01** (run installer as admin). Choose:

- On-premise install
- Enter Splunk indexer private IP (e.g., `10.6.96.5`) and port **9997** in the **Receiving Indexer** prompt during installation
- Provide admin credentials during install

**Configure inputs.conf** on each forwarder (copy default -> `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`) and append:

```ini
[WinEventLog://Security]
index = ad_2_0
disabled = false
```

(Repeat for Application, System, Microsoft-Windows-Sysmon/Operational, etc., as needed.)

Restart **SplunkForwarder** service inside **Services.msc** but before that change **Log On** to **Local System account**.

  <p align="center">
  <img src="assets/screenshots/27.inputs.conf-edit.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-27: Screenshot of inputs.conf</em>
  </p>

### 4) Verify telemetry in Splunk

On Splunk Web: **Search app** → `ad_2_0` → run search → confirm host fields show both `AD-DC01` and `vulture-guest` (test machine).

  <p align="center">
  <img src="assets/screenshots/28.telemetry from both-hosts.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-28: Screenshot of Telemetry from both hosts</em>
  </p>

### 5) Create Detection Alert: Unauthorized Successful Logins

**Target**: Windows Event ID 4624 (successful logon). RDP may produce logon types 7 or 10.

**Example search** (conceptual; adapt to your Splunk field names):

```spl
index="ad_2_0" EventCode=4624 (Logon_Type=7 OR Logon_Type=10) Source_Network_Address=* Source_Network_Address !="-" Source_Network_Address!=99.* user != Administrator
| stats count by _time, ComputerName, Source_Network_Address, user, Logon_Type
```

**Notes**:

- `Source_Network_Address` (or source field as parsed by Windows add-on) contains the client IP for network logons.
- Replace `99.*` with your corporate/authorized IP prefix — the query excludes known good IPs.

**Save search** → Save as Alert:

- **Title**: `Unauthorized RDP Logins`
- **Type**: Scheduled (for testing, run every minute; production choose suitable cadence)
- **Time range**: look back 24 hours
- **Trigger condition**: Number of Results > 0 (or > 0), severity = Medium
- **Action**: Add to Triggered Alerts and Webhook (we'll attach Shuffle webhook later)

**Test**:

- Loosen firewall RDP rule to allow external RDP; simulate an RDP login from a VPN or other IP (or intentionally change password to reproduce successful login from outside).
- Confirm Splunk triggers alert (Activity → Triggered Alerts).

  <p align="center">
  <img src="assets/screenshots/29.Triggered-Alerts.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-29: Screenshot of Triggered Alert in Splunk</em>
  </p>

## 🧩 Part 5 — SOAR Automation with Shuffle + Slack

### 1) Shuffle: create workflow & webhook

- Signup for **Shuffle** (self-hosted or cloud offering).
- **Workflows** → Create workflow `AD-Project-2.0`.
- Add a **Webhook trigger** node: name `Splunk-alert`. Copy webhook URI.

### 2) Wire Splunk alert → Shuffle webhook

In Splunk Alert (Part 4), **Edit Alert** → Actions → Add Webhook → paste Shuffle webhook URI → Save. Re-enable alert.

  <p align="center">
  <img src="assets/screenshots/30.editing-alert.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-30: Screenshot of adding Trigger to Webhook in Splunk</em>
  </p>

### 3) Slack Integration (via Shuffle App)

**In Slack:**

1. Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps)
2. Add the **Bot Token Scopes**: `chat:write`, `chat:write.public`
3. Install the app to your workspace and copy the **Bot User OAuth Token** (starts with `xoxb-`)
4. Create a channel named `#alerts` (or any name you prefer)
5. Get the **Channel ID** by:
   - Opening the channel in Slack
   - Copying the ID from the browser URL (e.g., `C09JBNYKC3S`)

  <p align="center">
  <img src="assets/screenshots/31.slack-shuffle.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-31: Screenshot of App created in Slack</em>
  </p>

**In Shuffle:**

- Add the **HTTP app** to your workflow (as shown in the configuration)
- Configure the POST action with the following details:
  - **URL:** `https://slack.com/api/chat.postMessage`
  - **Headers:**

```json
    {
      "Authorization": "Bearer YOUR_SLACK_BOT_TOKEN",
      "Content-Type": "application/json"
    }
```

- **Body:**

```json
    {
      "channel": "YOUR_CHANNEL_ID",
      "username": "Shuffle-Splunk-Alerts",
      "icon_emoji": ":rotating_light:",
      "text": "🚨 Splunk Alert 🚨\nAlert: $exec.search_name\nTime: $exec.result._time\nUser: $exec.result.user\nSource IP: $exec.result.Source_Network_Address"
    }
```

- Replace `YOUR_SLACK_BOT_TOKEN` and `YOUR_CHANNEL_ID` with your actual values from the steps above

<p align="center">
<img src="assets/screenshots/32.slack-shuffle-1.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-32: Screenshot of Alerts received in Slack</em>
</p>

---

**Note:** The configuration uses Shuffle's HTTP app to make POST requests to Slack's API, allowing dynamic alert content from Splunk to be formatted and sent to your designated Slack channel.

### 4) User Action Configuration (with Email Notification Subflow)

The User Action node allows SOC analysts to approve or deny blocking requests through an interactive prompt. This setup uses a **subflow** to send email notifications as part of the decision workflow.

**Main Workflow - User Action Setup:**

1. **Add User Action node** to your workflow
2. Configure the following settings:
   - **Name:** `User_Action`
   - **Information field:** `$exec` (displays alert context to the user)
   - **Input options:**
     - ☑️ **Subflow** (checked)
     - ☐ Email (unchecked)
     - ☐ SMS (unchecked)
   - **Find the workflow you want to trigger:** Select `AD-Project-2.0.1` (your subflow)

  <p align="center">
  <img src="assets/screenshots/33.user-input-mainflow.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-33: Screenshot of User Action Configuration in the Main Flow</em>
  </p>

**Subflow Configuration (AD-Project-2.0.1):**

This subflow handles the email notification when the User Action is triggered.

1. **Add Email app** to the subflow
2. Configure the **Send email shuffle** action:
   - **Name:** `email_notification`
   - **Action:** `Send email shuffle`
   - **Recipients:** `jain.shaurya96@gmail.com` (or your SOC team email)
   - **Subject:** `Suspicious Alert`
   - **Body:**

```yaml
     🚨 Splunk Alert 🚨  
     Unauthorized RDP login from IP:$exec.information.result.Source_Network_Address
     User:$exec.information.result.user
     On Host:$exec.information.result.ComputerName

     To APPROVE this REQUEST and BLOCK the user $exec.api_continue
     To DENY this request $exec.api_abort
```

  <p align="center">
  <img src="assets/screenshots/34.user-input-subflow.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-34: Screenshot of Sub-Flow Configuration</em>
  </p>

**Workflow Explanation:**

1. Splunk alert triggers the main workflow
2. Slack notification is sent
3. User Action node is reached, which triggers the subflow
4. Subflow sends an email notification to the SOC analyst
5. Analyst can approve (continue) or deny (abort) the action via the provided links
6. Based on the decision, the workflow proceeds to the Active Directory action or terminates

**Note:** The `$exec.api_continue` and `$exec.api_abort` variables automatically generate clickable links in the email that allow the analyst to approve or deny the request directly from their inbox.

  <p align="center">
  <img src="assets/screenshots/35.email.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-35: Screenshot of Email Received in SOC Analyst Mail</em>
  </p>

### 5) Active Directory Integration in Shuffle (LDAP)

The Active Directory integration in Shuffle requires careful configuration of LDAP authentication to enable automated user management actions like disabling accounts.

**Prerequisites:**

- Active Directory server accessible from Shuffle (public IP or VPN connection)
- Domain Administrator account or service account with appropriate privileges
- Confirmed Base DN structure from your AD environment

**Authentication Setup (Critical Step):**

⚠️ **Important:** The AD authentication MUST be configured through Shuffle's centralized authentication system, not directly in the workflow node.

1. Navigate to **Admin > App Auth > Add App Auth** in Shuffle
2. Select **Active Directory** from the application list
3. Configure the authentication with the following parameters:

   - **Server:** `PUBLIC-IP` (your domain controller's IP address)
   - **Port:** `389` (standard LDAP port; use 636 for LDAPS if SSL is configured)
   - **Domain:** `MyDFIR`
   - **Login user:** `sjain` (must be a Domain Admin account)
   - **Password:** `YOUR_PASSWORD` (store securely)
   - **Base DN:** `CN=Users,DC=MyDFIR,DC=local`
   - **Use SSL:** `false` (set to true if using port 636)

4. Click **Submit** to save the authentication
5. **Test the connection** - you should see authentication success

**Important Notes:**

- The user account (`sjain`) must have **Domain Admin privileges** to perform user management operations
- If you encounter "Invalid Credentials" errors, verify:
  - The account has proper AD permissions
  - The Base DN is correct (confirm with `Get-ADDomain` or `Get-ADRootDSE` in PowerShell)
  - Port 389 (LDAP) is accessible from Shuffle to your DC
- **Common Issue:** Creating authentication directly in the workflow node may cause credential saving errors. Always use the centralized **Admin > App Auth** method.

  <p align="center">
  <img src="assets/screenshots/36.Domain Admin.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-36: Screenshot of Domain Admin in the AD Environment</em>
  </p>
  
  <p align="center">
  <img src="assets/screenshots/37.Get-ADDomain.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-37: Screenshot of Base DN</em>
  </p>
  
  <p align="center">
  <img src="assets/screenshots/38.shuffle-AD-authentication.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-38: Screenshot of Authenticating to AD via Domain Admin</em>
  </p>

**Using the Authentication in Workflows:**

Once the authentication is configured:

1. Add the **Active Directory** app to your workflow
2. In the node configuration:
   - **Name:** `Active_Directory_1`
   - **Authentication:** Select `AD Auth 7.0` (or your saved authentication name) marked as "Latest"
   - **Action:** `Disable user`
   - **Samaccountname:** `$exec.result.user` (dynamically pulls username from Splunk alert)
   - **Search base:** `CN=Users,DC=MyDFIR,DC=local`
   - **Delay:** `5` seconds (optional, allows time for user decision)

3. Test the integration by triggering the workflow

**Troubleshooting Tips:**

- If authentication fails initially, try creating it via **Admin > App Auth** rather than inline
- Verify the DC is accessible: `Test-NetConnection <DC_IP> -Port 389`
- Ensure Windows Firewall allows LDAP traffic (port 389/636)
- For lab environments, LDAP (389) with `use_ssl=false` is acceptable; production should use LDAPS (636)

**Security Considerations:**

- Store credentials securely in Shuffle's authentication vault
- Consider using a dedicated service account instead of the Administrator account
- Enable LDAPS (port 636) with SSL certificates for production environments
- Rotate passwords regularly and update authentication settings accordingly

### 6) Playbook flow (detailed)

**Flow nodes**:

1. **Webhook (Splunk)** — Splunk alert hits Shuffle
2. **Slack post** — send alert text to `#alerts` (human-readable summary)
3. **User Input (email)** — send analyst email with decision prompt
4. **Condition node** — if analyst == Yes:
   - **Active Directory: Disable User** (action: `disable_user` with username runtime arg)
   - **Active Directory: Get User Attributes** (confirm attribute account disabled)
   - **Slack update** — post confirmation: `Account <username> has been disabled.`
   - else (if No): Do nothing (or log decision)

  <p align="center">
  <img src="assets/screenshots/39.main-flow.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-39: Screenshot of the Main Flow</em>
  </p>
  
  <p align="center">
  <img src="assets/screenshots/40.End-result.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-40: Screenshot of End Result</em>
  </p>
  
  <p align="center">
  <img src="assets/screenshots/41.slack-shuffle-1.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-41: Screenshot of Message on Slack once the User is Disabled</em>
  </p>

**Notes & implementation details**:

- Use runtime arguments from Splunk webhook payload for username and source IP.
- After AD disable action, call `get_user_attributes` to validate `userAccountControl` or property account disabled.
- When confirmed disabled, post success message to Slack and optionally archive the Splunk alert.

## ⚠️ Troubleshooting Log (issues encountered & resolutions)

### VMs show 169.x.x.x or unreachable private IP

- **Cause**: VPC interface not configured to static/private address, or VM unable to obtain private IP from VPC DHCP.
- **Context**: In VPC setup, each VM has both public IP (external access) and private IP (internal VM-to-VM communication within VPC). VMs communicate internally using private IPs (e.g., Splunk at `10.6.96.5` pulls logs from DC at `10.6.96.4`). This keeps traffic inside VPC—faster, more secure, no internet routing.
- **Fix**: Verify VPC is enabled on the instance in cloud provider dashboard. Check Windows NIC settings with `ipconfig` - should show private IP from VPC subnet (e.g., `10.6.96.4`). If private IP is missing or incorrect, restart the network adapter or reboot VM to obtain IP from VPC DHCP. Test internal connectivity with `ping` to other VM private IPs (e.g., `ping 10.6.96.3`).

### Domain join failure ("domain does not exist or cannot be contacted")

- **Cause**: DNS on test machine not pointing to DC.
- **Fix**: Set DC private IP as primary DNS on test machine, retry join.

### Splunk Web not reachable

- **Cause**: Splunk service was stopped, or web interface bound only to `127.0.0.1` (localhost) instead of `0.0.0.0` (all interfaces), or port 8000 blocked in Vultr firewall/Ubuntu UFW.
- **Fix**:
  1. Check if Splunk is running: `sudo /opt/splunk/bin/splunk status`
  2. If stopped, restart: `sudo /opt/splunk/bin/splunk restart`
  3. Edit `/opt/splunk/etc/system/local/web.conf` to bind to all interfaces:

        ```yaml
            [settings]
            httpport = 8000
            server.socket_host = 0.0.0.0
        ```

  4. Restart Splunk: `sudo /opt/splunk/bin/splunk restart`
  5. Verify listening on all interfaces: `ss -tulnp | grep 8000` (should show `0.0.0.0:8000`)
  6. Add TCP 8000 rule in Vultr firewall for your IP
  7. Allow port on Ubuntu: `sudo ufw allow 8000` (or `sudo ufw allow from YOUR_IP to any port 8000 proto tcp` for IP-specific access)

### No telemetry in Splunk

- **Cause**: Forwarder inputs.conf missing or Splunk indexer port 9997 blocked.
- **Fix**: Create inputs.conf with `WinEventLog://Security` stanza (`index = ad_2_0`), restart Splunk UF service, open 9997.

### Shuffle Slack app shows authentication error or fails to post

- **Cause**: Attempting to use Shuffle's native Slack app with OAuth, but authentication or channel configuration failed. The native Slack app in Shuffle may have issues with OAuth token persistence or workspace permissions.

- **Fix**: Use **HTTP app** instead to make direct POST requests to Slack API, giving you full control over authentication:

  **Step 1: Create Slack Bot and Get Authentication Token**
  1. Go to [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App**
  2. Choose **From scratch**, name it (e.g., "Shuffle-Splunk-Alerts"), and select your workspace
  3. Navigate to **OAuth & Permissions** in the left sidebar
  4. Scroll to **Scopes** → **Bot Token Scopes** and add:
     - `chat:write` (allows bot to post messages)
     - `chat:write.public` (allows bot to post to public channels without being invited)
  5. Scroll up and click **Install to Workspace** → **Allow**
  6. Copy the **Bot User OAuth Token** (starts with `xoxb-`) - this is your authentication credential
  
  **Step 2: Get Slack Channel ID**
  1. In Slack, create a channel named `#alerts` (or any name)
  2. Open the channel, right-click on the channel name → **View channel details**
  3. Scroll down to find the **Channel ID** (e.g., `C09JBNYKC3S`), or copy it from the browser URL
  
  **Step 3: Configure HTTP App in Shuffle**
  1. Add **HTTP app** to your workflow
  2. Select **POST** action
  3. Configure:
     - **URL:** `https://slack.com/api/chat.postMessage`
     - **Headers:**

        ```json
                {
                    "Authorization": "Bearer xoxb-YOUR-BOT-TOKEN-HERE",
                    "Content-Type": "application/json"
                }
            ```

       ⚠️ Replace `xoxb-YOUR-BOT-TOKEN-HERE` with your actual token from Step 1
     
     - **Body:**

        ```json
                {
                    "channel": "C09JBNYKC3S",
                    "username": "Shuffle-Splunk-Alerts",
                    "icon_emoji": ":rotating_light:",
                    "text": "🚨 Splunk Alert 🚨\nAlert: $exec.search_name\nTime: $exec.result._time\nUser: $exec.result.user\nSource IP: $exec.result.Source_Network_Address"
                }

        ```

       ⚠️ Replace `C09JBNYKC3S` with your actual Channel ID from Step 2
  
  **Step 4: Test**
  - Run the workflow in Shuffle
  - Check if message appears in your Slack `#alerts` channel
  - If you get "channel_not_found" error, verify the Channel ID is correct
  - If you get "invalid_auth" error, verify the Bot Token is correct and has proper scopes

- **Why this works better than native Slack app:**
  - Direct API calls give you full control over authentication
  - No dependency on Shuffle's OAuth implementation
  - Bot token is stored directly in your workflow (visible only to workflow editors)
  - Easier to troubleshoot and debug API responses

### User Action node shows "WAITING" state with empty email loops and workflow not proceeding after clicking Yes/No

- **Cause**: Incorrect User Action configuration and misunderstanding of the subflow approach:
  1. **Subflow email configuration working correctly**: Using a subflow (AD-Project-2.0.1) to send email notifications is actually the correct approach and works as intended
  2. **Correct variables in subflow**: In the subflow email body, use `$exec.api_continue` and `$exec.api_abort` (not `$User_Action.links.api_continue`) because within a subflow, `$exec` refers to the execution context passed from the parent workflow's User Action node
  3. **Information field in User Action**: Set to `$exec` to pass the entire webhook payload (Splunk alert data) to the subflow, making it accessible as `$exec.information.result.user`, `$exec.information.result.Source_Network_Address`, etc.

- **Correct Configuration (as shown in screenshots)**:

  **Main Workflow - User Action Node (Screenshot 1):**
  - **Name:** `User_Action`
  - **Information field:** `$exec` (passes webhook data to subflow)
  - **Input options:**
    - ☑️ **Subflow** (checked)
    - ☐ Email (unchecked)
    - ☐ SMS (unchecked)
  - **Find the workflow you want to trigger:** `AD-Project-2.0.1`
  - **Required Input-Questions:**
    - ☐ `disable_user` (checkbox, can be left unchecked in this configuration)

  **Subflow Configuration - AD-Project-2.0.1 (Screenshots 2 & 3):**
  - **Email node name:** `email_notification`
  - **Action:** `Send email shuffle`
  - **Recipients:** `jain.shaurya96@gmail.com`
  - **Subject:** `Suspicious Alert`
  - **Body (Screenshot 3 shows correct format):**

```yaml
    🚨 Splunk Alert 🚨
    Unauthorized RDP login from IP:$exec.information.result.Source_Network_Address
    User:$exec.information.result.user
    On Host:$exec.information.result.ComputerName

    To APPROVE this REQUEST and BLOCK the user $exec.api_continue
    To DENY this request $exec.api_abort
```

- **How it works**:
  1. Main workflow reaches User Action node and enters WAITING state
  2. User Action triggers the subflow (AD-Project-2.0.1) and passes `$exec` data
  3. Subflow's email node sends formatted email with alert details
  4. Email includes clickable links: `$exec.api_continue` (Yes) and `$exec.api_abort` (No)
  5. When analyst clicks a link, the main workflow resumes from the User Action node
  6. The workflow then proceeds to the next connected node (e.g., Active Directory disable action)

- **Key points**:
  - Within a **subflow**, use `$exec.api_continue` and `$exec.api_abort` to reference the parent workflow's decision links
  - Within the **main workflow**, you would use `$User_Action.links.api_continue` to reference the User Action node's links
  - The subflow approach is cleaner because it separates notification logic from decision logic
  - Screenshot 3 shows the correct output with properly formatted links that include full workflow execution URLs

- **Result**: Analyst receives ONE properly formatted email with alert context and two functional decision links that resume the workflow appropriately.

### Shuffle Active Directory integration - "Invalid Credentials" error

- **Cause**: Authentication created directly in workflow node instead of centralized App Auth system, causing Shuffle to not properly save/bind LDAP credentials. On Domain Controllers, `net user` command only modifies local SAM (non-existent on DCs), not the domain Administrator account stored in Active Directory.
- **Fix**:
  1. Navigate to **Admin > App Auth > Add App Auth** in Shuffle (not in workflow node)
  2. Select Active Directory and configure:
     - Server: DC IP (e.g., `155.138.208.227`)
     - Port: `389` (LDAP) or `636` (LDAPS)
     - Domain: `MyDFIR`
     - Login user: `sjain` (must have Domain Admin privileges)
     - Password: Store securely
     - Base DN: `CN=Users,DC=MyDFIR,DC=local`
     - Use SSL: `false` for lab (port 389)
  3. Test authentication - should show success
  4. In workflow, select the saved authentication (e.g., "AD Auth 7.0") from dropdown
  5. Verify DC is accessible: `Test-NetConnection <DC_IP> -Port 389`

### RDP access lost to Domain Controller after password reset attempt

- **Cause**: Used `net user Administrator "newpassword"` command which only affects local SAM accounts (non-existent on Domain Controllers). Domain Controllers authenticate only against Active Directory database, not local accounts. The command completed without error but didn't update the domain Administrator password in AD, causing RDP lockout with both old and new passwords failing.
- **Fix**:
  1. **If you have console access (Vultr):** Open VM console, login if possible, open Active Directory Users and Computers (`dsa.msc`), navigate to Users OU, right-click Administrator → Reset Password, set new password, uncheck "User must change password at next logon", check "Unlock account"
  2. **From another domain-joined machine (preferred):** Login as a Domain Admin account (e.g., `sjain`), verify Domain Admin membership with `whoami /groups | findstr /i "domain admins"`, open ADUC (`dsa.msc`), reset Administrator password via GUI, or use PowerShell:

     ```powershell
         Import-Module ActiveDirectory
         Set-ADAccountPassword -Identity "Administrator" -Reset -NewPassword (ConvertTo-SecureString '4c|KBmBfVGyf*g2D' -AsPlainText -Force)
         Unlock-ADAccount -Identity "Administrator"
     ```

  3. Test RDP with `MYDFIR\Administrator` and new password
  4. **Key distinction:** Local Administrator (exists only on workstations/member servers, managed via `net user`) vs Domain Administrator (exists in AD, managed via ADUC/AD cmdlets). DCs only authenticate domain accounts.

## 🔑 Key Learning Outcomes (concise)

- Build and secure cloud VMs and VPCs for lab use.
- Install and configure Active Directory, join machines, manage users.
- Install Splunk Enterprise and Splunk Universal Forwarder; parse Windows event logs.
- Author Splunk searches for Windows logon events (Event ID 4624) and create scheduled alerts.
- Build SOAR playbook in Shuffle: receive webhook, notify Slack/email, request analyst action, perform LDAP/AD remediation (disable user) and verify result.
- Practical trouble-shooting experience for real-world SOC operations.

## 🔗 References & Resources

- [YouTube Series Part 1](https://www.youtube.com/watch?v=1nX6_Nlly-4&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=61) – Creating a Logical Diagram
- [YouTube Series Part 2](https://www.youtube.com/watch?v=dUdj-OmrFi0&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=62) – Deploying and network three Vultr virtual machines—Domain Controller, Test Machine, and Splunk Server
- [YouTube Series Part 3](https://youtu.be/ZWt1_5DPBXE?si=NVdB4I9ULq9CIjRK) – Installed and configured Active Directory on a Windows Server, promote it to a Domain Controller, create a test user, and join a Windows client machine to the new domain for authentication and remote access.
- [YouTube Series Part 4](https://www.youtube.com/watch?v=czfuSdNuDak&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=64) - Installed and configured Splunk on an Ubuntu server, set up Universal Forwarders on Windows machines to send telemetry, and create a Splunk alert to detect unauthorized successful RDP logins.
- [YouTube Series Part 5](https://www.youtube.com/watch?v=mkx5e_UzpvI&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=65) - Integrated Slack and Shuffle SOAR to automate incident response. The workflow sends Slack alerts from Splunk, emails SOC analysts for confirmation, and automatically disables compromised AD accounts via LDAP when unauthorized logins are detected.
