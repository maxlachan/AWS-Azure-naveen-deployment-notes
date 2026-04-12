# 🛡️ AWS Secure Golden AMI — Hardening & Build Pipeline Guide

> **Complete Step-by-Step Execution Guide with Explanation & Commands**  
> Version 1.0 | Security Engineering Reference

---

## 📋 Table of Contents

1. [Overview & Introduction](#1-overview--introduction)
2. [Prerequisites & Architecture Setup](#2-prerequisites--architecture-setup)
3. [Step-by-Step Hardening Execution](#3-step-by-step-hardening-execution)
   - [Step 1: OS Hardening (CIS Benchmark)](#step-1-operating-system-hardening-cis-benchmark)
   - [Step 2: User Account & Authentication Hardening](#step-2-user-account--authentication-hardening)
   - [Step 3: Audit Logging & Monitoring](#step-3-audit-logging--monitoring-setup)
   - [Step 4: Host-Based Firewall](#step-4-host-based-firewall-iptables--nftables)
   - [Step 5: File Integrity Monitoring (AIDE)](#step-5-file-integrity-monitoring-aide)
   - [Step 6: Secrets Management](#step-6-secrets-management--remove-all-hardcoded-credentials)
   - [Step 7: EBS Encryption](#step-7-ebs-encryption)
   - [Step 8: Vulnerability Scanning](#step-8-vulnerability-scanning)
4. [Automated Golden AMI Pipeline](#4-automated-golden-ami-pipeline)
5. [Compliance Validation & Testing](#5-compliance-validation--testing)
6. [AMI Lifecycle Management](#6-ami-lifecycle-management)
7. [Pre-Promotion Checklist](#7-pre-promotion-checklist)
8. [Useful AWS CLI Commands Reference](#8-useful-aws-cli-commands-reference)
9. [References & Further Reading](#9-references--further-reading)

---

## 1. Overview & Introduction

A **Golden AMI** (Amazon Machine Image) is a hardened, pre-approved, and standardized base image used across an organization's AWS infrastructure. **Hardening** is the process of reducing the attack surface by:

- Disabling unnecessary services
- Applying security configurations
- Enforcing compliance baselines
- Embedding security tooling into the image **before** it is ever deployed

This guide covers the complete lifecycle of creating a Secure Golden AMI — from initial OS configuration and CIS benchmark compliance through patch management, access control, logging, vulnerability scanning, and automated pipeline delivery using EC2 Image Builder or HashiCorp Packer.

### Why Golden AMIs Matter

| Benefit | Description |
|---|---|
| **Consistent Security Baseline** | Every EC2 instance starts from a known-good, hardened state |
| **No Configuration Drift** | Eliminates security variance between Dev, Staging, and Production |
| **Faster Incident Response** | Known-good state can be redeployed in minutes |
| **Compliance Ready** | Supports CIS, NIST, PCI-DSS, HIPAA, SOC2 out of the box |
| **Reduced Vulnerability Window** | Patches baked in at build time, not applied post-launch |
| **DevSecOps Enablement** | Automated pipelines with compliance gating before deployment |

### Hardening Pillars

| Pillar | Description | Key Standard |
|---|---|---|
| OS Hardening | Disable unused services, secure kernel params, file permissions | CIS Benchmarks |
| Access Control | Least privilege, SSH key-only auth, MFA enforcement | NIST 800-53 AC |
| Network Security | Host firewall, kernel network hardening, no open ports | CIS Level 2 |
| Audit & Logging | auditd, syslog forwarding, CloudWatch Logs agent | NIST 800-92 |
| Patch Management | Current OS patches, automatic security updates config | NIST 800-40 |
| Encryption | EBS at-rest encryption, in-transit TLS, no plaintext secrets | FIPS 140-2 |
| Secrets Management | No credentials baked in, IAM roles, SSM Parameter Store | CIS Control 14 |
| Endpoint Security | EDR/AV agent, host IDS, file integrity monitoring | CIS Control 10 |

---

## 2. Prerequisites & Architecture Setup

### 2.1 AWS Account Prerequisites

- AWS Account with Administrator or sufficient IAM permissions
- VPC with a **private subnet** for AMI build instances
- S3 bucket for storing build artifacts and logs
- KMS key for EBS encryption (customer-managed recommended)
- EC2 Image Builder pipeline (or Packer with IAM role)
- AWS Systems Manager (SSM) access enabled

### 2.2 Required IAM Permissions

Create a dedicated IAM role for the build process:

```bash
# Create the AMI Builder IAM Role
aws iam create-role \
  --role-name GoldenAMIBuilderRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]}'

# Attach required managed policies
aws iam attach-role-policy --role-name GoldenAMIBuilderRole \
  --policy-arn arn:aws:iam::aws:policy/EC2InstanceProfileForImageBuilder

aws iam attach-role-policy --role-name GoldenAMIBuilderRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

aws iam attach-role-policy --role-name GoldenAMIBuilderRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
```

> ⚠️ **Best Practice:** Always use the principle of least privilege. The build role should only have permissions necessary to build the AMI — never production-level access.

---

## 3. Step-by-Step Hardening Execution

> All commands below target **Amazon Linux 2 / RHEL / CentOS**.  
> For Ubuntu/Debian replace `yum` with `apt-get` and adjust package names accordingly.

---

### Step 1: Operating System Hardening (CIS Benchmark)

#### 1.1 — Apply All OS Security Patches First

> Always start with a **fully patched base OS** before applying hardening configs.

```bash
#!/bin/bash

# Update all packages to latest security patches
sudo yum update -y --security
sudo yum upgrade -y

# For Ubuntu/Debian:
# sudo apt-get update && sudo apt-get upgrade -y
# sudo unattended-upgrade -d
```

#### 1.2 — Remove Unnecessary Packages & Services

Reducing installed software directly reduces the attack surface:

```bash
# Remove legacy and dangerous packages
sudo yum remove -y \
  telnet rsh ypbind ypserv tftp tftp-server \
  talk talk-server chargen-dgram chargen-stream \
  daytime-dgram daytime-stream echo-dgram echo-stream tcpmux-server

# Disable and stop unused services
for svc in avahi-daemon cups nfs rpcbind bluetooth; do
  sudo systemctl disable $svc 2>/dev/null
  sudo systemctl stop $svc 2>/dev/null
done
```

#### 1.3 — Kernel Parameter Hardening (sysctl)

Linux kernel parameters control low-level networking and memory security behaviors:

```bash
# Create a hardening sysctl config file
cat <<'EOF' | sudo tee /etc/sysctl.d/99-hardening.conf

# ── Network Protection ──────────────────────────────────────────
# IP Spoofing Protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Enable TCP SYN Cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Disable IPv6 if not used in your environment
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# ── Memory Protection ────────────────────────────────────────────
# Prevent core dumps from SUID binaries
fs.suid_dumpable = 0

# ASLR - Address Space Layout Randomization (full randomization)
kernel.randomize_va_space = 2

# ── Kernel Hardening ─────────────────────────────────────────────
# Restrict kernel pointer exposure in /proc
kernel.kptr_restrict = 2

# Restrict access to kernel logs
kernel.dmesg_restrict = 1
EOF

# Apply all changes immediately
sudo sysctl --system
```

**Why each setting matters:**

| Parameter | Purpose |
|---|---|
| `rp_filter = 1` | Drops packets that don't use a valid return path (anti-spoofing) |
| `accept_source_route = 0` | Prevents attackers from specifying their own routing path |
| `tcp_syncookies = 1` | Defends against SYN flood DoS attacks |
| `randomize_va_space = 2` | Makes memory exploits like buffer overflows significantly harder |
| `kptr_restrict = 2` | Hides kernel addresses from unprivileged users |
| `suid_dumpable = 0` | Prevents sensitive data leaking via core dumps |

#### 1.4 — Filesystem Hardening

```bash
# Mount /tmp with security flags — noexec prevents script execution in /tmp
echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0' | sudo tee -a /etc/fstab
echo 'tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0' | sudo tee -a /etc/fstab

# Disable uncommon/legacy filesystems to reduce kernel attack surface
cat <<'EOF' | sudo tee /etc/modprobe.d/disable-filesystems.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install fat /bin/true
install vfat /bin/true
EOF
```

---

### Step 2: User Account & Authentication Hardening

#### 2.1 — Password & Account Policies

```bash
# Set strong password aging policies in /etc/login.defs
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'  /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# Install and configure PAM password quality enforcement
sudo yum install -y libpwquality

cat <<'EOF' | sudo tee /etc/security/pwquality.conf
minlen = 14          # Minimum 14 characters
minclass = 4         # Must use all 4 character classes (upper, lower, digit, special)
maxrepeat = 3        # No more than 3 consecutive identical characters
maxsequence = 4      # No sequential characters (1234, abcd)
dictcheck = 1        # Check against dictionary words
EOF

# Account lockout — lock after 5 failed attempts for 15 minutes
cat <<'EOF' | sudo tee /etc/security/faillock.conf
deny = 5
unlock_time = 900
fail_interval = 900
EOF
```

#### 2.2 — SSH Hardening

SSH is the primary remote access vector. This is one of the most critical hardening steps:

```bash
# Backup original sshd config before modifying
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat <<'EOF' | sudo tee /etc/ssh/sshd_config
# ── Protocol & Port ──────────────────────────────────────────────
Protocol 2
Port 22

# ── Authentication ───────────────────────────────────────────────
PermitRootLogin no                    # Never allow root login over SSH
PasswordAuthentication no             # Keys only — no passwords
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# ── Cryptography — Strong algorithms only ────────────────────────
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256

# ── Connection Limits ────────────────────────────────────────────
LoginGraceTime 60
MaxAuthTries 4
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 3

# ── Disable Dangerous Features ───────────────────────────────────
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no

# ── Logging ──────────────────────────────────────────────────────
SyslogFacility AUTHPRIV
LogLevel VERBOSE
EOF

# Validate config syntax before restarting
sudo sshd -t && sudo systemctl restart sshd
```

> 💡 **Tip:** Use **AWS SSM Session Manager** as the primary access method. SSH can be blocked at the Security Group level entirely and only opened via SSM port forwarding when needed.

#### 2.3 — Remove Default/Unused System Accounts

```bash
# Lock legacy system accounts that don't need interactive shell access
for user in games ftp shutdown halt sync news uucp operator; do
  sudo usermod -L -s /sbin/nologin $user 2>/dev/null
done

# Lock root account password (force key-only or SSM access)
sudo passwd -l root
```

---

### Step 3: Audit Logging & Monitoring Setup

#### 3.1 — Configure auditd (Linux Audit Daemon)

`auditd` records security-relevant system events. **Mandatory for PCI-DSS, HIPAA, and SOC2 compliance.**

```bash
sudo yum install -y audit audit-libs

# Write CIS-aligned audit rules
cat <<'EOF' | sudo tee /etc/audit/rules.d/hardening.rules
# Remove existing rules and start clean
-D

# Buffer size — increase if audit events are being dropped
-b 8192

# Failure mode: 2 = kernel panic if audit fails (highest assurance)
-f 2

# ── Identity & Access ────────────────────────────────────────────
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity

# ── Privilege Escalation ─────────────────────────────────────────
-a always,exit -F arch=b64 -S setuid -S setgid -k setuid
-a always,exit -F arch=b64 -S execve -k exec

# ── File Deletion Events ─────────────────────────────────────────
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# ── Login Events ─────────────────────────────────────────────────
-w /var/log/lastlog    -p wa -k logins
-w /var/run/faillock   -p wa -k logins

# ── Sudo Usage ───────────────────────────────────────────────────
-w /var/log/sudo.log   -p wa -k sudo_log

# ── Kernel Module Loading ────────────────────────────────────────
-w /sbin/insmod        -p x  -k modules
-w /sbin/rmmod         -p x  -k modules

# ── Make audit config immutable (requires reboot to change) ──────
-e 2
EOF

sudo systemctl enable auditd
sudo systemctl start auditd
sudo augenrules --load
```

#### 3.2 — Install & Configure CloudWatch Agent

Forward logs to AWS CloudWatch Logs for centralized monitoring and long-term retention:

```bash
# Install the CloudWatch agent
sudo yum install -y amazon-cloudwatch-agent

# Write the agent configuration
cat <<'EOF' | sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/secure",
            "log_group_name": "/golden-ami/secure",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/audit/audit.log",
            "log_group_name": "/golden-ami/audit",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/messages",
            "log_group_name": "/golden-ami/messages",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/sudo.log",
            "log_group_name": "/golden-ami/sudo",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
EOF

sudo systemctl enable amazon-cloudwatch-agent
sudo amazon-cloudwatch-agent-ctl -a fetch-config \
  -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
```

---

### Step 4: Host-Based Firewall (iptables / nftables)

#### 4.1 — Configure iptables Default Deny Policy

```bash
# Install iptables services
sudo yum install -y iptables-services

# Flush all existing rules
sudo iptables -F
sudo iptables -X
sudo iptables -Z

# ── Set Default DROP Policies ────────────────────────────────────
# All inbound and forwarded traffic is denied by default
sudo iptables -P INPUT   DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT  ACCEPT

# ── Allow Established Connections ───────────────────────────────
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ── Allow Loopback ───────────────────────────────────────────────
sudo iptables -A INPUT -i lo -j ACCEPT

# ── Allow SSH (restrict further via Security Groups at VPC level) ─
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ── Allow Outbound HTTPS (SSM, patching, CloudWatch) ─────────────
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT

# Save rules so they persist across reboots
sudo service iptables save
sudo systemctl enable iptables
```

> 💡 These host-based firewall rules are a **defense-in-depth layer** alongside AWS Security Groups. Configure both independently — Security Groups are your first line, iptables is your second.

---

### Step 5: File Integrity Monitoring (AIDE)

AIDE (Advanced Intrusion Detection Environment) monitors the filesystem for unauthorized changes by creating a database of file checksums and attributes.

```bash
# Install AIDE
sudo yum install -y aide

# Write AIDE configuration
cat <<'EOF' | sudo tee /etc/aide.conf
# AIDE Configuration
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes

# Define attribute sets to monitor
ALLXTRAHASHES = sha256+sha512+whirlpool
NORMAL = p+i+u+g+s+m+c+sha256

# ── Monitor Critical System Directories ──────────────────────────
/boot          NORMAL
/bin           NORMAL
/sbin          NORMAL
/lib           NORMAL
/usr/bin       NORMAL
/usr/sbin      NORMAL
/etc           NORMAL

# ── Exclude Volatile Files ────────────────────────────────────────
!/etc/mtab
!/etc/aide.conf
EOF

# Initialize AIDE database — run ONCE at build time
sudo aide --init
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Schedule daily integrity check via cron
echo '0 5 * * * root /usr/sbin/aide --check | mail -s "AIDE Integrity Report $(hostname)" security@example.com' \
  | sudo tee /etc/cron.d/aide
```

---

### Step 6: Secrets Management — Remove All Hardcoded Credentials

> ❌ **A Golden AMI must NEVER contain hardcoded credentials, API keys, or passwords.**  
> All sensitive values must be fetched at **runtime** from AWS SSM Parameter Store or AWS Secrets Manager.

#### 6.1 — Scan and Clean Before Baking

```bash
# Install trufflehog to scan for leaked credentials
pip3 install trufflehog
trufflehog filesystem / --only-verified

# Remove any AWS credential files
rm -f /root/.aws/credentials
rm -f /home/*/.aws/credentials
rm -f /etc/*-credentials

# Remove SSH host keys — they will be auto-regenerated on first boot
sudo rm -f /etc/ssh/ssh_host_*

# Clear shell history
cat /dev/null > ~/.bash_history
history -c
```

#### 6.2 — Runtime Secrets Retrieval Pattern

Use this pattern in your application startup or userdata scripts:

```bash
#!/bin/bash
# Fetch secrets at runtime using the EC2 instance's IAM role
# No hardcoded credentials needed — the role provides access

# From SSM Parameter Store (SecureString)
DB_PASSWORD=$(aws ssm get-parameter \
  --name '/myapp/db/password' \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text)

# From Secrets Manager
SECRET=$(aws secretsmanager get-secret-value \
  --secret-id 'myapp/production/api-key' \
  --query 'SecretString' \
  --output text)
```

---

### Step 7: EBS Encryption

All EBS volumes associated with your Golden AMI must be **encrypted at rest**.

```bash
# Enable account-level EBS encryption by default (all new volumes encrypted automatically)
aws ec2 enable-ebs-encryption-by-default

# Verify it's enabled
aws ec2 get-ebs-encryption-by-default

# When creating the AMI, specify a KMS key explicitly
aws ec2 create-image \
  --instance-id i-0123456789abcdef0 \
  --name 'GoldenAMI-RHEL8-Hardened-v1.0' \
  --block-device-mappings '[{
    "DeviceName": "/dev/xvda",
    "Ebs": {
      "VolumeSize": 30,
      "VolumeType": "gp3",
      "Encrypted": true,
      "KmsKeyId": "arn:aws:kms:ap-south-1:123456789012:key/mrk-xxxx"
    }
  }]'
```

---

### Step 8: Vulnerability Scanning

Before promoting an AMI to production, it must **pass automated vulnerability scanning**.

#### 8.1 — Enable Amazon Inspector v2

```bash
# Enable Inspector v2 for EC2 scanning in your account
aws inspector2 enable --resource-types EC2
```

#### 8.2 — Using Trivy (Open-Source Scanner)

```bash
# Add Trivy repo and install
sudo rpm --import https://aquasecurity.github.io/trivy-repo/rpm/public.key

cat <<'EOF' | sudo tee /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
enabled=1
gpgcheck=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF

sudo yum install -y trivy

# Scan the running OS for known CVEs
trivy rootfs --severity HIGH,CRITICAL /

# For CI/CD pipeline gates — exit with error code if CRITICAL CVEs found
trivy rootfs --severity CRITICAL --exit-code 1 /
```

> 🚨 **Vulnerability Gate Rule:** Reject AMI promotion if any **CRITICAL** CVEs are found. Warn on **HIGH**. Document all exceptions with a security waiver and compensating controls.

---

## 4. Automated Golden AMI Pipeline

### 4.1 Pipeline Architecture

| Stage | Tool / Service | Purpose |
|---|---|---|
| **Source** | Git (CodeCommit / GitHub) | Version-controlled hardening scripts |
| **Build** | EC2 Image Builder | Apply hardening components, install agents |
| **Test** | Image Builder Test Component | Validate security configuration |
| **Scan** | Amazon Inspector / Trivy | CVE vulnerability scan with gate |
| **Approve** | CodePipeline Manual Gate | Human or auto-approval based on scan score |
| **Distribute** | Image Builder Distribution | Share AMI across accounts and regions |
| **Deprecate** | Lambda + EventBridge | Auto-deprecate AMIs older than 90 days |

### 4.2 Sample EC2 Image Builder Component (YAML)

```yaml
name: HardeningComponent
description: Apply CIS Level 2 hardening to the base AMI
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: ApplySysctl
        action: ExecuteBash
        inputs:
          commands:
            - |
              cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
              net.ipv4.tcp_syncookies = 1
              kernel.randomize_va_space = 2
              fs.suid_dumpable = 0
              kernel.kptr_restrict = 2
              EOF
              sysctl --system

      - name: HardenSSH
        action: ExecuteBash
        inputs:
          commands:
            - sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
            - sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
            - sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config

      - name: EnableAuditd
        action: ExecuteBash
        inputs:
          commands:
            - systemctl enable auditd
            - systemctl start auditd

  - name: validate
    steps:
      - name: ValidateSSH
        action: ExecuteBash
        inputs:
          commands:
            - grep -q 'PermitRootLogin no' /etc/ssh/sshd_config || exit 1
            - grep -q 'PasswordAuthentication no' /etc/ssh/sshd_config || exit 1

      - name: ValidateAuditd
        action: ExecuteBash
        inputs:
          commands:
            - systemctl is-active auditd || exit 1

      - name: ValidateSysctl
        action: ExecuteBash
        inputs:
          commands:
            - sysctl net.ipv4.tcp_syncookies | grep -q '= 1' || exit 1
            - sysctl kernel.randomize_va_space | grep -q '= 2' || exit 1
```

---

## 5. Compliance Validation & Testing

### 5.1 — Run OpenSCAP CIS Benchmark Scan

OpenSCAP is a NIST-certified compliance scanner that validates your AMI against CIS Benchmarks and STIG profiles:

```bash
# Install OpenSCAP and the SCAP Security Guide content
sudo yum install -y openscap-scanner scap-security-guide

# Run CIS Level 2 scan for Amazon Linux 2
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_server_l2 \
  --results /tmp/openscap-results.xml \
  --report  /tmp/openscap-report.html \
  /usr/share/xml/scap/ssg/content/ssg-amzn2-ds.xml

# Upload the HTML report to S3 for review
aws s3 cp /tmp/openscap-report.html \
  s3://your-compliance-bucket/reports/$(date +%Y-%m-%d)-openscap-report.html
```

> 🎯 **Target:** >= 90% CIS compliance score before AMI promotion. Document all accepted deviations with a security waiver and compensating controls.

### 5.2 — Automated Test Cases

Run these tests as part of your Image Builder validation phase:

| # | Test | Command | Expected Result |
|---|---|---|---|
| 1 | Root login disabled | `grep 'PermitRootLogin' /etc/ssh/sshd_config` | `PermitRootLogin no` |
| 2 | Password auth off | `grep 'PasswordAuthentication' /etc/ssh/sshd_config` | `PasswordAuthentication no` |
| 3 | auditd running | `systemctl is-active auditd` | `active` |
| 4 | No world-writable files | `find / -xdev -perm -0002 -type f` | No output |
| 5 | SYN cookies enabled | `sysctl net.ipv4.tcp_syncookies` | `= 1` |
| 6 | ASLR enabled | `sysctl kernel.randomize_va_space` | `= 2` |
| 7 | No .rhosts files | `find / -name '.rhosts' -type f` | No output |
| 8 | No empty passwords | `awk -F: '($2=="") {print}' /etc/shadow` | No output |
| 9 | EBS encrypted | `aws ec2 describe-volumes --query '...[?!Encrypted]'` | Empty list |
| 10 | No AWS credentials | `find / -name 'credentials' -path '*/.aws/*'` | No output |

---

## 6. AMI Lifecycle Management

### 6.1 — Naming & Tagging Convention

Consistent tagging is essential for governance, billing, and lifecycle automation:

| Tag Key | Example Value | Purpose |
|---|---|---|
| `Name` | `GoldenAMI-RHEL8-HardenedL2-v2.1.0` | Human-readable identifier |
| `Environment` | `golden` | Distinguish from application AMIs |
| `OS` | `RHEL8` | Operating system |
| `CISLevel` | `Level2` | Compliance level applied |
| `BuildDate` | `2025-04-12` | Build date for rotation tracking |
| `PatchLevel` | `2025-04-10` | OS patch level date |
| `OpenSCAPScore` | `94.2` | Compliance scan score |
| `ApprovedBy` | `security-team` | Approval authority |
| `ExpiryDate` | `2025-07-12` | 90-day rotation deadline |

```bash
# Apply required tags to the AMI
aws ec2 create-tags --resources ami-0123456789abcdef0 --tags \
  Key=Name,Value='GoldenAMI-RHEL8-HardenedL2-v2.1.0' \
  Key=Environment,Value='golden' \
  Key=CISLevel,Value='Level2' \
  Key=OpenSCAPScore,Value='94.2' \
  Key=ExpiryDate,Value='2025-07-12'
```

### 6.2 — AMI Rotation Policy

- Rebuild Golden AMIs every **30–90 days** to incorporate new OS patches
- **Auto-deprecate** AMIs older than the rotation window using Lambda + EventBridge
- Send **SNS notification** to consuming teams when a new Golden AMI is available
- Maintain minimum **2 prior Golden AMI versions** for rollback capability
- **Deregister** AMIs older than 6 months with no running instances

```bash
# Deprecate an old AMI (it remains usable but is flagged as end-of-life)
aws ec2 enable-image-deprecation \
  --image-id ami-0oldamiid \
  --deprecate-at '2025-07-12T00:00:00Z'
```

---

## 7. Pre-Promotion Checklist

Use this checklist before promoting any AMI to the Golden AMI catalog:

| # | Control | Category | Status |
|---|---|---|---|
| ☐ 1 | All OS security patches applied | Patch Management | Pass / Fail |
| ☐ 2 | Unnecessary services disabled | OS Hardening | Pass / Fail |
| ☐ 3 | sysctl kernel hardening applied | OS Hardening | Pass / Fail |
| ☐ 4 | SSH root login disabled | Access Control | Pass / Fail |
| ☐ 5 | SSH password auth disabled | Access Control | Pass / Fail |
| ☐ 6 | Strong SSH ciphers configured | Access Control | Pass / Fail |
| ☐ 7 | PAM password complexity enforced | Access Control | Pass / Fail |
| ☐ 8 | Account lockout policy configured | Access Control | Pass / Fail |
| ☐ 9 | auditd enabled and rules loaded | Audit Logging | Pass / Fail |
| ☐ 10 | CloudWatch agent configured | Audit Logging | Pass / Fail |
| ☐ 11 | iptables default-deny configured | Network Security | Pass / Fail |
| ☐ 12 | AIDE initialized and scheduled | Integrity | Pass / Fail |
| ☐ 13 | No hardcoded credentials present | Secrets | Pass / Fail |
| ☐ 14 | SSH host keys removed | Secrets | Pass / Fail |
| ☐ 15 | Bash history cleared | Secrets | Pass / Fail |
| ☐ 16 | EBS volumes encrypted (KMS) | Encryption | Pass / Fail |
| ☐ 17 | OpenSCAP CIS score >= 90% | Compliance | Pass / Fail |
| ☐ 18 | No CRITICAL CVEs from Trivy scan | Vulnerability | Pass / Fail |
| ☐ 19 | AMI tagged with required metadata | Governance | Pass / Fail |
| ☐ 20 | Expiry date tag set (90-day max) | Governance | Pass / Fail |

---

## 8. Useful AWS CLI Commands Reference

### AMI Management

```bash
# List your Golden AMIs with creation date
aws ec2 describe-images --owners self \
  --filters 'Name=tag:Environment,Values=golden' \
  --query 'Images[*].[ImageId,Name,CreationDate]' \
  --output table

# Share a Golden AMI with another AWS account
aws ec2 modify-image-attribute \
  --image-id ami-0123456789abcdef0 \
  --launch-permission 'Add=[{UserId=111122223333}]'

# Copy AMI to another region with encryption
aws ec2 copy-image \
  --source-image-id ami-0123456789abcdef0 \
  --source-region ap-south-1 \
  --region us-east-1 \
  --name 'GoldenAMI-RHEL8-Hardened-v2.1.0' \
  --encrypted \
  --kms-key-id alias/golden-ami-key

# Deregister an old AMI
aws ec2 deregister-image --image-id ami-0oldamiid

# Delete the associated EBS snapshot after deregistering
aws ec2 delete-snapshot --snapshot-id snap-0123456789abcdef0
```

### Inspector & Scanning

```bash
# List findings from Amazon Inspector for an EC2 instance
aws inspector2 list-findings \
  --filter-criteria '{"resourceId": [{"comparison": "EQUALS", "value": "i-0123456789abcdef0"}]}' \
  --query 'findings[*].[title,severity,status]' \
  --output table

# Get Inspector coverage summary
aws inspector2 list-coverage \
  --query 'coveredResources[*].[resourceId,resourceType,scanStatus.statusCode]' \
  --output table
```

### Systems Manager

```bash
# Start a session without SSH (using SSM Session Manager)
aws ssm start-session --target i-0123456789abcdef0

# Run a command on the instance via SSM (no SSH needed)
aws ssm send-command \
  --instance-ids i-0123456789abcdef0 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["sudo aide --check"]'
```

---

## 9. References & Further Reading

| Resource | URL |
|---|---|
| CIS Amazon Linux 2 Benchmark | https://www.cisecurity.org/benchmark/amazon_linux |
| AWS EC2 Image Builder Docs | https://docs.aws.amazon.com/imagebuilder |
| AWS Security Hub CIS Standards | https://docs.aws.amazon.com/securityhub |
| NIST SP 800-53 Rev 5 | https://csrc.nist.gov/publications/detail/sp/800-53/rev-5 |
| OpenSCAP / SCAP Security Guide | https://www.open-scap.org |
| Amazon Inspector v2 | https://docs.aws.amazon.com/inspector |
| Trivy Vulnerability Scanner | https://trivy.dev |
| AWS Packer Plugin | https://developer.hashicorp.com/packer/plugins/builders/amazon |
| AWS SSM Session Manager | https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html |

---

## 📄 License

This documentation is intended for educational use. Always validate security configurations against your organization's specific compliance requirements before production deployment.

---

*Maintained by the Security Engineering Team | Last Updated: April 2025*
