# LogWarden Agentless "Octopus" Setup

LogWarden uses an **Agentless Pull Architecture**. You do not need to install any software on your servers.

## 1. Linux Servers (SSH)
Provide a read-only SSH key. The Octopus engine will connect and pull logs securely.

**Quickstart:**
1.  Add our public key to your server:
    ```bash
    echo "ssh-ed25519 AAAAC3Nza..." >> ~/.ssh/authorized_keys
    ```
2.  Add the server IP to LogWarden Settings.
3.  We handle the rest (log rotation, tailing, etc.).

## 2. Windows Servers (WinRM)
We use the native Windows Remote Management protocol (encrypted over HTTPS).

**Quickstart:**
1.  Enable WinRM on your server:
    ```powershell
    winrm quickconfig -transport:https
    ```
2.  Create a Service Account with "Event Log Readers" permission.
3.  Provide credentials to LogWarden.

## 3. Cloud (AWS/Azure)
We connect via Cloud-Native APIs (poll-based).

**AWS:**
-   Create a Cross-Account IAM Role with `CloudWatchKeyReadOnly`.
-   Provide the Role ARN.

**Azure:**
-   Register an App in Entra ID.
-   Grant `Reader` permissions on the Log Analytics Workspace.
