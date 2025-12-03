# LogWarden Architecture

LogWarden uses a **Hub and Spoke** architecture to securely collect, analyze, and visualize logs from multiple servers.

## Components

### 1. The Hub (Central Server)
This is the main LogWarden instance (Dashboard + Core API + AI).
- **Core API**: Receives logs from all agents via `POST /ingest/logs`.
- **AI Engine**: Analyzes incoming logs in real-time.
- **Dashboard**: Visualizes data and manages the system.

### 2. The Spokes (Agents)
Lightweight collectors installed on your target servers (Linux, Windows, macOS).
- **Function**: They "tail" local log files (e.g., `/var/log/syslog`).
- **Communication**: They **PUSH** logs to the Hub over HTTPS.
- **Security**: No inbound ports needed on the agents. They only need outbound access to the Hub.

## Data Flow
1. **Event Occurs**: A user fails login on `Server-A`.
2. **Capture**: The Agent on `Server-A` reads the log line.
3. **Push**: Agent sends JSON payload to `Hub-URL/ingest/logs`.
4. **Ingest**: Hub saves log to database.
5. **Analyze**: AI Engine scans log for threats (e.g., "Brute Force").
6. **Alert**: Dashboard updates instantly with the new threat.

## Scalability
- **Horizontal Scaling**: You can add hundreds of agents. The Hub handles the aggregation.
- **Performance**: Agents are minimal python scripts (<10MB RAM).
