#!/bin/bash

# Enhanced DevSecOps Setup Script
# This script sets up a complete DevSecOps environment with security best practices

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Configuration
JENKINS_PASSWORD=$(openssl rand -base64 32)
GRAFANA_PASSWORD=$(openssl rand -base64 16)
POSTGRES_PASSWORD=$(openssl rand -base64 16)
DOMAIN_NAME=$(curl -s http://169.254.169.254/latest/meta-data/public-hostname 2>/dev/null || echo "localhost")
JENKINS_PUBLIC_HOSTNAME=$(curl -s http://169.254.169.254/latest/meta-data/public-hostname 2>/dev/null || echo "localhost")
SELENIUM_PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null || echo "127.0.0.1")

log "Starting DevSecOps environment setup..."

# Update system
log "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install essential packages
log "Installing essential packages..."
apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    jq \
    tree \
    htop \
    vim \
    nano \
    fail2ban \
    ufw \
    unattended-upgrades \
    auditd \
    rkhunter \
    chkrootkit \
    lynis \
    clamav \
    clamav-daemon

# Install Docker
log "Installing Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Install Docker Compose
log "Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install Java
log "Installing Java..."
apt-get install -y default-jre default-jdk

# Configure Docker
log "Configuring Docker..."
usermod -aG docker ubuntu
systemctl enable docker
systemctl start docker

# Configure firewall
log "Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 8080/tcp
ufw allow 443/tcp
ufw allow 80/tcp
ufw allow 3000/tcp
ufw allow 5601/tcp
ufw allow 9090/tcp
ufw allow 9200/tcp
ufw allow 6379/tcp
ufw allow 5432/tcp

# Configure fail2ban
log "Configuring fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# Configure automatic security updates
log "Configuring automatic security updates..."
echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
echo 'Unattended-Upgrade::Automatic-Reboot-Time "02:00";' >> /etc/apt/apt.conf.d/50unattended-upgrades

# Create directories
log "Creating directories..."
mkdir -p /opt/devsecops/{logs,reports,artifacts,ssl}
mkdir -p /var/www/reports
chown -R ubuntu:ubuntu /opt/devsecops
chown -R ubuntu:ubuntu /var/www/reports

# Generate SSL certificates
log "Generating SSL certificates..."
cd /opt/devsecops/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout key.pem -out cert.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=${DOMAIN_NAME}"

# Set environment variables
log "Setting environment variables..."
cat > /opt/devsecops/.env << EOF
# DevSecOps Environment Variables
Jenkins_PW=${JENKINS_PASSWORD}
JAVA_OPTS=-Djenkins.install.runSetupWizard=false -Xmx2g -Xms1g
JenkinsPublicHostname=${JENKINS_PUBLIC_HOSTNAME}
SeleniumPrivateIp=${SELENIUM_PRIVATE_IP}
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DOMAIN_NAME=${DOMAIN_NAME}
EOF

# Copy environment file
cp /opt/devsecops/.env .env

# Create monitoring directories
log "Setting up monitoring..."
mkdir -p monitoring/grafana/{provisioning/{datasources,dashboards},dashboards}
mkdir -p monitoring/rules

# Create Prometheus rules
cat > monitoring/rules/security-alerts.yml << 'EOF'
groups:
  - name: security-alerts
    rules:
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% for 5 minutes"

      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is above 85% for 5 minutes"

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space"
          description: "Disk space is below 10%"

      - alert: JenkinsDown
        expr: up{job="jenkins"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Jenkins is down"
          description: "Jenkins service is not responding"
EOF

# Create Grafana datasource
cat > monitoring/grafana/provisioning/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

# Create Filebeat configuration
cat > monitoring/filebeat.yml << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/jenkins/*.log
  fields:
    service: jenkins
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/nginx/*.log
  fields:
    service: nginx
  fields_under_root: true

- type: docker
  containers.ids:
    - "*"
  processors:
    - add_docker_metadata:
        host: "unix:///var/run/docker.sock"

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  indices:
    - index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"

setup.kibana:
  host: "kibana:5601"

setup.dashboards.enabled: true
setup.template.enabled: true
EOF

# Build and start services
log "Building and starting services..."
docker-compose up -d --build

# Wait for services to be ready
log "Waiting for services to be ready..."
sleep 60

# Create Jenkins CLI jar
log "Downloading Jenkins CLI..."
wget http://127.0.0.1:8080/jnlpJars/jenkins-cli.jar -O jenkins-cli.jar

# Wait for Jenkins to be fully ready
log "Waiting for Jenkins to be fully ready..."
sleep 30

# Create the pipeline job
log "Creating Jenkins pipeline job..."
java -jar ./jenkins-cli.jar -s http://localhost:8080 -auth myjenkins:${JENKINS_PASSWORD} create-job pythonpipeline < config.xml

# Set up security tools
log "Setting up security tools..."
cd /opt/devsecops

# Install additional security tools
apt-get install -y \
    nikto \
    sqlmap \
    dirb \
    nmap \
    netcat \
    tcpdump \
    wireshark \
    aircrack-ng \
    john \
    hashcat

# Configure security monitoring
log "Configuring security monitoring..."

# Create security audit script
cat > /opt/devsecops/security-audit.sh << 'EOF'
#!/bin/bash
# Daily security audit script

LOG_FILE="/var/log/security-audit.log"
DATE=$(date +"%Y-%m-%d %H:%M:%S")

echo "[$DATE] Starting security audit..." >> $LOG_FILE

# System audit
lynis audit system --quick >> $LOG_FILE 2>&1

# Rootkit scan
rkhunter --check --skip-keypress >> $LOG_FILE 2>&1

# Virus scan
freshclam
clamscan -r /home /var/www /opt --exclude-dir="^/sys|^/proc" >> $LOG_FILE 2>&1

# Check for failed login attempts
grep "Failed password" /var/log/auth.log | tail -10 >> $LOG_FILE

# Check disk usage
df -h >> $LOG_FILE

# Check memory usage
free -h >> $LOG_FILE

# Check running processes
ps aux --sort=-%cpu | head -10 >> $LOG_FILE

echo "[$DATE] Security audit completed." >> $LOG_FILE
EOF

chmod +x /opt/devsecops/security-audit.sh

# Add to crontab
echo "0 2 * * * root /opt/devsecops/security-audit.sh" >> /etc/crontab

# Create backup script
log "Setting up backup system..."
cat > /opt/devsecops/backup.sh << 'EOF'
#!/bin/bash
# Backup script for DevSecOps environment

BACKUP_DIR="/opt/devsecops/backups"
DATE=$(date +"%Y%m%d_%H%M%S")
RETENTION_DAYS=30

mkdir -p $BACKUP_DIR

# Backup Jenkins home
tar -czf $BACKUP_DIR/jenkins_home_$DATE.tar.gz -C /opt/devsecops jenkins_home/

# Backup Docker volumes
docker run --rm -v jenkins_home:/data -v $BACKUP_DIR:/backup alpine tar -czf /backup/jenkins_data_$DATE.tar.gz -C /data .

# Backup configuration files
tar -czf $BACKUP_DIR/config_$DATE.tar.gz -C /opt/devsecops .env docker-compose.yml

# Cleanup old backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
EOF

chmod +x /opt/devsecops/backup.sh

# Add backup to crontab
echo "0 1 * * * root /opt/devsecops/backup.sh" >> /etc/crontab

# Create health check script
log "Setting up health monitoring..."
cat > /opt/devsecops/health-check.sh << 'EOF'
#!/bin/bash
# Health check script for DevSecOps services

SERVICES=("jenkins-master" "selenium-chrome" "prometheus" "grafana" "elasticsearch" "kibana" "nginx")

for service in "${SERVICES[@]}"; do
    if ! docker ps | grep -q $service; then
        echo "ERROR: $service is not running!"
        # Restart the service
        docker-compose restart $service
        # Send alert (you can add email/Slack notification here)
    else
        echo "OK: $service is running"
    fi
done
EOF

chmod +x /opt/devsecops/health-check.sh

# Add health check to crontab
echo "*/5 * * * * root /opt/devsecops/health-check.sh" >> /etc/crontab

# Final configuration
log "Performing final configuration..."

# Set proper permissions
chown -R ubuntu:ubuntu /opt/devsecops
chmod -R 755 /opt/devsecops

# Create access information file
cat > /opt/devsecops/access-info.txt << EOF
===========================================
DevSecOps Environment Setup Complete
===========================================

Jenkins Access:
- URL: https://${DOMAIN_NAME} or http://${DOMAIN_NAME}:8080
- Username: myjenkins
- Password: ${JENKINS_PASSWORD}

Grafana Access:
- URL: https://${DOMAIN_NAME}/grafana
- Username: admin
- Password: ${GRAFANA_PASSWORD}

Kibana Access:
- URL: https://${DOMAIN_NAME}/kibana

Prometheus Access:
- URL: https://${DOMAIN_NAME}/prometheus

Security Reports:
- URL: https://${DOMAIN_NAME}/reports

SSH Access:
- Use your SSH key to connect to this server
- User: ubuntu

Important Notes:
- All services are configured with security best practices
- Automatic backups run daily at 1 AM
- Security audits run daily at 2 AM
- Health checks run every 5 minutes
- Firewall is configured to allow only necessary ports

Backup Location: /opt/devsecops/backups
Logs Location: /opt/devsecops/logs
Reports Location: /var/www/reports

===========================================
EOF

# Display access information
log "Setup completed successfully!"
echo ""
cat /opt/devsecops/access-info.txt

# Save credentials securely
log "Saving credentials to secure location..."
cat > /root/devsecops-credentials.txt << EOF
Jenkins Password: ${JENKINS_PASSWORD}
Grafana Password: ${GRAFANA_PASSWORD}
PostgreSQL Password: ${POSTGRES_PASSWORD}
EOF

chmod 600 /root/devsecops-credentials.txt

log "Credentials saved to /root/devsecops-credentials.txt (root access only)"

# Final security check
log "Performing final security check..."
/opt/devsecops/security-audit.sh

log "DevSecOps environment setup completed!"
log "Please review the access information above and secure the credentials."
log "Remember to change default passwords after first login."
