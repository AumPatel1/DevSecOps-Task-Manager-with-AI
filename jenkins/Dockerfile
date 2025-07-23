FROM jenkins/jenkins:lts-jdk17
MAINTAINER pawan uppadey <pawan.uppadey@gmail.com>

# Install Jenkins plugins
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN /usr/local/bin/install-plugins.sh < /usr/share/jenkins/ref/plugins.txt

# Copy automation scripts
COPY setupJenkins.groovy /usr/share/jenkins/ref/init.groovy.d/
COPY ansible.cfg /etc/ansible/ansible.cfg

# Switch to root for package installation
USER root

# Update package manager and install essential tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
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
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Install Terraform
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add - \
    && apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
    && apt-get update \
    && apt-get install -y terraform \
    && rm -rf /var/lib/apt/lists/*

# Install kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/

# Install Helm
RUN curl https://get.helm.sh/helm-v3.12.0-linux-amd64.tar.gz | tar xz \
    && mv linux-amd64/helm /usr/local/bin/ \
    && rm -rf linux-amd64

# Install Trivy for container scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.45.0

# Install additional security tools
RUN pip3 install --no-cache-dir \
    safety \
    bandit \
    trufflehog \
    semgrep \
    detect-secrets \
    pip-audit \
    safety-db \
    ansible \
    boto3 \
    botocore \
    kubernetes \
    prometheus-client \
    elasticsearch \
    requests \
    selenium \
    beautifulsoup4 \
    lxml \
    pyyaml \
    jinja2 \
    cryptography \
    paramiko \
    netaddr

# Install Node.js and npm for frontend security tools
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g npm@latest \
    && npm install -g \
        audit-ci \
        snyk \
        retire \
        eslint \
        prettier

# Install Go for additional security tools
RUN curl -fsSL https://go.dev/dl/go1.21.0.linux-amd64.tar.gz | tar -C /usr/local -xzf - \
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile

# Install additional security tools with Go
RUN /usr/local/go/bin/go install github.com/aquasecurity/trivy@latest \
    && /usr/local/go/bin/go install github.com/securecodewarrior/git-secrets@latest

# Install Lynis
RUN wget https://downloads.cisofy.com/lynis/lynis-3.0.8.tar.gz \
    && tar xfvz lynis-3.0.8.tar.gz -C /opt/ \
    && ln -s /opt/lynis/lynis /usr/local/bin/lynis \
    && rm lynis-3.0.8.tar.gz

# Install Nikto
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32 \
    && add-apt-repository 'deb http://archive.ubuntu.com/ubuntu bionic multiverse' \
    && add-apt-repository 'deb http://archive.ubuntu.com/ubuntu bionic-security multiverse' \
    && add-apt-repository 'deb http://archive.ubuntu.com/ubuntu bionic-updates multiverse' \
    && apt-get update \
    && apt-get install -y nikto \
    && rm -rf /var/lib/apt/lists/*

# Install OWASP ZAP
RUN mkdir -p /opt/zap \
    && curl -L https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz | tar xz -C /opt/zap --strip-components=1 \
    && ln -s /opt/zap/zap.sh /usr/local/bin/zap-baseline.py \
    && ln -s /opt/zap/zap.sh /usr/local/bin/zap-full-scan.py

# Install additional utilities
RUN pip3 install --no-cache-dir \
    kbtin \
    ansi2html \
    colorama \
    tabulate \
    rich \
    click \
    typer

# Create directories for security tools
RUN mkdir -p /var/jenkins_home/security-tools \
    /var/jenkins_home/reports \
    /var/jenkins_home/artifacts \
    /var/jenkins_home/logs

# Set up security tool configurations
COPY security-tools/ /var/jenkins_home/security-tools/

# Create non-root user for security tools
RUN useradd -m -s /bin/bash security \
    && chown -R security:security /var/jenkins_home/security-tools

# Set up monitoring
RUN mkdir -p /var/jenkins_home/monitoring \
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/security/.bashrc

# Install Prometheus Node Exporter for system metrics
RUN curl -L https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz | tar xz \
    && mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/ \
    && rm -rf node_exporter-1.6.1.linux-amd64

# Set up security hardening
RUN echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf \
    && echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf \
    && echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf

# Create security scripts
COPY scripts/ /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# Set up environment variables
ENV PATH="/usr/local/go/bin:${PATH}"
ENV PYTHONPATH="/var/jenkins_home/security-tools:${PYTHONPATH}"
ENV JENKINS_OPTS="--httpPort=-1 --httpsPort=8083 --httpsKeyStore=/var/jenkins_home/ssl/keystore.jks --httpsKeyStorePassword=changeit"

# Switch back to jenkins user
USER jenkins

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/login || exit 1

# Expose ports
EXPOSE 8080 8083 50000

# Default command
CMD ["jenkins"]
