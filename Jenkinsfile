/*
Enhanced DevSecOps Pipeline with:
- Parallel security scanning
- Quality gates with configurable thresholds
- Better error handling and reporting
- Modular structure
- Artifact management
- Monitoring integration
*/

@Library('security-library') _

// Configuration
def config = [
    security: [
        sast: [threshold: 5, level: 'low'],
        sca: [threshold: 10],
        container: [threshold: 3],
        dast: [threshold: 5]
    ],
    aws: [
        region: 'eu-west-2',
        instance_type: 't3.medium',
        cleanup: true
    ],
    notifications: [
        email: 'security-team@company.com',
        slack: '#security-alerts'
    ]
]

testenv = "null"
def scanResults = [:]

pipeline {
    agent any
    
    options {
        timeout(time: 2, unit: 'HOURS')
        timestamps()
        ansiColor('xterm')
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }
    
    environment {
        AWS_DEFAULT_REGION = 'eu-west-2'
        PYTHONPATH = "${WORKSPACE}"
        SECURITY_REPORTS_DIR = "${WORKSPACE}/security-reports"
    }
    
    stages {
        stage('Initialize') {
            steps {
                script {
                    // Create reports directory
                    sh 'mkdir -p ${SECURITY_REPORTS_DIR}'
                    
                    // Load configuration
                    if (fileExists('pipeline-config.yaml')) {
                        config = readYaml file: 'pipeline-config.yaml'
                    }
                    
                    echo "Pipeline configuration loaded: ${config}"
                }
            }
        }
        
        stage('Checkout & Setup') {
            steps {
                script {
                    // Checkout with retry
                    retry(3) {
                        checkout([
                            $class: 'GitSCM',
                            branches: [[name: '*/master']],
                            userRemoteConfigs: [[
                                url: 'https://github.com/pawnu/secDevLabs.git',
                                credentialsId: 'github-credentials'
                            ]]
                        ])
                    }
                    
                    // Setup Python environment
                    sh '''
                        python3 -m venv venv
                        source venv/bin/activate
                        pip install --upgrade pip
                        pip install -r requirements.txt || true
                    '''
                }
            }
        }
        
        stage('Security Scans') {
            parallel {
                stage('SAST') {
                    steps {
                        script {
                            echo 'Running Static Application Security Testing'
                            sh '''
                                source venv/bin/activate
                                bandit -r . -f json -o ${SECURITY_REPORTS_DIR}/bandit-report.json -ll || true
                                bandit -r . -f html -o ${SECURITY_REPORTS_DIR}/bandit-report.html -ll || true
                            '''
                            
                            // Parse results
                            if (fileExists("${SECURITY_REPORTS_DIR}/bandit-report.json")) {
                                def results = readJSON file: "${SECURITY_REPORTS_DIR}/bandit-report.json"
                                scanResults.sast = results
                                echo "SAST found ${results.results.size()} issues"
                            }
                        }
                    }
                }
                
                stage('SCA') {
                    steps {
                        script {
                            echo 'Running Software Composition Analysis'
                            sh '''
                                source venv/bin/activate
                                safety check -r requirements.txt --json --output ${SECURITY_REPORTS_DIR}/safety-report.json || true
                                safety check -r requirements.txt --html --output ${SECURITY_REPORTS_DIR}/safety-report.html || true
                            '''
                            
                            if (fileExists("${SECURITY_REPORTS_DIR}/safety-report.json")) {
                                def results = readJSON file: "${SECURITY_REPORTS_DIR}/safety-report.json"
                                scanResults.sca = results
                                echo "SCA found ${results.vulnerabilities.size()} vulnerabilities"
                            }
                        }
                    }
                }
                
                stage('Secret Scanning') {
                    steps {
                        script {
                            echo 'Running Git Secret Scanner'
                            sh '''
                                trufflehog --regex --entropy=False --max_depth=3 --json . > ${SECURITY_REPORTS_DIR}/trufflehog-report.json || true
                                trufflehog --regex --entropy=False --max_depth=3 --html . > ${SECURITY_REPORTS_DIR}/trufflehog-report.html || true
                            '''
                            
                            if (fileExists("${SECURITY_REPORTS_DIR}/trufflehog-report.json")) {
                                def results = readJSON file: "${SECURITY_REPORTS_DIR}/trufflehog-report.json"
                                scanResults.secrets = results
                                echo "Secret scan found ${results.size()} potential secrets"
                            }
                        }
                    }
                }
                
                stage('Container Audit') {
                    steps {
                        script {
                            echo 'Auditing Dockerfile security'
                            sh '''
                                mkdir -p ${SECURITY_REPORTS_DIR}/container
                                lynis audit dockerfile Dockerfile --report-file ${SECURITY_REPORTS_DIR}/container/lynis-report.txt || true
                                trivy image --format json --output ${SECURITY_REPORTS_DIR}/container/trivy-report.json . || true
                                trivy image --format html --output ${SECURITY_REPORTS_DIR}/container/trivy-report.html . || true
                            '''
                        }
                    }
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                script {
                    echo 'Evaluating security quality gates'
                    
                    def violations = []
                    
                    // SAST Quality Gate
                    if (scanResults.sast && scanResults.sast.results.size() > config.security.sast.threshold) {
                        violations.add("SAST: ${scanResults.sast.results.size()} issues found (threshold: ${config.security.sast.threshold})")
                    }
                    
                    // SCA Quality Gate
                    if (scanResults.sca && scanResults.sca.vulnerabilities.size() > config.security.sca.threshold) {
                        violations.add("SCA: ${scanResults.sca.vulnerabilities.size()} vulnerabilities found (threshold: ${config.security.sca.threshold})")
                    }
                    
                    // Secret Quality Gate
                    if (scanResults.secrets && scanResults.secrets.size() > 0) {
                        violations.add("SECRETS: ${scanResults.secrets.size()} potential secrets found")
                    }
                    
                    if (violations.size() > 0) {
                        def message = "Security quality gates failed:\n" + violations.join("\n")
                        error message
                    }
                    
                    echo "All security quality gates passed!"
                }
            }
        }
        
        stage('Deploy Test Environment') {
            steps {
                script {
                    echo 'Setting up AWS test environment'
                    
                    // Use Terraform for infrastructure
                    sh '''
                        cd terraform
                        terraform init
                        terraform plan -out=tfplan
                        terraform apply tfplan
                    '''
                    
                    // Get test environment details
                    testenv = sh(
                        script: "terraform output -raw test_instance_ip",
                        returnStdout: true
                    ).trim()
                    
                    echo "Test environment deployed at: ${testenv}"
                    
                    // Configure test environment
                    sh "ansible-playbook -i ~/ansible_hosts ~/configureTestEnv.yml --extra-vars 'testenv=${testenv}'"
                }
            }
        }
        
        stage('DAST') {
            steps {
                script {
                    echo 'Running Dynamic Application Security Testing'
                    
                    if (testenv != "null") {
                        sh '''
                            source venv/bin/activate
                            python ~/authDAST.py $SeleniumPrivateIp ${testenv} ${SECURITY_REPORTS_DIR}/dast-results.html
                            
                            # Run additional DAST tools
                            nikto -h http://${testenv}:10007 -Format html -output ${SECURITY_REPORTS_DIR}/nikto-report.html || true
                            zap-baseline.py -t http://${testenv}:10007 -J ${SECURITY_REPORTS_DIR}/zap-report.json || true
                        '''
                    }
                }
            }
        }
        
        stage('System Security Audit') {
            steps {
                script {
                    echo 'Running system security audit'
                    sh '''
                        ansible-playbook -i ~/ansible_hosts ~/hostaudit.yml \
                            --extra-vars "logfolder=${SECURITY_REPORTS_DIR}/system/"
                    '''
                }
            }
        }
        
        stage('Deploy WAF') {
            steps {
                script {
                    echo 'Deploying Web Application Firewall'
                    sh 'ansible-playbook -i ~/ansible_hosts ~/configureWAF.yml'
                }
            }
        }
        
        stage('Generate Reports') {
            steps {
                script {
                    echo 'Generating comprehensive security report'
                    
                    // Create executive summary
                    sh '''
                        cat > ${SECURITY_REPORTS_DIR}/executive-summary.html << 'EOF'
                        <html>
                        <head><title>Security Scan Report</title></head>
                        <body>
                        <h1>Security Scan Executive Summary</h1>
                        <p>Build: ${BUILD_NUMBER}</p>
                        <p>Timestamp: ${new Date()}</p>
                        <h2>Scan Results:</h2>
                        <ul>
                        <li>SAST Issues: ${scanResults.sast?.results?.size() ?: 0}</li>
                        <li>SCA Vulnerabilities: ${scanResults.sca?.vulnerabilities?.size() ?: 0}</li>
                        <li>Secrets Found: ${scanResults.secrets?.size() ?: 0}</li>
                        </ul>
                        </body>
                        </html>
                        EOF
                    '''
                    
                    // Archive reports
                    archiveArtifacts artifacts: 'security-reports/**/*', fingerprint: true
                    
                    // Publish to artifact repository
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'security-reports',
                        reportFiles: 'executive-summary.html',
                        reportName: 'Security Report'
                    ])
                }
            }
        }
    }
    
    post {
        always {
            script {
                // Cleanup test environment if configured
                if (config.aws.cleanup && testenv != "null") {
                    echo "Cleaning up test environment: ${testenv}"
                    sh 'ansible-playbook -i ~/ansible_hosts ~/killec2.yml'
                }
                
                // Send notifications
                if (currentBuild.result == 'SUCCESS') {
                    echo "Pipeline completed successfully"
                } else {
                    echo "Pipeline failed or was aborted"
                }
            }
        }
        
        success {
            script {
                // Success notification
                emailext (
                    subject: "Security Pipeline SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        Security pipeline completed successfully!
                        
                        Build: ${env.BUILD_NUMBER}
                        URL: ${env.BUILD_URL}
                        
                        Scan Results:
                        - SAST Issues: ${scanResults.sast?.results?.size() ?: 0}
                        - SCA Vulnerabilities: ${scanResults.sca?.vulnerabilities?.size() ?: 0}
                        - Secrets Found: ${scanResults.secrets?.size() ?: 0}
                        
                        Reports available at: ${env.BUILD_URL}artifact/security-reports/
                    """,
                    to: config.notifications.email
                )
            }
        }
        
        failure {
            script {
                // Failure notification
                emailext (
                    subject: "Security Pipeline FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        Security pipeline failed!
                        
                        Build: ${env.BUILD_NUMBER}
                        URL: ${env.BUILD_URL}
                        
                        Please check the build logs for details.
                    """,
                    to: config.notifications.email
                )
            }
        }
        
        cleanup {
            script {
                // Cleanup workspace
                cleanWs()
            }
        }
    }
}
