#!/usr/bin/env groovy
// SecurePipe — Jenkins Shared Library
// Usage: @Library('securepipe') _ securePipeFullScan()

def call(Map config = [:]) {
    def reportDir = config.reportDir ?: 'securepipe-reports'
    def failOnCritical = config.failOnCritical ?: true
    def failOnHigh = config.failOnHigh ?: true
    def containerImage = config.containerImage ?: ''
    def dastUrl = config.dastUrl ?: ''
    def skipStages = config.skipStages ?: []

    pipeline {
        agent any

        environment {
            REPORT_DIR = "${reportDir}"
        }

        stages {
            stage('Secrets Detection') {
                when { expression { !('secrets' in skipStages) } }
                steps {
                    sh "mkdir -p ${reportDir}"
                    docker.image('zricethezav/gitleaks:8.18').inside('--entrypoint=') {
                        sh "gitleaks detect --source . --report-format json --report-path ${reportDir}/secrets-results.json || true"
                    }
                    script {
                        def findings = sh(script: "jq 'length' ${reportDir}/secrets-results.json 2>/dev/null || echo 0", returnStdout: true).trim()
                        echo "Gitleaks found ${findings} secrets"
                        if (findings.toInteger() > 0 && failOnCritical) {
                            error "Secrets detected — failing pipeline"
                        }
                    }
                }
            }

            stage('SAST') {
                when { expression { !('sast' in skipStages) } }
                steps {
                    docker.image('returntocorp/semgrep:1.64').inside('--entrypoint=') {
                        sh "semgrep --config auto --json --output ${reportDir}/sast-results.json . || true"
                    }
                    script {
                        def count = sh(script: "jq '.results | length' ${reportDir}/sast-results.json 2>/dev/null || echo 0", returnStdout: true).trim()
                        echo "Semgrep found ${count} findings"
                    }
                }
            }

            stage('Dependency Scanning') {
                when { expression { !('deps' in skipStages) } }
                steps {
                    docker.image('aquasec/trivy:0.51').inside('--entrypoint=') {
                        sh "trivy fs --format json --output ${reportDir}/dependency-results.json . || true"
                    }
                    script {
                        def count = sh(script: "jq '[.Results[]?.Vulnerabilities // [] | length] | add // 0' ${reportDir}/dependency-results.json 2>/dev/null || echo 0", returnStdout: true).trim()
                        echo "Trivy found ${count} dependency vulnerabilities"
                        if (count.toInteger() > 0 && failOnHigh) {
                            def critical = sh(script: "jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == \"CRITICAL\")] | length' ${reportDir}/dependency-results.json 2>/dev/null || echo 0", returnStdout: true).trim()
                            def high = sh(script: "jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == \"HIGH\")] | length' ${reportDir}/dependency-results.json 2>/dev/null || echo 0", returnStdout: true).trim()
                            if (critical.toInteger() > 0 && failOnCritical) { error "${critical} CRITICAL vulnerabilities found" }
                            if (high.toInteger() > 0 && failOnHigh) { error "${high} HIGH vulnerabilities found" }
                        }
                    }
                }
            }

            stage('Container Scanning') {
                when { expression { !('container' in skipStages) && containerImage } }
                steps {
                    docker.image('aquasec/trivy:0.51').inside('--entrypoint=') {
                        sh "trivy image --format json --output ${reportDir}/container-results.json ${containerImage} || true"
                    }
                    script {
                        def count = sh(script: "jq '[.Results[]?.Vulnerabilities // [] | length] | add // 0' ${reportDir}/container-results.json 2>/dev/null || echo 0", returnStdout: true).trim()
                        echo "Container scan found ${count} vulnerabilities"
                    }
                }
            }

            stage('DAST') {
                when { expression { !('dast' in skipStages) && dastUrl } }
                steps {
                    docker.image('owasp/zap2docker-stable:2.15').inside('--entrypoint=') {
                        sh "zap-baseline.py -t ${dastUrl} -J dast-results.json || true"
                        sh "cp /zap/json-report/dast-results.json ${reportDir}/ 2>/dev/null || true"
                    }
                }
            }

            stage('Signing') {
                when { expression { !('signing' in skipStages) && containerImage && env.COSIGN_KEY } }
                steps {
                    docker.image('bitnami/cosign:2.4').inside('--entrypoint=') {
                        sh "cosign sign --key env://COSIGN_KEY ${containerImage} || echo 'Signing failed'"
                    }
                }
            }

            stage('SBOM') {
                when { expression { !('sbom' in skipStages) } }
                steps {
                    docker.image('anchore/syft:1.11').inside('--entrypoint=') {
                        sh "syft dir:./ -o cyclonedx-json > ${reportDir}/sbom-cyclonedx.json || true"
                    }
                }
            }
        }

        post {
            always {
                archiveArtifacts artifacts: "${reportDir}/**", allowEmptyArchive: true
            }
        }
    }
}