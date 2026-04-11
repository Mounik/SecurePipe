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
                    docker.image('zricethezav/gitleaks:latest').inside('--entrypoint=') {
                        sh "gitleaks detect --source . --report-format json --report-path ${reportDir}/secrets-results.json || true"
                    }
                }
            }

            stage('SAST') {
                when { expression { !('sast' in skipStages) } }
                steps {
                    docker.image('returntocorp/semgrep:latest').inside('--entrypoint=') {
                        sh "semgrep --config auto --json --output ${reportDir}/sast-results.json . || true"
                    }
                }
            }

            stage('Dependency Scanning') {
                when { expression { !('deps' in skipStages) } }
                steps {
                    docker.image('aquasec/trivy:latest').inside('--entrypoint=') {
                        sh "trivy fs --format json --output ${reportDir}/dependency-results.json . || true"
                    }
                }
            }

            stage('Container Scanning') {
                when { expression { !('container' in skipStages) && containerImage } }
                steps {
                    docker.image('aquasec/trivy:latest').inside('--entrypoint= -v /var/run/docker.sock:/var/run/docker.sock') {
                        sh "trivy image --format json --output ${reportDir}/container-results.json ${containerImage} || true"
                    }
                }
            }

            stage('DAST') {
                when { expression { !('dast' in skipStages) && dastUrl } }
                steps {
                    docker.image('owasp/zap2docker-stable:latest').inside('--entrypoint=') {
                        sh "zap-baseline.py -t ${dastUrl} -J dast-results.json || true"
                        sh "cp /zap/json-report/dast-results.json ${reportDir}/ || true"
                    }
                }
            }

            stage('SBOM') {
                when { expression { !('sbom' in skipStages) } }
                steps {
                    docker.image('anchore/syft:latest').inside('--entrypoint=') {
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