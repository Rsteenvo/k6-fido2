
@Library('jenkins-shared-library@latest') _

pipeline {
    agent {
        kubernetes {
            label 'kaniko'
        }
    }

    // Disable concurrent build on a branch to avoid we tag 1 commits twice. This is valid per branch and not the whole job.
    options {
        disableConcurrentBuilds()
    }

    environment {
        MVN_VERSION = "maven 3.3.9"
    }

    stages {
        stage ('Checkout & Initialize') {
            steps {
                script {
                    ciSCMCheckout()
                    pom = readMavenPom(file: 'pom.xml')
                }
            }
        }
        stage('Download dependencies') {
            steps {
                withMaven(maven: MVN_VERSION, mavenSettingsConfig: SETTINGS_ID) {
                    // Download multithreaded, 4 threads per core.
                    sh "mvn -T 4C -B dependency:copy-dependencies dependency:resolve-plugins"
                }
            }
        }
        stage('Build & Test & Verify') {
            steps {
                withMaven(maven: MVN_VERSION, mavenSettingsConfig: SETTINGS_ID) {
                    sh "mvn test verify"
                }
            }
        }
        stage('Docker Build & Push') {
            steps {
                script {
                    if (env.BRANCH_NAME == 'master') {
                        IMAGETAG="${pom.version}".minus('-SNAPSHOT')
                        REPO="staging"
                    } else {
                        IMAGETAG="${pom.version}-${env.CHANGE_BRANCH ?: env.BRANCH_NAME}"
                        REPO="development"
                    }
                }

                buildPushImage_v2("${pom.artifactId}","${IMAGETAG}", [
                  VERSION: "${pom.version}",
                  PROJECT: "${REPO}"
                ])
            }
        }
        stage('Release') {
            when {
                anyOf {
                    branch 'master'
                    expression { env.BRANCH_NAME ==~ /^\d+\.\d+\.\d+-hotfix$/ }
                    expression { env.BRANCH_NAME ==~ /^\d+\.\d+\.\d+-patch$/ }
                    expression { env.BRANCH_NAME ==~ /^\d+\.\d+\.\d+-release$/ }
                }
            }
            steps {
                sshagent(["stash_clippyservice_ssh_key"]){
                    withMaven(maven: MVN_VERSION,  mavenSettingsConfig: SETTINGS_ID){
                        script {
                            // during release we don't have to run tests again. This saves a tremendous amount of time
                            sh "mvn -DskipTests -Dmaven.test.skip=true --batch-mode release:prepare release:perform -Dmaven.javadoc.skip=true"
                        }
                    }
                }
            }
        }
    }

    post {
        failure {
            slackSend(channel: "#dv-notifications", color: '#FF0000', message: "${env.JOB_NAME} has failed: ${env.BUILD_URL}")
        }
    }
}
