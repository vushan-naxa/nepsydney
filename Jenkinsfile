pipeline {
    agent any
    stages {
        stage('Test'){
            steps{
                sh 'echo "Test skipped"'
            }
        }

        stage('Deploy'){
            steps{
                // sh "chmod 755 ./deploy.sh"
                // sh "sh ./deploy.sh"
                echo "Deploy done"
                // sh 'ssh root@139.59.67.104 "bash -s" < ./deploy.sh'
            }
        }
    }

    post{
        success{
            echo 'Success'
            echo `git rev-parse --short HEAD`
            // slackSend (color: '#00FF00', message: "SUCCESS: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
        }
        failure {
            echo 'Failed'
            // slackSend (color: '#FF0000', message: "FAILED: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
        }
        unstable {
            echo 'Unstable'
        }
        changed {
            echo 'State changed'
        }
    }
}