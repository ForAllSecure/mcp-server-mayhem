// STUB template - later work replaces this content with a real pipeline.
// It exists so the loading path, packaging, and platform-to-file mapping can be
// exercised end to end. Placeholder contract: see CONTRACT.md in this directory.
pipeline {
    agent any

    environment {
        // Jenkins binds the secret here; <<token_secret_ref>> is how a sh step
        // refers to it afterwards. Never echo the value.
        MAYHEM_TOKEN = credentials('mayhem-token')
        MAYHEM_URL = '<<mayhem_url>>'
    }

    stages {
<<#build_job>>
        stage('build') {
            steps {
                echo "build <<image>> from <<dockerfile>> with context <<build_context>>"
            }
        }
<</build_job>>
        stage('fuzz') {
            steps {
                script {
                    def mayhemfiles = <<targets_list>>
                    for (mayhemfile in mayhemfiles) {
                        echo "fuzz ${mayhemfile} image=<<image>> duration=<<duration_seconds>>s"
                    }
                }
            }
        }
    }
}
