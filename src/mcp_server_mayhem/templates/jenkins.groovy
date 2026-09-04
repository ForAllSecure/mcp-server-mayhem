// Runs one Mayhem analysis per Mayhemfile, fanning out in parallel so that a
// defect in one target does not stop the others.
//
// Requires a Jenkins credential holding the Mayhem token; see the environment
// block below. The token is bound by Jenkins and read by the CLI from the
// environment, never passed as a command-line flag where it would appear in the
// build log and the process list.
//
// Placeholder contract: see CONTRACT.md in this directory.
pipeline {
    agent any

    parameters {
        // Per-target run duration in seconds. Override it for a single build
        // from "Build with Parameters" without regenerating this file.
        string(
            name: 'MAYHEM_DURATION',
            defaultValue: '<<duration_seconds>>',
            description: 'Seconds to run each target for'
        )
    }

    environment {
        // 'mayhem-token' is a placeholder. Create a "Secret text" credential
        // with exactly that ID under Manage Jenkins > Credentials and store the
        // Mayhem token in it. Jenkins binds it here as <<token_secret_ref>> and
        // masks it in the build log. Until that credential exists the build
        // fails immediately with "Could not find credentials entry with ID
        // 'mayhem-token'".
        MAYHEM_TOKEN = credentials('mayhem-token')
        // Empty unless a self-hosted Mayhem instance was specified. An empty
        // MAYHEM_URL is not treated as "unset" by the CLI, so every step that
        // reaches the API falls back to the public endpoint explicitly.
        MAYHEM_URL = '<<mayhem_url>>'
        // Empty when no image was supplied, in which case --image is omitted
        // entirely below and the image declared in the Mayhemfile is used.
        TARGET_IMAGE = '<<image>>'
    }

    stages {
<<#build_job>>
        stage('build and push image') {
            steps {
                // 'mayhem-registry' is a placeholder. Create a "Username with
                // password" credential with exactly that ID under Manage
                // Jenkins > Credentials, holding an account allowed to push to
                // the registry that hosts TARGET_IMAGE. Jenkins has no
                // zero-configuration registry credential the way GitHub and
                // GitLab do, so until that credential exists this stage fails
                // at "docker push" with an authentication error.
                withCredentials([usernamePassword(
                    credentialsId: 'mayhem-registry',
                    usernameVariable: 'REGISTRY_USER',
                    passwordVariable: 'REGISTRY_PASSWORD'
                )]) {
                    // Change ghcr.io below if TARGET_IMAGE is hosted on a
                    // different registry. The password is piped rather than
                    // passed with -p so it does not reach the build log.
                    sh '''
                        set -eu
                        echo "$REGISTRY_PASSWORD" | docker login -u "$REGISTRY_USER" --password-stdin ghcr.io
                        docker build -t "$TARGET_IMAGE" -f "<<dockerfile>>" "<<build_context>>"
                        docker push "$TARGET_IMAGE"
                    '''
                }
            }
        }

<</build_job>>
        stage('install the Mayhem CLI') {
            // Downloaded once into the workspace rather than inside each
            // parallel branch, because the branches below share this workspace
            // and would otherwise race writing the same file.
            steps {
                sh '''
                    set -eu
                    MAYHEM_URL="${MAYHEM_URL:-https://app.mayhem.security}"
                    curl -fsSL "$MAYHEM_URL/cli/Linux/mayhem" -o mayhem
                    chmod +x mayhem
                '''
            }
        }

        stage('fuzz') {
            steps {
                script {
                    def mayhemfiles = <<targets_list>>
                    def branches = [:]
                    // A plain for loop rather than .each: closures over a
                    // collection do not survive Jenkins' CPS transformation
                    // reliably. Rebinding inside the body gives each branch its
                    // own copy of the path instead of sharing the loop variable.
                    for (path in mayhemfiles) {
                        def mayhemfile = path
                        branches["fuzz ${mayhemfile}"] = {
                            withEnv(["MAYHEMFILE=${mayhemfile}"]) {
                                // catchError records this target as failed
                                // without aborting its siblings, so one bad
                                // target does not cancel the rest of the matrix.
                                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                    // --image is omitted entirely when no image
                                    // was supplied. Passing an empty value would
                                    // make the CLI consume the next flag as the
                                    // image name.
                                    sh '''
                                        set -eu
                                        export MAYHEM_URL="${MAYHEM_URL:-https://app.mayhem.security}"
                                        if [ -n "$TARGET_IMAGE" ]; then
                                          ./mayhem run . --file "$MAYHEMFILE" --duration "$MAYHEM_DURATION" --image "$TARGET_IMAGE"
                                        else
                                          ./mayhem run . --file "$MAYHEMFILE" --duration "$MAYHEM_DURATION"
                                        fi
                                    '''
                                }
                            }
                        }
                    }
                    // Sibling branches run to completion when one fails.
                    branches.failFast = false
                    parallel branches
                }
            }
        }
    }
}
