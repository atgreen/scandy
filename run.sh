#!/bin/bash

set -e
set -x

WORKDIR=$(mktemp -d)

function cleanup {
    rm -rf ${WORKDIR}
}

trap cleanup EXIT

function retry_command {
    local -r cmd="$@"
    local -i attempt=0
    local -i max_attempts=5
    local -i sleep_time=1  # Initial backoff delay in seconds

    until $cmd; do
        attempt+=1
        if (( attempt > max_attempts )); then
            echo "The command has failed after $max_attempts attempts."
            return 1
        fi
        echo "The command has failed. Retrying in $sleep_time seconds..."
        sleep $sleep_time
        sleep_time=$((sleep_time * 2))  # Double the backoff delay each time
    done
}

function trivy_scan {
    # Perform trivy scans
    IMG=$(echo ${2} | sed 's/\//\-\-/g')
    IMG=$(echo ${IMG} | sed 's/:/\-\-/g')
    mkdir -p ${1}/trivy
    trivy -f json -o ${1}/trivy/${IMG}.json image ${2}
}

function grype_scan {
    # Perform grype scans
    IMG=$(echo ${2} | sed 's/\//\-\-/g')
    IMG=$(echo ${IMG} | sed 's/:/\-\-/g')
    mkdir -p ${1}/grype
    grype -o json=${1}/grype/${IMG}.json ${2}
}

# Clone the github advisory database
git clone --depth=1  https://github.com/github/advisory-database.git

for IMAGE in     registry.redhat.io/ansible-automation-platform-24/ee-supported-rhel8 \
                 registry.redhat.io/ubi8/dotnet-80 \
                 registry.redhat.io/ubi8/dotnet-60 \
                 registry.redhat.io/ubi8/dotnet-80-runtime \
                 registry.redhat.io/ubi8/dotnet-60-runtime \
                 registry.access.redhat.com/ubi9/nodejs-18 \
                 registry.access.redhat.com/ubi9/nodejs-20 \
                 registry.redhat.io/jboss-eap-7/eap74-openjdk11-openshift-rhel8 \
                 registry.redhat.io/ocp-tools-4/jenkins-rhel8:v4.12.0-1723557810 \
                 registry.redhat.io/ocp-tools-4/jenkins-rhel8:v4.14.0-1725667424 \
                 registry.access.redhat.com/ubi8/openjdk-8 \
                 registry.access.redhat.com/ubi8/openjdk-21 \
                 registry.access.redhat.com/ubi9/openjdk-21 \
                 registry.redhat.io/ubi8/openjdk-8-runtime \
                 registry.redhat.io/ubi8/openjdk-21-runtime \
                 registry.redhat.io/ubi9/openjdk-21-runtime \
                 registry.access.redhat.com/ubi9 \
                 registry.access.redhat.com/ubi8 \
                 registry.access.redhat.com/ubi9-minimal \
                 registry.access.redhat.com/ubi8-minimal \
                 registry.access.redhat.com/ubi9-micro \
                 registry.access.redhat.com/ubi8-micro \
                 registry.access.redhat.com/ubi8/python-39 \
                 registry.access.redhat.com/ubi8/python-311 \
                 registry.access.redhat.com/ubi8/python-312 \
                 registry.access.redhat.com/ubi9/python-39 \
                 registry.access.redhat.com/ubi9/python-311 \
                 registry.access.redhat.com/ubi9/python-312 \
                 registry.redhat.io/jboss-eap-7/eap74-openjdk11-runtime-openshift-rhel8; do

    SCANDIR=${WORKDIR}/$(echo ${IMAGE} | sed -e 's/regi.*\///g')

    echo "===== Processing ${IMAGE} =========================="

    # Install the latest package updates.
    cat > Containerfile <<EOF
FROM ${IMAGE}
USER 0
RUN yum -y update || microdnf -y update || true
EOF
    cat Containerfile
    retry_command podman build -t ${IMAGE}-with-updates .
    trivy_scan ${SCANDIR} ${IMAGE}-with-updates
    grype_scan ${SCANDIR} ${IMAGE}-with-updates

    if [[ "$IMAGE" != *":"* ]]; then
        podman rmi ${IMAGE}-with-updates:latest
        podman rmi ${IMAGE}:latest
    else
        podman rmi ${IMAGE}
    fi

    IMG=$(echo ${IMAGE}-with-updates | sed 's/\//\-\-/g')
    IMG=$(echo ${IMG} | sed 's/:/\-\-/g')
    VERSION=$(date +%Y%m%d)

    sbcl --non-interactive --eval "(asdf:load-system :report)" --eval "(report:main)" $(pwd)/_site/${IMG}.html ${SCANDIR}/grype/* ${SCANDIR}/trivy/* ${IMAGE} || true
    sbcl --eval "(asdf:load-system :report)" --eval "(report::make-index.html)"

    (cd ${WORKDIR};
     tar cvfz ${IMG}-scandy.tar.gz * ;
     retry_command oras push ghcr.io/atgreen/${IMG}:${VERSION} ${IMG}-scandy.tar.gz:application/vnd.uknown/layer.v1+gzip;
     retry_command oras tag ghcr.io/atgreen/${IMG}:${VERSION} latest

     rm -rf *
    )
done
