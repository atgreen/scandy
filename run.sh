#!/bin/bash

set -e
set -x

WORKDIR=`mktemp -d`

function cleanup {
    rm -rf ${WORKDIR}
}

trap cleanup EXIT

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

if ! test -f /usr/bin/sbcl; then
  sudo apt update
  sudo apt install sbcl sqlite3 libsqlite3-dev
  git clone https://github.com/ocicl/ocicl
  (cd ocicl; sbcl --load setup.lisp; ocicl setup > ~/.sbclrc)
fi

echo TESTING DB
sbcl --non-interactive --eval "(asdf:load-system :dbi)" --eval "(defvar *db* (dbi:connect :sqlite3 :database-name \"~/foo.db\"))"
ls -l ~/foo.db

for IMAGE in registry.access.redhat.com/ubi9 \
                 registry.access.redhat.com/ubi8 \
                 registry.access.redhat.com/ubi9-minimal \
                 registry.access.redhat.com/ubi8-minimal \
                 registry.access.redhat.com/ubi8/python-39 \
                 registry.access.redhat.com/ubi8/python-311 \
                 registry.access.redhat.com/ubi8/python-312 \
                 registry.access.redhat.com/ubi9/python-39 \
                 registry.access.redhat.com/ubi9/python-311 \
                 registry.access.redhat.com/ubi9/python-312 \
                 registry.redhat.io/ocp-tools-4/jenkins-rhel8:v4.12.0-1716801209 \
                 registry.redhat.io/jboss-eap-7/eap74-openjdk11-runtime-openshift-rhel8; do

    SCANDIR=${WORKDIR}/$(echo ${IMAGE} | sed -e 's/regi.*\///g')

    echo "===== Processing ${IMAGE} =========================="

    # Install the latest package updates.
    cat > Containerfile <<EOF
FROM ${IMAGE}
USER 0
RUN yum -y update || microdnf -y update
EOF
    cat Containerfile
    podman build -t ${IMAGE}-with-updates .
    trivy_scan ${SCANDIR} ${IMAGE}-with-updates
    grype_scan ${SCANDIR} ${IMAGE}-with-updates

    IMG=$(echo ${IMAGE}-with-updates | sed 's/\//\-\-/g')
    IMG=$(echo ${IMG} | sed 's/:/\-\-/g')
    VERSION=$(date +%Y%m%d)

    sbcl --non-interactive --load report.lisp $(pwd)/_site/${IMG}.html ${SCANDIR}/grype/* ${SCANDIR}/trivy/* ${IMAGE} ~/scandy.db

    (cd ${WORKDIR};
     tar cvfz ${IMG}-scandy.tar.gz * ;
     oras push ghcr.io/atgreen/${IMG}:${VERSION} ${IMG}-scandy.tar.gz:application/vnd.uknown/layer.v1+gzip ;
     oras tag ghcr.io/atgreen/${IMG}:${VERSION} latest

     rm -rf *
    )
done
