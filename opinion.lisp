;;; opinion.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2024  Anthony Green <green@moxielogic.com>
;;;
;;; Permission is hereby granted, free of charge, to any person obtaining a copy
;;; of this software and associated documentation files (the "Software"), to deal
;;; in the Software without restriction, including without limitation the rights
;;; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
;;; copies of the Software, and to permit persons to whom the Software is
;;; furnished to do so, subject to the following conditions:
;;;
;;; The above copyright notice and this permission notice shall be included in all
;;; copies or substantial portions of the Software.
;;;
;;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;;; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
;;; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
;;; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
;;; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;;; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;;; SOFTWARE.
;;;

(in-package :report)

(defun get-opinion (cve components locations image)
  (cond

    ((and (string= cve "CVE-2024-0057")
          (string= image "registry.redhat.io/ubi8/dotnet-80"))
     '("False Positive"
       "This is a false positive.  CVE-2024-0057 was addressed in <a href=\"https://access.redhat.com/errata/RHSA-2024:0150\">RHSA-2024:0150</a>."))

    ((and (string= cve "CVE-2024-38095")
          (string= image "registry.redhat.io/ubi8/dotnet-80"))
     '("False Positive"
       "This is a false positive.  CVE-2024-38095 was addressed in <a href=\"https://access.redhat.com/errata/RHSA-2024:4451\">RHSA-2024:4451</a>."))

    ((and (string= cve "CVE-2024-21626")
          (equal locations '("/usr/bin/oc"
                             "github.com/opencontainers/runc-v1.0.1")))
     '("False Positive"
       "This is a false positive.  The git commit to fix the problem in the upstream <code>runc</code> project can be reviewed here: <a href=\"https://github.com/opencontainers/runc/commit/02120488a4c0fc487d1ed2867e901eeed7ce8ecf\">https://github.com/opencontainers/runc/commit/02120488a4c0fc487d1ed2867e901eeed7ce8ecf</a>.   While <code>/usr/bin/oc</code> does use code from the vulnerable <code>runc</code> project, it only uses code from <code>github.com/opencontainers/runc/libcontainer/user</code>, which is unrelated to this CVE.  Accordingly, this is a false positive."))

    ((and (string= cve "CVE-2022-45047")
          (equal locations '("/usr/lib/jenkins/subversion.hpi"))
          (string= image "registry.redhat.io/ocp-tools-4/jenkins-rhel8:v4.14.0-1716468091"))
     '("False Positive"
       "This is a false positive.  The scanner is detecting CVE-2022-45047 in <code>/usr/lib/jenkins/subversion.hpi</code>, which is installed through the <code>jenkins-2-plugins</code> RPM.  CVE-2022-45047 was addressed in a much earlier OpenShift Developer Tools and Services RHSA for OCP 4.12: <a href=\"https://access.redhat.com/errata/RHSA-2023:1064\">https://access.redhat.com/errata/RHSA-2023:1064</a>.  Seeing as this was fixed in 4.12, well before 4.14, this image does not contain CVE-2022-45047 and is a false positive."))

    ((and (string= cve "GHSA-m425-mq94-257g")
          (equal locations '("/usr/bin/oc"
                             "google.golang.org/grpc-v1.51.0"))
          (string= image "registry.redhat.io/ocp-tools-4/jenkins-rhel8:v4.14.0-1716468091"))
     '("False Positive"
       "This Github Security Advisory appears to be an error in their metadata at <a href=\"https://github.com/github/advisory-database\">https://github.com/github/advisory-database</a>.  They don't indicate that it relates to any CVE, but in fact this appears to be <a href=\"https://access.redhat.com/security/cve/CVE-2023-44487\">CVE-2023-44487</a>.  An almost identical GHSA report does map to the correct CVE: <a href=\"https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g\">https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g</a>.   CVE-2023-44487 is fixed in this jenkins image according to this Red Hat Security Advisory: <a href=\"https://access.redhat.com/errata/RHSA-2023:7288\">https://access.redhat.com/errata/RHSA-2023:7288</a>.   However, <a href=\"https://access.redhat.com/errata/RHSA-2023:7288\">RHSA-2023:7288</a> does not reference the OpenShift client, <code>/usr/bin/oc</code>.  Running <code>/usr/bin/oc version</code> within the image shows that we have installed version 4.14.0-202405222237.p0.gf7b14a9.assembly.stream.el8-f7b14a9, which is newer than the version of the OpenShift client containing the CVE-2023-44487 fix that was delivered in <a href=\"https://access.redhat.com/errata/RHSA-2023:5009\">https://access.redhat.com/errata/RHSA-2023:5009</a>.  Accordingly, this is a false positive."))

    ((and (string= cve "CVE-2024-24790")
          (or (find "stdlib-1.19.13" locations :test 'equal)
              (find "stdlib-1.20.12" locations :test 'equal)))
     '("Ignorable"
       "Red Hat has rated this CVE as Medium severity in the context of RHEL, and does not intend to update <code>git-lfs</code> or <code>oc</code> to address this CVE.  Specifically, Red Hat differs from the NVD rating based on: <ul><li>Attack Vector: Local, not Network</li><li>Attack Complexity: High, not Low</li><li>Availability Impact: None, not High</li></ul>"))

    ((and (string= cve "CVE-2022-1471")
          (equal locations '("/usr/share/java/prometheus-jmx-exporter/jmx_prometheus_javaagent.jar")))
     '("False Positive"
       "This is a false positive.  CVE-2022-1471 was fixed for <code>prometheus-jmx-exporter</code> in security advisory update <a
href=\"https://access.redhat.com/errata/RHSA-2022:9058\">https://access.redhat.com/errata/RHSA-2022:9058</a>."))

    ((and (find cve '("CVE-2024-21147" "CVE-2024-21131" "CVE-2024-21138" "CVE-2024-21140" "CVE-2024-21144" "CVE-2024-21145") :test 'equal)
         (find "java-1.8.0-openjdk-headless-1:1.8.0.422.b05-2.el8" locations :test 'equal))
    '("False Positive"
      "This is a false positive.  This CVE was fixed in the security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2024:4563\">https://access.redhat.com/errata/RHSA-2024:4563</a> by <code>java-1.8.0-openjdk-headless-1:1.8.0.422.b05-2.el8</code> and related packages, which are already installed in this image."))

   ((and (find cve '("CVE-2024-21147" "CVE-2024-21131" "CVE-2024-21138" "CVE-2024-21140" "CVE-2024-21144" "CVE-2024-21145") :test 'equal)
         (find "java-11-openjdk-headless-1:11.0.24.0.8-3.el8" locations :test 'equal))
    '("False Positive"
      "This is a false positive.  This CVE was fixed in the security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2024:4566\">https://access.redhat.com/errata/RHSA-2024:4566</a> by <code>java-11-openjdk-headless-1:11.0.24.0.8-3.el8</code> and related packages, which are already installed in this image."))

   ((and (find cve '("CVE-2024-21145" "CVE-2024-21138" "CVE-2024-21131") :test 'equal)
         (find "java-21-openjdk-headless-1:21.0.4.0.7-1.el9" locations :test 'equal))
    '("False Positive"
      "This is a false positive.  This CVE was fixed in the security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2024:4573\">https://access.redhat.com/errata/RHSA-2024:4573</a> by <code>java-21-openjdk-headless-1:21.0.4.0.7-1.el9</code> and related packages, which are already installed in this image."))

   ((and (find cve '("CVE-2024-21145" "CVE-2024-21138" "CVE-2024-21131") :test 'equal)
         (find "java-21-openjdk-headless-1:21.0.4.0.7-1.el8" locations :test 'equal))
    '("False Positive"
      "This is a false positive.  This CVE was fixed in the security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2024:4573\">https://access.redhat.com/errata/RHSA-2024:4573</a> by <code>java-21-openjdk-headless-1:21.0.4.0.7-1.el8</code> and related packages, which are already installed in this image."))

   ((and (string= cve "CVE-2022-34169")
         (equal locations
                '("/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/xalan/xalan/2.7.1.redhat-00014/xalan-2.7.1.redhat-00014.jar"
                  "xalan:xalan-2.7.1.redhat-00014")))
    '("False Positive"
      "This is a false positive.  According to Red Hat, the vulnerable code is not included in the jar files used by EAP.  See <a href=\"https://access.redhat.com/solutions/6994572\">https://access.redhat.com/solutions/6994572</a> for details."))

   ((and (string= cve "CVE-2014-0107")
         (equal locations
                '("/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/xalan/xalan/2.7.1.redhat-00014/xalan-2.7.1.redhat-00014.jar"
                  "xalan:xalan-2.7.1.redhat-00014")))
    '("False Positive"
      "This is a false positive.  EAP 7 is not vulnerable to this CVE according to their document here: <a href=\"https://access.redhat.com/solutions/917873\">https://access.redhat.com/solutions/917873</a>."))

   ((and (string= cve "CVE-2014-3530")
         (equal locations
                '("/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/picketlink/picketlink-common/2.5.5.SP12-redhat-00013/picketlink-common-2.5.5.SP12-redhat-00013.jar"
                  "org.picketlink:picketlink-common-2.5.5.SP12-redhat-00013")))
    '("False Positive"
      "This is a false positive.  This CVE was fixed in EAP 5 and 6.   EAP 7 was released 7 years after this CVE, and was never affected by it."))

   ((and (string= cve "CVE-2024-23898")
         (equal locations '("org.jenkins-ci.main:jenkins-core-2.440.3")))
    '("False Positive"
       "This is a false positive.  This CVE was fixed in the OCP 4.12 Jenkins security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2024:0778\">https://access.redhat.com/errata/RHSA-2024:0778</a>."))

   ((and (string= cve "CVE-2022-25647")
          (equal locations '("/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/infinispan/protostream/protostream/4.3.6.Final-redhat-00001/protostream-4.3.6.Final-redhat-00001.jar"
                             "com.google.code.gson:gson-2.8.5.redhat-00002")))
     '("False Positive"
       "This is a false positive.  This CVE was fixed in the EAP 4.7.6 security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2022:5893\">https://access.redhat.com/errata/RHSA-2022:5893</a>."))

    ((and (string= cve "CVE-2022-1471")
          (equal locations '("org.yaml:snakeyaml-1.33.0.SP1-redhat-00001")))
     '("False Positive"
       "This is a false positive.  This CVE was fixed in the EAP 4.7.10 security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2023:1513\">https://access.redhat.com/errata/RHSA-2023:1513</a>."))

    ((and (string= cve "CVE-2022-23913")
          (equal locations '("/opt/eap/bin/client/jboss-client.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/apache/activemq/artemis-core-client/2.16.0.redhat-00052/artemis-core-client-2.16.0.redhat-00052.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/jboss/eap/wildfly-client-all/7.4.17.GA-redhat-00002/wildfly-client-all-7.4.17.GA-redhat-00002.jar"
                             "org.apache.activemq:artemis-core-client-2.16.0.redhat-00052")))
     '("False Positive"
       "This is a false positive.  This CVE was fixed in the EAP 4.7.5 security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2022:4919\">https://access.redhat.com/errata/RHSA-2022:4919</a>."))

    ((and (string= cve "CVE-2023-6236")
          (equal locations '("/opt/eap/bin/client/jboss-client.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/jboss/eap/wildfly-client-all/7.4.17.GA-redhat-00002/wildfly-client-all-7.4.17.GA-redhat-00002.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/wildfly/security/wildfly-elytron/1.15.23.Final-redhat-00001/wildfly-elytron-1.15.23.Final-redhat-00001.jar"
                             "org.wildfly.security:wildfly-elytron-http-oidc-1.15.23.Final-redhat-00001")))
     '("False Positive"
       "This is a false positive. EAP 7.4 does not provide the vulnerable provider-url configuration option in its OIDC implementation and is not affected by this flaw."))

    ((and (or (string= cve "CVE-2023-5685") (string= cve "CVE-2023-44487"))
          (equal locations '("/opt/eap/bin/client/jboss-cli-client.jar"
                             "/opt/eap/bin/client/jboss-client.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/jboss/eap/wildfly-client-all/7.4.17.GA-redhat-00002/wildfly-client-all-7.4.17.GA-redhat-00002.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/jboss/xnio/xnio-api/3.8.12.SP2-redhat-00001/xnio-api-3.8.12.SP2-redhat-00001.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/wildfly/core/wildfly-cli/15.0.36.Final-redhat-00001/wildfly-cli-15.0.36.Final-redhat-00001-client.jar"
                             "org.jboss.xnio:xnio-api-3.8.12.SP2-redhat-00001")))
     '("False Positive"
       "This is a false positive.  This CVE was fixed in the EAP 4.7.14 security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2023:7641\">https://access.redhat.com/errata/RHSA-2023:7641</a>."))

    ((and (string= cve "CVE-2023-44487")
          (equal locations '("/opt/eap/bin/client/jboss-client.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/io/netty/netty-codec-http2/4.1.94.Final-redhat-00003/netty-codec-http2-4.1.94.Final-redhat-00003.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/jboss/eap/wildfly-client-all/7.4.17.GA-redhat-00002/wildfly-client-all-7.4.17.GA-redhat-00002.jar"
                             "io.netty:netty-codec-http2-4.1.94.Final-redhat-00003")))
     '("False Positive"
       "This is a false positive.  CVE-2023-44487 was fixed for <code>netty-codec-http2</code> in the EAP 4.7.14 security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2023:7641\">https://access.redhat.com/errata/RHSA-2023:7641</a>."))

    ((and (string= cve "CVE-2023-44487")
          (equal locations '("nodejs-1:20.12.2-2.module+el9.4.0+21731+46b5b8a7"
                             "nodejs-docs-1:20.12.2-2.module+el9.4.0+21731+46b5b8a7"
                             "nodejs-full-i18n-1:20.12.2-2.module+el9.4.0+21731+46b5b8a7"
                             "npm-1:10.5.0-1.20.12.2.2.module+el9.4.0+21731+46b5b8a7")))
     '("False Positive"
       "This is a false positive.  The first <code>nodejs 20</code> introduced in RHEL 9 was version 20.8.1.  This is the same version that has the fix for CVE-2023-44487.  See <a href=\"https://nodejs.org/en/blog/release/v20.8.1/\">https://nodejs.org/en/blog/release/v20.8.1/</a> and <a href=\"https://nodejs.org/en/blog/vulnerability/october-2023-security-releases\">https://nodejs.org/en/blog/vulnerability/october-2023-security-releases</a> for details."))

    ((and (string= cve "CVE-2022-0235")
          (equal locations '("dnf-plugin-subscription-manager-1.28.42-1.el8"
                             "python3-cloud-what-1.28.42-1.el8"
                             "python3-subscription-manager-rhsm-1.28.42-1.el8"
                             "python3-syspurpose-1.28.42-1.el8"
                             "subscription-manager-1.28.42-1.el8")))
     '("False Positive"
       "This is a false positive. These packages used to have a dependency on the vulnerable <code>node-fetch</code> code back in RHEL 8.2, but this is no longer the case."))

    ((and (string= image "registry.redhat.io/jboss-eap-7/eap74-openjdk11-openshift-rhel8")
          (or (string= cve "CVE-2022-42004")
              (string= cve "CVE-2022-42003"))
          (equal locations '("/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/com/fasterxml/jackson/core/jackson-databind/2.12.7.redhat-00003/jackson-databind-2.12.7.redhat-00003.jar"
                             "com.fasterxml.jackson.core:jackson-databind-2.12.7.redhat-00003")))
     '("False Positive"
       "This is a false positive. This jackson-databind CVE was fixed in <a href=\"https://access.redhat.com/errata/RHSA-2023:0553\">RHSA-2023:0553</a>."))

    ((string= cve "CVE-2005-2541")
     '("Ignorable"
       "The <code>tar</code> program is behaving as documented. There are no plans to change this."))

    ((and (string= cve "CVE-2016-1000027")
          (equal locations '("/usr/lib/jenkins/jenkins.war" "org.springframework:spring-web-5.3.33")))
     '("Ignorable"
       "This CVE relates to using the spring framework for deserializing untrusted data.  However, Jenkins does not use the spring framework for deserialization.  It implements its own serialization framework, and the upstream Jenkins project explicitly ignores this CVE in their own CI infrastructure.  See <a href=\"https://github.com/jenkinsci/devops-portal-plugin/blame/af57f86bb4d12d3a0907aa40cf8040f24366eca3/suppress-dependency-issues.xml#L15\">https://github.com/jenkinsci/devops-portal-plugin/blame/af57f86bb4d12d3a0907aa40cf8040f24366eca3/suppress-dependency-issues.xml#L15</a>"))

    ((and (string= cve "CVE-2018-8088")
          (equal locations '("/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/slf4j/slf4j-ext/1.7.22.redhat-2/slf4j-ext-1.7.22.redhat-2.jar" "org.slf4j:slf4j-ext-1.7.22.redhat-2")))
     '("False Positive"
       "This is a false positive. This slf4j CVE was fixed in <a href=\"https://access.redhat.com/errata/RHSA-2018:0629\">RHSA-2018:0629</a> and <a href=\"https://access.redhat.com/errata/RHSA-2018:1251\">RHSA-2018:1251</a>."))

    ((and (or (string= cve "CVE-2022-23221")
              (string= cve "CVE-2021-42392"))
          (equal locations '("/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/com/h2database/h2/1.4.197.redhat-00004/h2-1.4.197.redhat-00004.jar" "com.h2database:h2-1.4.197.redhat-00004")))
     '("False Positive"
       "This is a false positive.  This CVE was fixed in the EAP 7.4.5 security advisory update <a href=\"https://access.redhat.com/errata/RHSA-2022:4919\">https://access.redhat.com/errata/RHSA-2022:4919</a>."))

    ((string= cve "CVE-2021-32256")
     '("Ignorable"
       "This is a junk CVE.  The upstream binutils project rejects this bug as a security issue, in accordance with <a href=\"https://sourceware.org/git/?p=binutils-gdb.git;a=blob_plain;f=binutils/SECURITY.txt;h=f16b0c9d7099150e0f116e9e681c424eea3915fe;hb=HEAD\">their security policy</a>."))

    ((and (string= cve "CVE-2022-40897")
          (equal locations '("/opt/app-root/lib/python3.9/site-packages/setuptools-53.0.0.dist-info/METADATA" "setuptools-53.0.0")))
     '("False Positive"
       "This is a false positive.  This container image contains a fixed
version of python-setuptools (see <a
href=\"https://access.redhat.com/errata/RHSA-2023:0952\">https://access.redhat.com/errata/RHSA-2023:0952</a>).
The scanner is not identifying the problem in this fixed copy of
python-setuptools because it can associate those files with the RPM
package that it knows contains the fix.
The scanner correctly recognizes that this fixed copy of
python-setuptools is not vulnerable to CVE-2022-40897.
However, the container image also contains a Python virtual environment in <code>/opt/app-root</code>, which includes copies of these fixed Python files. The scanner is unable to detect that these copies originated from Red Hat's fixed python-setuptools."))

    ((and (string= cve "CVE-2022-40897")
          (equal locations '("/opt/app-root/lib/python3.9/site-packages/setuptools-50.3.2.dist-info/METADATA" "setuptools-50.3.2")))
     '("False Positive"
       "This is a false positive.  This container image contains a fixed
version of python-setuptools (see <a
href=\"https://access.redhat.com/errata/RHSA-2024:2985\">https://access.redhat.com/errata/RHSA-2024:2985</a>).
The scanner correctly recognizes that this fixed copy of
python-setuptools is not vulnerable to CVE-2022-40897.
However, the container image also contains a Python virtual environment in <code>/opt/app-root</code>, which includes copies of these fixed Python files. The scanner is unable to detect that these copies originated from Red Hat's fixed python-setuptools."))


    ((and (string= cve "CVE-2022-3509") (find "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/infinispan/protostream/protostream/4.3.6.Final-redhat-00001/protostream-4.3.6.Final-redhat-00001.jar" locations :test 'equal))
     '("False Positive"
       "This is a false positive.  While <code>protostream-4.3.6.Final-redhat-00001.jar</code> does contain certain class files from <code>protobuf-java-3.15.2</code>, it does not contain the class file with the vulnerability (<code>com.google.protobuf.TextFormat</code>)."))

    ((and (or (string= cve "CVE-2022-3171") (string= cve "CVE-2022-3510")) (find "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/infinispan/protostream/protostream/4.3.6.Final-redhat-00001/protostream-4.3.6.Final-redhat-00001.jar" locations :test 'equal))
     '("False Positive"
       "This is a false positive.  While <code>protostream-4.3.6.Final-redhat-00001.jar</code> does contain certain class files from <code>protobuf-java-3.15.2</code>, it does not contain the class file with the vulnerability (<code>com.google.protobuf.MessageReflection</code>)."))

    ((and (string= cve "CVE-2022-3171")
          (equal locations '("/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/infinispan/protostream/protostream/4.3.6.Final-redhat-00001/protostream-4.3.6.Final-redhat-00001.jar"
                             "com.google.protobuf:protobuf-java-3.15.2")))
     '("False Positive"
       "This is a false positive.  While <code>protostream-4.3.6.Final-redhat-00001.jar</code> does contain certain class files from <code>protobuf-java-3.15.2</code>, it does not contain the class file with the vulnerability (<code>com.google.protobuf.UnknownFieldSet</code>)."))

    ((string= cve "CVE-2023-2004")
     '("Ignorable"
       "This is a junk CVE that is not a security issue and was withdrawn by its CNA.  Consider a global exception policy for this CVE."))

    ((equal components '("mod_http2"))
     '("Removable"
       "You can remove this from your application container if you aren't serving http2 content with <code>httpd</code>.  Consider removing this package like so:
<pre>
RUN rpm -e mod_http2
</pre>"))

    ((or (equal components '("httpd" "httpd-core" "httpd-devel" "httpd-filesystem" "httpd-tools" "mod_ldap" "mod_lua" "mod_session" "mod_ssl"))
         (equal components '("httpd" "httpd-devel" "httpd-filesystem" "httpd-tools" "mod_http2" "mod_ldap" "mod_session" "mod_ssl")))
     '("Removable"
       "A number of UBI images, including the Python UBI images, include <code>httpd</code> and related packages.  These packages may not be required by your application, even when running web services (eg. via Flask).  Consider removing these packages like so:
<pre>
RUN rpm -e httpd httpd-core httpd-devel httpd-filesystem httpd-tools mod_ldap mod_lua mod_session mod_ssl mod_auth_gssapi mod_http2
</pre>"))

    ((find cve '("CVE-2023-2222" "CVE-2019-1010022" "CVE-2022-3554" "CVE-2022-3555") :test 'equal)
     '("Ignorable"
       "This is a junk CVE rejected by upstream.  Consider a global exception policy for this CVE."))

    ((and (string= cve "CVE-2023-49569")
          (equal locations '("/usr/bin/oc" "github.com/go-git/go-git/v5-v5.3.0")))
     '("False Positive"
       "The scanner is detecting the use of a vulnerable go-git project version in <code>/usr/bin/oc</code>.  However, <code>oc</code> does not include the vulnerable parts of that project.  It only uses <code>go-git</code> string formatting code that is pulled in as a transitive dependency, and is not affected by this vulnerability.  Consider an exception policy for this CVE as it relates to the <code>oc</code> command."))

    ((and (find cve
                '("CVE-2024-23651" "CVE-2024-23652"
                  "CVE-2024-23653" "CVE-2024-23650") :test 'equal)
          (equal locations '("/usr/bin/oc" "github.com/moby/buildkit-v0.0.0-20181107081847-c3a857e3fca0")))
     '("False Positive"
       "The scanner is detecting the use of a vulnerable moby project version
in <code>/usr/bin/oc</code>.  However, <code>oc</code> only uses the
Dockerfile parsing code from moby's buildkit, and not include the
vulnerable buildkit code, therefore <code>oc</code> is not affected by this
vulnerability.  Consider an exception policy for this CVE as it
relates to the <code>oc</code> command."))

    ((equal components '("emacs-filesystem"))
     '("Ignorable"
       "This vulnerability was identified in the <code>emacs</code> project
source code.  Red Hat builds multiple packages from the
<code>emacs</code> project source code, some of which do not contain
the specific code that triggered this CVE.  However, Red Hat's policy
is to taint every binary RPM built from the vulnerable source package
with the same vulnerability.  In this specific case,
<code>emacs-filesystem</code> only contains empty directories, and no
software at all.  It is only installed as a dependency for other
packages that install
emacs lisp extensions, even when emacs itself is not installed.  Consider a global exception for this vulnerability when
<code>emacs</code> is not installed in your container image."))

    ((equal components '("kernel-headers"))
     '("Ignorable"
       "This vulnerability exists in the Linux <code>kernel</code>, but Red Hat's policy is to taint
every subpackage built from the vulnerable source package with the
same vulnerability.  In this case, however,
<code>kernel-headers</code> only contains C header files needed to
build software that interfaces with the kernel.  Consider a
global exception for this vulnerability."))

    ((equal components '("less"))
     '("Removable"
       "The <code>less</code> package is often only dragged into a container image as a dependency of <code>git-core</code>.  If this is the case for your image, consider removing <code>less</code> like so:
<pre>
RUN rpm -e --nodeps less
</pre>
When <code>less</code> is present, <code>git</code> will use <code>less</code> to page the
output of logs to a terminal for interactive use; something that is
not typically required in containerized applications.
When <code>less</code> is not present, <code>git</code> will just cat log output instead of paging it."))

    ((and (string= cve "CVE-2024-1233")
          (equal locations '("/opt/eap/bin/client/jboss-client.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/jboss/eap/wildfly-client-all/7.4.17.GA-redhat-00002/wildfly-client-all-7.4.17.GA-redhat-00002.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/wildfly/security/wildfly-elytron-realm-token/1.15.23.Final-redhat-00001/wildfly-elytron-realm-token-1.15.23.Final-redhat-00001.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/wildfly/security/wildfly-elytron/1.15.23.Final-redhat-00001/wildfly-elytron-1.15.23.Final-redhat-00001.jar"
                             "org.wildfly.security:wildfly-elytron-realm-token-1.15.23.Final-redhat-00001")))
     '("False Positive"
       "This is a false positive.  This issue was resolved in multiple components through <a href=\"https://access.redhat.com/errata/RHSA-2024:3559\">RHSA-2024:3559</a>, <a href=\"https://access.redhat.com/errata/RHSA-2024:3560\">RHSA-2024:3560</a>, and <a href=\"https://access.redhat.com/errata/RHSA-2024:3561\">RHSA-2024:3561</a>."))

    ((and (string= cve "CVE-2024-6409")
          (equal components '("openssh" "openssh-clients")))
     '("Ignorable & Removable"
       "This vulnerability was identified in the <code>openssh</code> project
source code.  Red Hat builds multiple packages from the
<code>openssh</code> project source code, some of which do not contain
the specific code that triggered this CVE.  However, Red Hat's policy
is to taint every binary RPM built from the vulnerable source package
with the same vulnerability.  In this specific case, the vulnerability lies in <code>sshd</code>, which is distributed in the <code>openssh-server</code> RPM.  This package is not installed in this container image.  Consider a global exception for this vulnerability when <code>openssh-server</code> is not installed in your container image.
<br>
Alternatively, you may consider removing the <code>openssh</code> and
<code>openssh-clients</code> from your container image.  These are
often only dragged into images as dependencies of
<code>git-core</code>.  You can safely remove these packages from your
image if this is the case and you are not using ssh-based
authentication with <code>git</code> (for instance, you may be using
token-based authentication).  Remove these packages like so:
<pre>
RUN rpm -e --nodeps openssh openssh-clients
</pre>"))

    ((equal components '("openssh" "openssh-clients"))
     '("Removable"
       "The <code>openssh</code> and <code>openssh-clients</code> are often only dragged
into container images as dependencies of <code>git-core</code>.  You
can safely remove these packages from your container image if this is
the case and you are not using ssh-based authentication with
<code>git</code> (for instance, you may be using token-based
authentication).  Remove these packages like so:
<pre>
RUN rpm -e --nodeps openssh openssh-clients
</pre>"))

    (t nil)))
