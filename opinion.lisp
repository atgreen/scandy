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

    ((and (string= cve "CVE-2023-6236")
          (equal locations '("/opt/eap/bin/client/jboss-client.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/jboss/eap/wildfly-client-all/7.4.17.GA-redhat-00002/wildfly-client-all-7.4.17.GA-redhat-00002.jar"
                             "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/wildfly/security/wildfly-elytron/1.15.23.Final-redhat-00001/wildfly-elytron-1.15.23.Final-redhat-00001.jar"
                             "org.wildfly.security:wildfly-elytron-http-oidc-1.15.23.Final-redhat-00001")))
     '("False Positive"
       "This is a false positive. EAP 7.4 does not provide the vulnerable provider-url configuration option in its OIDC implementation and is not affected by this flaw."))

    ((and (or (string= cve "CVE=2023-5865") (string= cve "CVE-2023-44487"))
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
       "This is a false positive.  This h2 CVE was fixed in <a href=\"https://access.redhat.com/errata/RHSA-2022:4919\">RHSA-2022:4919</a>."))

    ((string= cve "CVE-2021-32256")
     '("Ignorable"
       "This is a junk CVE.  The upstream binutils project rejects this bug as a security issue, in accordance with <a href=\"https://sourceware.org/git/?p=binutils-gdb.git;a=blob_plain;f=binutils/SECURITY.txt;h=f16b0c9d7099150e0f116e9e681c424eea3915fe;hb=HEAD\">their security policy</a>."))

    ((and (string= cve "CVE-2022-40897") (equal locations '("/opt/app-root/lib/python3.9/site-packages/setuptools-53.0.0.dist-info/METADATA" "setuptools-53.0.0")))
     '("False Positive"
       "This is a false positive.  This container image contains a fixed
version of python-setuptools (see <a
href=\"https://access.redhat.com/errata/RHSA-2023:0952\">https://access.redhat.com/errata/RHSA-2023:0952</a>).
The scanner is not identifying the problem in this fixed copy of
python-setuptools because it can associate those files with the RPM
package that it knows contains the fix.  However, this container image
also contains a python virtual environment in
<code>/opt/app-root</code> that contains copies of those original
fixed source files.  The scanner is unable to correctly detect that
these copies came from Red Hat's fixed python-setuptools."))

    ((and (string= cve "CVE-2022-3509") (find "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/infinispan/protostream/protostream/4.3.6.Final-redhat-00001/protostream-4.3.6.Final-redhat-00001.jar" locations :test 'equal))
     '("False Positive"
       "This is a false positive.  While <code>protostream-4.3.6.Final-redhat-00001.jar</code> does contain certain class files from <code>protobuf-java-3.15.2</code>, it does not contain the class file with the vulnerability (<code>com.google.protobuf.TextFormat</code>)."))

    ((and (or (string= cve "CVE-2022-3171") (string= cve "CVE-2022-3510")) (find "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/infinispan/protostream/protostream/4.3.6.Final-redhat-00001/protostream-4.3.6.Final-redhat-00001.jar" locations :test 'equal))
     '("False Positive"
       "This is a false positive.  While <code>protostream-4.3.6.Final-redhat-00001.jar</code> does contain certain class files from <code>protobuf-java-3.15.2</code>, it does not contain the class file with the vulnerability (<code>com.google.protobuf.MessageReflection</code>)."))

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

    ((or (string= cve "CVE-2023-2222") (string= cve "CVE-2019-1010022"))
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
is to taint every subpackage built from the vulnerable source package
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
          (or (format t "***** CVE-2024-1223: ~A" locations) t)
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
is to taint every subpackage built from the vulnerable source package
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
