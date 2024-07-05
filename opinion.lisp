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

(defun get-opinion (cve components locations)
  (cond

    ((and (string= cve "CVE-2022-3509") (find "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/infinispan/protostream/protostream/4.3.6.Final-redhat-00001/protostream-4.3.6.Final-redhat-00001.jar" locations :test 'equal))
     '("False Positive"
       "This is a false positive.  While <code>protostream-4.3.6.Final-redhat-00001.jar</code> does contain certain class files from <code>protobuf-java-3.15.2</code>, it does not contain the class file with the vulnerability (<code>com.google.protobuf.TextFormat</code>)."))

    ((and (string= cve "CVE-2022-3171") (find "/opt/jboss/container/wildfly/s2i/galleon/galleon-m2-repository/org/infinispan/protostream/protostream/4.3.6.Final-redhat-00001/protostream-4.3.6.Final-redhat-00001.jar" locations :test 'equal))
     '("False Positive"
       "This is a false positive.  While <code>protostream-4.3.6.Final-redhat-00001.jar</code> does contain certain class files from <code>protobuf-java-3.15.2</code>, it does not contain the class file with the vulnerability (<code>com.google.protobuf.MessageReflection</code>)."))

    ((string= cve "CVE-2023-2004")
     '("Ignorable"
       "This is a junk CVE that is not a security issue and was withdrawn by its CNA.  Consider a global exception policy for this CVE."))

    ((equal components '("httpd" "httpd-core" "httpd-devel" "httpd-filesystem" "httpd-tools" "mod_ldap" "mod_lua" "mod_session" "mod_ssl"))
     '("Removable"
       "A number of UBI images, including the Python UBI images, include <code>httpd</code> and related packages.  These packages may not be required by your application, even when running web services (eg. via Flask).  Consider removing these packages like so:
<pre>
RUN rpm -e httpd httpd-core httpd-devel httpd-filesystem httpd-tools mod_ldap mod_lua mod_session mod_ssl mod_auth_gssapi mod_http2
</pre>"))

    ((or (string= cve "CVE-2023-2222") (string= cve "CVE-2019-1010022"))
     '("Ignorable"
       "This is a junk CVE rejected by upstream.  Consider a global exception policy for this CVE."))

    ((and (string= cve "CVE-2024-23652")
          (equal locations '("/usr/bin/oc" "github.com/moby/buildkit-v0.0.0-20181107081847-c3a857e3fca0")))
     '("Ignorable"
       "The scanner is detecting the use of the vulnerable buildkit project version in <code>/usr/bin/oc</code>.  However, <code>oc</code> does not include the vulnerable parts of buildkit and is not affected by this vulnerability.  Consider an exception policy for this CVE as it relates to the <code>oc</code> command."))

    ((equal components '("emacs-filesystem"))
     '("Ignorable"
       "This vulnerability exists in <code>emacs</code>, but Red Hat's policy is to taint
every subpackage built from the vulnerable source package with the
same vulnerability.  In this case, however,
<code>emacs-filesystem</code> only contains empty directories, and no
software.  It is installed as a dependency for packages that install
emacs lisp extensions, even when emacs itself is not installed.
Consider a global exception for this vulnerability when
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
When present, <code>git</code> will use <code>less</code> to page the output of logs to a terminal for interactive use; something that is not typically required in containerized applications.  <code>git</code> will just cat log output instead of paging it once <code>less</code> is removed."))

    ((equal components '("openssh" "openssh-clients"))
     '("Removable"
       "The <code>openssh</code> and <code>openssh-clients</code> are often only dragged
into container images as dependencies of <code>git-core</code>.  You can safely remove
these packages from your container image if this is the case and you are not using ssh-based authentication with <code>git</code> (for instance, you may be using token-based authentication).  Remove these packages like so:
<pre>
RUN rpm -e --nodeps openssh openssh-clients
</pre>"))

    (t nil)))
