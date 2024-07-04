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

(defun get-opinion (cve components)
  (cond
    ((equal components '("emacs-filesystem"))
     '("Ignoreable"
       "This vulnerability exists in <code>emacs</code>, but Red Hat's policy is to taint
every subpackage built from the vulnerable source package with the
same vulnerability.  In this case, however,
<code>emacs-filesystem</code> only contains empty directories, and no
software.  It is installed as a dependency for packages that install
emacs lisp extensions, even when emacs itself is not installed.
Consider a global exception for this vulnerability when
<code>emacs</code> is not installed in your container image."))

    ((equal components '("kernel-headers"))
     '("Ignoreable"
       "This vulnerability exists in the Linux <code>kernel</code>, but Red Hat's policy is to taint
every subpackage built from the vulnerable source package with the
same vulnerability.  In this case, however,
<code>kernel-headers</code> only contains C header files needed to
build software that interfaces with the kernel.  Consider a
global exception for this vulnerability."))

    ((equal components '("less"))
     '("Removeable"
       "The <code>less</code> package is often only dragged into a container image as a dependency of <code>git-core</code>.  If this is the case for your image, consider removing <code>less</code> like so:
<pre>
RUN rpm -e --nodeps less
</pre>
When present, <code>git</code> will use <code>less</code> to page the output of logs to a terminal for interactive use; something that is not typically required in containerized applications.  <code>git</code> will just cat log output instead of paging it once <code>less</code> is removed."))

    ((equal components '("openssh" "openssh-clients"))
     '("Removeable"
       "The <code>openssh</code> and <code>openssh-clients</code> are often only dragged
into container images as dependencies of <code>git-core</code>.  You can safely remove
these packages from your container image if this is the case and you are not using ssh-based authentication with <code>git</code> (for instance, you may be using token-based authentication).  Remove these packages like so:
<pre>
RUN rpm -e --nodeps openssh openssh-clients
</pre>"))

    (t nil)))
