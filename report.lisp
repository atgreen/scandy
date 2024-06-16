(asdf:load-system :cl-json)
(asdf:load-system :markup)
(asdf:load-system :cl-who)
(asdf:load-system :dexador)
(asdf:load-system :completions)
(asdf:load-system :local-time)
(asdf:load-system :dbi)
(asdf:load-system :ironclad)
(asdf:load-system :zs3)
(asdf:load-system :trivial-backtrace)
(asdf:load-system :log4cl)

(log:info "Loaded all systems")

(handler-case
    (progn
      (setf zs3:*credentials* (list (uiop:getenv "AWS_ACCESS_KEY")
                                    (uiop:getenv "AWS_SECRET_KEY")))

      (defvar *scandy-db* (fifth (uiop:command-line-arguments)))

      (unless (zs3:bucket-exists-p "scandy-db")
        (zs3:create-bucket "scandy-db"))
      (zs3:get-file "scandy-db" "scandy.db" *scandy-db*))

  (error (e)
    (trivial-backtrace:print-backtrace e)))

(log:info "Pulled scandy.db from S3 storage")

(markup:enable-reader)

;; Connect to SQLite database
(defvar *db* (dbi:connect :sqlite3 :database-name *scandy-db*))

(log:info "Connected to database" *db*)

;; Create RH CVE table
(dbi:do-sql *db* "
CREATE TABLE IF NOT EXISTS rhcve (
    cve TEXT PRIMARY KEY,
    content TEXT
)")

;; Create LLM cache
(dbi:do-sql *db* "
CREATE TABLE IF NOT EXISTS llm_cache (
    prompt_hash TEXT PRIMARY KEY,
    response TEXT
)")

(defclass vulnerabilty ()
  ((id :accessor id)
   (severity :accessor severity)
   (component :accessor component :initform nil)
   (title :accessor title :initform nil)
   (published-date :accessor published-date :initform nil)
   (description :accessor description :initform nil)
   (references :accessor references :initform nil)))

(defclass grype-vulnerability (vulnerabilty)
  ((location :accessor location :initform nil)))

(defclass trivy-vulnerability (vulnerabilty)
  (status))

(defclass redhat-vulnerability (vulnerabilty)
  ())

(defun get-component (vlist)
  (let ((cv (find-if (lambda (v) (component v)) vlist)))
    (if cv (component cv) "?")))

(defun capitalize-word (word)
  "Capitalize the first letter of WORD and make the rest lower-case."
  (concatenate 'string
               (string-upcase (subseq word 0 1))
               (string-downcase (subseq word 1))))

(defmethod initialize-instance ((vuln grype-vulnerability) &key json)
  (call-next-method)
  (with-slots (id severity component location description references) vuln
    (let ((gid (cdr (assoc :ID (cdr (assoc :VULNERABILITY json))))))
      (if (string= "CVE-" (subseq gid 0 4))
          (setf id gid)
          (let* ((related (cadr (assoc :RELATED-VULNERABILITIES json)))
                 (rid (cdr (assoc :ID related)))
                 (urls (cdr (assoc :URLS related))))
            (setf id (or rid gid))
            (setf references urls))))
    (setf description (cdr (assoc :DESCRIPTION (cdr (assoc :VULNERABILITY json)))))
    (setf component (cdr (assoc :NAME (cdr (assoc :ARTIFACT json)))))
    (when (not (string= "rpm" (cdr (assoc :TYPE (cdr (assoc :ARTIFACT json))))))
      (setf location
            (cdr (assoc :PATH (car (cdr (assoc :LOCATIONS (cdr (assoc :ARTIFACT json)))))))))
    (setf severity (capitalize-word (cdr (assoc :SEVERITY (cdr (assoc :VULNERABILITY json))))))
    (setf references (append references (cdr (assoc :URLS (cdr (assoc :VULNERABILITY json))))))))

(defmethod initialize-instance ((vuln trivy-vulnerability) &key json)
  (call-next-method)
  (with-slots (id severity published-date component title description references status) vuln
    (setf id (cdr (assoc :*VULNERABILITY-+ID+ json)))
    (setf severity (capitalize-word (cdr (assoc :*SEVERITY json))))
    (setf status (cdr (assoc :*STATUS json)))
    (setf title (cdr (assoc :*TITLE json)))
    (when (assoc :*PUBLISHED-DATE json)
      (setf published-date (local-time:parse-timestring (cdr (assoc :*PUBLISHED-DATE json)))))
    (setf description (cdr (assoc :*DESCRIPTION json)))
    (setf component (cdr (assoc :*PKG-NAME json)))
    (setf references (cdr (assoc :*REFERENCES json)))))

(defmethod initialize-instance ((vuln redhat-vulnerability) &key json)
  (call-next-method)
  (with-slots (id severity published-date component) vuln
    (setf id (cdr (assoc :NAME json)))
    (setf severity (capitalize-word (cdr (assoc :THREAT--SEVERITY json))))
    (setf references (cdr (assoc :REFERENCES json)))
    (setf published-date (local-time:parse-timestring (cdr (assoc :PUBLIC--DATE json))))
    (setf title (cdr (assoc :DESCRIPTION (cdr (assoc :BUGZILLA json)))))))

(defmethod llm-context ((vuln vulnerabilty))
  (if (string= (component vuln) "kernel-headers")
      "This vulnerability is unlikely to be relevant for this container
image, as it is associated with the kernel-headers package.  Kernel
 CVEs taint the kernel-headers package when the real vulnerability
 exists in the host kernel, not the container image."
      ""))

(defmethod llm-context ((vuln redhat-vulnerability))
  (call-next-method)
  (with-output-to-string (stream)
    (when (title vuln)
      (format stream "Title: ~A.~%" (title vuln)))
    (when (description vuln)
      (format stream "Description: ~A.~%" (description vuln)))
    (when (component vuln)
      (format stream "Component: ~A.~%" (component vuln)))
    (format stream "Red Hat assigned this vulnerability a severity of ~A. ~%" (severity vuln))))

(defmethod llm-context ((vuln grype-vulnerability))
  (call-next-method)
  (with-output-to-string (stream)
    (when (title vuln)
      (format stream "Title: ~A.~%" (title vuln)))
    (when (description vuln)
      (format stream "Description: ~A.~%" (description vuln)))
    (when (component vuln)
      (format stream "Component: ~A.~%" (component vuln)))
    (when (location vuln)
      (format stream "The grype container scanner believes that this vulnerability exists at this location: ~A.~%"
              (location vuln)))
    (format stream "The grype container scanner believes the severity for this vulnerability is ~A. ~%"
            (severity vuln))))

(defmethod llm-context ((vuln trivy-vulnerability))
  (call-next-method)
  (with-output-to-string (stream)
    (when (title vuln)
      (format stream "Title: ~A.~%" (title vuln)))
    (when (description vuln)
      (format stream "Description: ~A.~%" (description vuln)))
    (when (component vuln)
      (format stream "Component: ~A.~%" (component vuln)))
    (format stream "The trivy container scanner believes the severity for this vulnerability is ~A. ~%"
            (severity vuln))))

(defun grype-severity (vulns)
  (let ((v (find-if (lambda (v) (eq (type-of v) 'grype-vulnerability)) vulns)))
    (when v (severity v))))

(defun trivy-severity (vulns)
  (let ((v (find-if (lambda (v) (eq (type-of v) 'trivy-vulnerability)) vulns)))
    (when v (severity v))))

(defun redhat-severity (vulns)
  (let ((v (find-if (lambda (v) (eq (type-of v) 'redhat-vulnerability)) vulns)))
    (when v (severity v))))

(markup:deftag page-template (children &key title)
   <html>
     <head>
       <meta charset="utf-8" />
       <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
       <link sizes="180x180" rel="apple-touch-icon" href="images/apple-touch-icon.png" />
       <link sizes="32x32" rel="icon" type="image/png" href="images/favicon-32x32.png" />
       <link sizes="16x16" rel="icon" type="image/png" href="images/favicon-16x16.png" />
       <link rel="manifest" href="images/site.webmanifest" />
       <link rel="mask-icon" href="images/safari-pinned-tab.svg" />
       <meta name="msapplication-TileColor" content="#da532c" />
       <meta name="theme-color" content="#ffffff" />
       <title>,(progn title)</title>
  <style>
@import url("https://netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css");

* {
    font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
    box-sizing: border-box;
}

html {
    position: relative;
    min-height: 100%;
}

body {
    padding-top: 65px;
    margin-bottom: 60px;
}

h1 {
  position: relative;
  bottom: 18px;
  left: 10px;
}

pre {
    display: block;
    padding: 9.5px;
    margin: 0 0 10px;
    font-size: 13px;
    line-height: 1.42857143;
    color: #333;
    word-break: break-all;
    word-wrap: break-word;
    background-color: #f5f5f5;
    border: 1px solid #ccc;
    border-radius: 4px;
    box-shadow: 2px 2px 3px 0px black;
}

table {
    border-collapse: collapse;
    border: 1px solid #ddd;
    width: 75%;
}

table th {
    text-align: left;
    border-bottom: 1px solid #ccc;
}

table th, table td {
    padding: .4em;
}

table.fold-table > tbody > tr.view td,
table.fold-table > tbody > tr.view th {
    cursor: pointer;
}

table.fold-table > tbody > tr.view td:first-child,
table.fold-table > tbody > tr.view th:first-child {
    position: relative;
    padding-left: 20px;
}

table.fold-table > tbody > tr.view td:first-child:before,
table.fold-table > tbody > tr.view th:first-child:before {
    position: absolute;
    top: 50%;
    left: 5px;
    width: 9px;
    height: 16px;
    margin-top: -8px;
    font: 16px fontawesome;
    color: #999;
    content: "\f0d7";
    transition: all .3s ease;
}

table.fold-table > tbody > tr.view:nth-child(4n-1) {
    background: #eee;
}

table.fold-table > tbody > tr.view:hover {
    background: #aaa;
}

table.fold-table > tbody > tr.fail {
    background: #ffb3b3
}

table.fold-table > tbody > tr.xfail {
    background: #e6f6e6
}

table.fold-table > tbody > tr.pass {
    background: #80ff80
}

/*
table.fold-table > tbody > tr.view.open {
    background: tomato;
    color: white;
}
*/

table.fold-table > tbody > tr.view.open td:first-child:before, table.fold-table > tbody > tr.view.open th:first-child:before {
    transform: rotate(-180deg);
    color: #333;
}

table.fold-table > tbody > tr.fold {
    display: none;
}

table.fold-table > tbody > tr.fold.open {
    display: table-row;
}

.fold-content {
    padding: .5em;
}

.fold-content h3 {
    margin-top: 0;
}

.fold-content > table {
    border: 12px solid #ccc;
}

tr:nth-child(4n-2) {
    background: #eee;
}

.no-wrap {
  white-space: nowrap;
  word-break: keep-all;
  overflow-wrap: normal;
}

.footer {
  position: absolute;
  bottom: 0;
  width: 100%;
  /* Set the fixed height of the footer here */
  height: 120px;
  line-height: 60px; /* Vertically center the text there */
  background-color: #f5f5f5;
}

.footer > .container {
    padding-right: 15px;
    padding-left: 15px;
}

code {
  font-size: 80%;
}
  </style>
       <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css"
	     integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC"
	     crossorigin="anonymous" />
       <script src="https://cdnjs.cloudflare.com/ajax/libs/prefixfree/1.0.7/prefixfree.min.js" ></script>
     </head>
     <header>
       <nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
         <div class="container-fluid" style="margin-left: 1rem; margin-right: 1rem;">
           <a class="navbar-brand" href="https://github.com/atgreen/scandy">scandy</a>
         </div>
       </nav>
     </header>
     <body>
       <main class="container" role="main">
         <div class="row" >
           <div class="col" >
             ,@(progn children)
             <hr/>
             Scandy is brought to you by Anthony Green <a href="mailto:green@moxielogic.com" >&lt;green@moxielogic.com&gt</a>
             and is available in source form under the terms of the MIT license from
             <a href="https://github.com/atgreen/scandy" > https://github.com/atgreen/scandy</a>.
           </div>
         </div>
       </main>
     </body>
     <footer class="page-footer font-small
                    special-color-dark pt-4">
       <div class="footer-copyright
                   text-center py-3">(C) 2024<a href="https://linkedin.com/in/green" > Anthony Green</a></div>
     </footer>
     <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"
             integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo"
             crossorigin="anonymous" ></script>
     <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.6/umd/popper.min.js"
             integrity="sha384-wHAiFfRlMFy6i5SRaxvfOCifBUQy1xHdJ/yoi7FRNXMRBu5WHdZYu1hA6ZOblgut"
             crossorigin="anonymous" ></script>
     <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"
	     integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
  crossorigin="anonymous" ></script>
  <script>
  $(function(){
            $(".fold-table tr.view").on("click", function(){
                                                 $(this).toggleClass("open").next(".fold").toggleClass("open");
                                                 });
            });
  </script>
  </html>)

(defconstant +severity+ '("Unknown" "Low" "Medium" "Moderate" "High" "Important" "Critical"))

(defun vuln< (v1 v2)
  "Sort vulnerabilities."
  (let ((v1 (find-if (lambda (v) (eq (type-of v) 'trivy-vulnerability)) v1))
        (v2 (find-if (lambda (v) (eq (type-of v) 'trivy-vulnerability)) v2)))
    (let ((id1 (and v1 (id v1)))
          (id2 (and v2 (id v2))))
      (cond
        ((or (null v1) (null v2))
         v2)
        ((or (null (severity v1)) (null (severity v2)))
         (severity v2))
        ((not (equal (severity v1) (severity v2)))
         (< (position (severity v1) +severity+ :test 'string=)
            (position (severity v2) +severity+ :test 'string=)))
        ((not (string= (subseq id1 0 8) (subseq id2 0 8)))
         (string< id1 id2))
        ((and (position #\- id1) (position #\- id2))
         (let ((n1 (parse-integer (subseq id1 (1+ (position #\- id1 :from-end t)))))
               (n2 (parse-integer (subseq id2 (1+ (position #\- id2 :from-end t))))))
           (< n1 n2)))
        (t
         (string< id1 id2))))))

(defun reference< (r1 r2)
  (cond
    ((or (search "access.redhat.com/security/cve" r1)
         (search "access.redhat.com/security/cve" r2))
     (search "access.redhat.com/security/cve" r1))
    ((or (search "access.redhat.com/errata" r1)
         (search "access.redhat.com/errata" r2))
     (search "access.redhat.com/errata" r1))
    ((or (search "nist.gov" r1)
         (search "nist.gov" r2))
     (search "nist.gov" r1))
    ((or (search "cve.org" r1)
         (search "cve.org" r2))
     (search "cve.org" r1))
    ((or (search "bugzilla" r1)
         (search "bugzilla" r2))
     (search "bugzilla" r1))
    ((or (search "fedora" r1)
         (search "fedora" r2))
     (search "fedora" r1))
    (t (string< r1 r2))))

(defun collect-references (id vulns)
  ;; Force the redhat CVE link because sometimes it's missing from the
  ;; metadata we pull.
  (let ((refs (when (string= "CVE-" (subseq id 0 4))
                (list (format nil "https://access.redhat.com/security/cve/~A" id)))))
    (loop for v in vulns
          do (setf refs (append refs (references v))))
    (sort (remove-duplicates refs :test #'string-equal) 'reference<)))

(defun collect-components (vulns)
  (let ((components (loop for v in vulns
                          when (component v)
                            collect (component v))))
    (sort (remove-duplicates components :test #'string-equal) 'string<)))

(defun describe-container (image)
  (cond
    ((search "ubi8" image)
     "RHEL 8")
    ((search "rhel8" image)
     "RHEL 8")
    ((search "ubi9" image)
     "RHEL 9")
    ((search "rhel9" image)
     "RHEL 9")
    (t
     image)))

(defvar *count* 11)

(defun get-redhat-security-data (cve-id)
  (let ((content (cadr (assoc :|content| (dbi:fetch-all (dbi:execute (dbi:prepare *db* "SELECT content from rhcve WHERE cve = ?")
                                                                     (list cve-id)))))))
    (when content
      (log:info "Found cached redhat security API response" cve-id))
    (if content
        content
        (let ((rhj (dex:get (format nil "https://access.redhat.com/hydra/rest/securitydata/cve/~A" cve-id))))
          (dbi:do-sql *db*
            "INSERT INTO rhcve (cve, content) VALUES (?, ?)"
            (list cve-id rhj))
          (log:info "Caching redhat security API response" cve-id)
          rhj))))

(defun string-digest (string)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence :md5
                             (babel:string-to-octets string
                                                     :encoding :utf-8))))

(defun get-llm-response (prompt)
  (let* ((md5 (string-digest prompt))
         (response (cadr (assoc :|response|
                                (dbi:fetch-all
                                 (dbi:execute
                                  (dbi:prepare *db* "SELECT response from llm_cache WHERE prompt_hash = ?")
                                  (list md5)))))))
    (when response
      (log:info "Found cached LLM response" prompt-hash))
    (or response
        (let ((completer (make-instance 'completions:openai-completer
                                        :model "gpt-4o"
                                        :api-key (uiop:getenv "LLM_API_KEY"))))
          (let ((text (completions:get-completion completer prompt)))
            (log:info "LLM response" text)
            (dbi:do-sql *db*
              "INSERT INTO llm_cache (prompt_hash, response) VALUES (?, ?)"
              (list md5 text))
            text)))))

(defun format-llm-context (stream vuln a b)
  (format stream "~A" (llm-context vuln)))

(defun get-analysis (id image vulns)
  (when (eq 0 *count*)
    (return-from get-analysis))
  (decf *count*)
  (handler-case
      (let ((prompt (format nil "
You are a cyber security analyst.  My ~A container image was
flagged with a CVE.  Respond with a short description of this
CVE, and a risk assessment for containers based on this image.
Respond in HTML format suitable for including directly in a <div>
section.

Don't include references.  Don't include container specific
considerations. Rate the impact for the version of Linux being used.
Do not wrap the HTML text in ```.  Here is an excellent example of
what I expect,  but be sure to replace CVE-2021-3991 with the ID of the
actual vulnerability:

  <h2>Security Advisory: CVE-2021-3997</h2>
  <p><strong>Description:</strong> CVE-2021-3997 is a vulnerability in <code>systemd</code> related to uncontrolled recursion in <code>systemd-tmpfiles</code>. This flaw may lead to a denial of service (DoS) at boot time when too many nested directories are created in <code>/tmp</code>. This can cause the system to exhaust its stack and crash. For more details, refer to the <a href=\"https://bugzilla.redhat.com/show_bug.cgi?id=2024639\" target=\"_blank\">Red Hat Bugzilla entry</a>.</p>

  <h3>Risk Assessment:</h3>
  <ul>
    <li><strong>Red Hat Enterprise Linux 8 Impact:</strong> Rated as low due to the default 1024 nofile limit, which prevents <code>systemd-tmpfiles</code> from exhausting its stack and crashing.</li>
    <li><strong>Mitigations:</strong> No direct mitigation provided by Red Hat. Regular updates and adherence to best practices for container security are recommended.</li>
  </ul>

  <h3>Fix state: Will not fix</h3>

If the context below includes location information, mention that location in your assessment.

Here's some data for context.  Note that it includes the vulnerability ID that you
should use in your risk assessment.  Also, you only need to provide a risk assessment
that's relevant for my ~A container image.  So, for instance, if I have a RHEL 9 container image,
don't mention RHEL 8.  Here's the context for your analysis:

~A~%

~{ ~/format-llm-context/ ~}~%" (describe-container image) (describe-container image) (get-redhat-security-data id) vulns)))
        (print prompt)
        (get-llm-response prompt))
    (error (e)
      (trivial-backtrace:print-condition e t)
      nil)))

(defun severity-style (severity)
  (cond
    ((equal severity "Critical")
     "background-color: #ffcccc; border-top: 1px solid #eee;  border-bottom: 1px solid #eee;")
    ((or (equal severity "High") (equal severity "Important"))
     "background-color: #ffdab9; border-top: 1px solid #eee;  border-bottom: 1px solid #eee;")
    ((or (equal severity "Medium") (equal severity "Moderate"))
     "background-color: #ffffcc; border-top: 1px solid #eee;  border-bottom: 1px solid #eee;")
    (t "")))

(let* ((vuln-table (make-hash-table :test 'equal))
       (report-filename (first (uiop:command-line-arguments)))
       (grype-filename (second (uiop:command-line-arguments)))
       (trivy-filename (third (uiop:command-line-arguments)))
       (image-name (fourth (uiop:command-line-arguments)))
       (grype-json
         (json:decode-json-from-string (uiop:read-file-string grype-filename)))
       (trivy-json
         (json:decode-json-from-string (uiop:read-file-string trivy-filename))))

  (log:info "STARTING ANALYSIS")

  (let ((vulns (cdr (assoc :MATCHES grype-json))))
    (dolist (vuln-json vulns)
      (let ((vuln (make-instance 'grype-vulnerability :json vuln-json)))
        (push vuln (gethash (id vuln) vuln-table)))))

  (let ((vulns (cdr (assoc :*VULNERABILITIES (car (cdr (assoc :*RESULTS trivy-json)))))))
    (dolist (vuln-json vulns)
      (let ((vuln (make-instance 'trivy-vulnerability :json vuln-json)))
        (push vuln (gethash (id vuln) vuln-table)))))

  ;; Create a Red Hat vulnerability record
  (maphash (lambda (id vulns)
             (handler-case
                 (let* ((rhj (get-redhat-security-data id))
                        (rhl (json:decode-json-from-string rhj)))
                   (push (make-instance 'redhat-vulnerability :json rhl) (gethash id vuln-table)))
               (error (e)
                 (trivial-backtrace:print-condition e t)
                 nil)))
           vuln-table)

  (log:info "SORTING VULNS" (hash-table-count vuln-table))

  (let ((ordered-vulns
          (let (vulns)
            (maphash (lambda (id vpair) (push vpair vulns)) vuln-table)
            (reverse (sort vulns 'vuln<)))))

    (with-open-file (stream report-filename :direction :output
                                            :if-exists :supersede
                                            :if-does-not-exist :create)
      (markup:write-html-to-stream
       <page-template title="scandy">
       <br>
       <h1>,(progn image-name)</h1>
       <h2>With updates as of ,(local-time:format-timestring nil (local-time:now) :format local-time:+rfc-1123-format+) </h2>
       <br>
       <table class="fold-table" id="results">
       <markup:merge-tag>
       <tr><th>ID</th><th>Age</th><th>Component</th><th>Trivy Severity</th><th>Grype Severity</th><th>Red Hat Severity</th></tr>
       ,@(mapcar (lambda (vulns)
                   <markup:merge-tag>
                   <tr class="view"><td class="no-wrap"> ,(id (car vulns)) </td><td>
                   ,(let ((pdv (find-if (lambda (v) (published-date v)) vulns)))
                      (if pdv
                          (floor
                           (/ (- (get-universal-time)
                                 (local-time:timestamp-to-universal
                                  (published-date pdv)))
                              (* 60.0 60.0 24.0)))
                          "?"))
                   </td><td>,(format nil "~{~A ~}" (collect-components vulns))</td><td style=(severity-style (trivy-severity vulns)) > ,(trivy-severity vulns) </td><td style=(severity-style (grype-severity vulns)) > ,(grype-severity vulns) </td><td style=(severity-style (redhat-severity vulns)) > ,(redhat-severity vulns) </td> </tr>
                   <tr class="fold"><td colspan="6">
                   <div>
                   <div>
                   ,(progn (markup:unescaped (or (get-analysis (id (car vulns)) image-name vulns) "")))
                   </div>
                   <h3>References:</h3>
                   <ul>
                   <markup:merge-tag>
                   ,@(mapcar (lambda (url)
                               <li><a href=url target="_blank"> ,(progn url) </a></li>)
                             (collect-references (id (car vulns)) vulns))
                   </markup:merge-tag>
                   </ul>
                   </div>
                   </td></tr>
                   </markup:merge-tag>
                   )
                 ordered-vulns)
       </markup:merge-tag>
       </table>
       </page-template>
       stream))))

(dbi:disconnect *db*)

(zs3:put-file *scandy-db* "scandy-db" "scandy.db")

(log:info "Pushed scandy.db from S3 storage")

(sb-ext:quit)
