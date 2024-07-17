;;; report.lisp
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

(defpackage #:report
  (:use #:cl)
  (:export main))

(in-package :report)

(defparameter +scandy-db-filename+ "scandy.db")
(defvar *db* nil)

(defvar *image-name* nil)

(markup:enable-reader)

(defun get-db-connection ()
  (setf *db* (handler-case
                 (dbi:connect :sqlite3 :database-name +scandy-db-filename+)
               (error (e)
                      (trivial-backtrace:print-condition e t))))
  (log:info "Connected to database" *db*)

  (handler-case
      (progn
        ;; Create RH CVE table
        (dbi:do-sql *db* "CREATE TABLE IF NOT EXISTS rhcve (cve TEXT PRIMARY KEY, content TEXT)")
        ;; Create per-run vulnerability db
        (dbi:do-sql *db* "CREATE TABLE IF NOT EXISTS vulns (id TEXT, age INTEGER, components TEXT, severity TEXT, image TEXT)"))
    (error (e)
           (trivial-backtrace:print-condition e t)))

  (log:info "Validated databases")

  *db*)

(defclass vulnerabilty ()
  ((id :accessor id)
   (severity :accessor severity)
   (component :accessor component :initform nil)
   (title :accessor title :initform nil)
   (published-date :accessor published-date :initform nil)
   (description :accessor description :initform nil)
   (location :accessor location :initform nil)
   (references :accessor references :initform nil)))

(defclass grype-vulnerability (vulnerabilty)
  ())

(defclass trivy-vulnerability (vulnerabilty)
  (status))

(defclass redhat-vulnerability (vulnerabilty)
  ())

(defun get-component (vlist)
  (let ((cv (find-if (lambda (v) (component v)) vlist)))
    (if cv (component cv) "?")))

(defun capitalize-word (word)
  "Capitalize the first letter of WORD and make the rest lower-case."
  (when (and word (> (length word) 1))
    (concatenate 'string
                 (string-upcase (subseq word 0 1))
                 (string-downcase (subseq word 1)))))

(defun extract-cve (url)
  (let ((pattern "CVE-\\d{4}-\\d{4,7}$")) ; Regular expression pattern for CVE-YYYY-NNNN
    (multiple-value-bind (match start end)
        (cl-ppcre:scan-to-strings pattern url)
      (if match
          match
          nil))))

(defvar *ghsa-files* nil)

(defun grok-ghsa (vuln)
  (with-slots (id published-date references description) vuln
    (when (equal "GHSA-" (subseq id 0 5))
      (let ((ghsa (gethash id *ghsa-files*)))
        (when ghsa
          (let ((ghjson (json:decode-json-from-string (uiop:read-file-string ghsa))))
            (let ((pt (cdr (assoc :PUBLISHED ghjson))))
              (when pt
                (setf published-date (local-time:parse-timestring pt))))
            (let ((reference-list (cdr (assoc :REFERENCES ghjson))))
              (dolist (reference reference-list)
                (let ((url (cdr (assoc :URL reference))))
                  (when url
                    (progn
                      (push url references)
                      (if (and (assoc :TYPE reference) (string= (cdr (assoc :TYPE reference)) "ADVISORY"))
                          (progn
                            (let ((cveid (extract-cve url)))
                              (when cveid
                                (setf id cveid))))))))))
            (setf description (with-output-to-string (stream)
                                (3bmd:parse-string-and-print-to-stream
                                 (format nil "~A~%~%~A~%"
                                         (or (cdr (assoc :SUMMARY ghjson)) "")
                                         (or (cdr (assoc :DETAILS ghjson)) ""))
                                 stream)))))))))

(defun replace-newlines-with-br (input-string)
  "Replace newlines in INPUT-STRING with <br>."
  (with-output-to-string (out)
    (loop for char across input-string do
         (if (char= char #\Newline)
             (write-string "<br>" out)
             (write-char char out)))))

(defmethod initialize-instance ((vuln grype-vulnerability) &key json)
  "Initialize a grype-vulnerability from decoded json data."
  (call-next-method)
  (with-slots (id severity component location description references) vuln
    (setf id (cdr (assoc :ID (cdr (assoc :VULNERABILITY json)))))
    (grok-ghsa vuln)
    (unless description
      (setf description (cdr (assoc :DESCRIPTION (cdr (assoc :VULNERABILITY json))))))
    (setf component (cdr (assoc :NAME (cdr (assoc :ARTIFACT json)))))
    (if (not (string= "rpm" (cdr (assoc :TYPE (cdr (assoc :ARTIFACT json))))))
        (setf location
              (cdr (assoc :PATH (car (cdr (assoc :LOCATIONS (cdr (assoc :ARTIFACT json))))))))
        (setf location
              (format nil "~A-~A"
                      (cdr (assoc :NAME (cdr (assoc :ARTIFACT json))))
                      (cdr (assoc :VERSION (cdr (assoc :ARTIFACT json)))))))
    (setf severity (capitalize-word (cdr (assoc :SEVERITY (cdr (assoc :VULNERABILITY json))))))
    (setf references (append references (cdr (assoc :URLS (cdr (assoc :VULNERABILITY json))))))))

(defmethod initialize-instance ((vuln trivy-vulnerability) &key json)
  "Initialize a trivy-vulnerability from decoded json data."
  (call-next-method)
  (with-slots (id severity location published-date component title description references status) vuln
    (setf id (cdr (assoc :*VULNERABILITY-+ID+ json)))
    (grok-ghsa vuln)
    (setf severity (capitalize-word (cdr (assoc :*SEVERITY json))))
    (setf status (cdr (assoc :*STATUS json)))
    (setf title (cdr (assoc :*TITLE json)))
    (unless published-date
      (when (assoc :*PUBLISHED-DATE json)
        (setf published-date (local-time:parse-timestring (cdr (assoc :*PUBLISHED-DATE json))))))
    (unless description
      (setf description (cdr (assoc :*DESCRIPTION json))))
    (setf component (cdr (assoc :*PKG-NAME json)))
    (setf location
          (format nil "~A-~A" component (cdr (assoc :*INSTALLED-VERSION json))))
    (setf references (append references (cdr (assoc :*REFERENCES json))))))

(defmethod initialize-instance ((vuln redhat-vulnerability) &key json)
  "Initialize a redhat-vulnerability from decoded json data."
  (call-next-method)
  (with-slots (id severity published-date component description references title) vuln
    (setf id (cdr (assoc :NAME json)))
    (setf severity (capitalize-word (cdr (assoc :THREAT--SEVERITY json))))
    (setf description (replace-newlines-with-br (cl-who:escape-string (cadr (assoc :DETAILS json)))))
    (setf references (cdr (assoc :REFERENCES json)))
    (setf published-date (local-time:parse-timestring (cdr (assoc :PUBLIC--DATE json))))
    (setf title (cdr (assoc :DESCRIPTION (cdr (assoc :BUGZILLA json)))))))

(defmacro vuln-severity (vulns type)
  `(let ((v (find-if (lambda (v) (eq (type-of v) ,type)) ,vulns)))
     (when v (severity v))))

(defun grype-severity (vulns) (vuln-severity vulns 'grype-vulnerability))
(defun trivy-severity (vulns) (vuln-severity vulns 'trivy-vulnerability))
(defun redhat-severity (vulns) (vuln-severity vulns 'redhat-vulnerability))

(defun get-description (vulns)
  (let ((v (find-if (lambda (v) (eq (type-of v) 'redhat-vulnerability)) vulns)))
    (if v
        (description v)
      (let ((v (find-if (lambda (v) (eq (type-of v) 'trivy-vulnerability)) vulns)))
        (if v
            (description v)
          (let ((v (find-if (lambda (v) (eq (type-of v) 'grype-vulnerability)) vulns)))
            (description v)))))))

(defvar *ordered-vulns* nil)

(markup:deftag modals-template ()
  (markup:make-merge-tag
    (mapcar (lambda (vulns)
             <markup:merge-tag>
             <div class="modal fade" id=(format nil "~A-modal" (id (car vulns))) tabindex="-1" aria-labelledby=(format nil "~A-modalLabel" (id (car vulns))) aria-hidden="true">
             <div class="modal-dialog modal-lg">
             <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id=(format nil "~A-modalLabel" (id (car vulns))) > ,(progn *image-name*) </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                <h2>Security Advisory: ,(progn (id (car vulns))) </h2>
                <h3>Description:</h3> ,(markup:unescaped (get-description vulns))
                ,(progn (let ((locations (collect-locations vulns)))
                          (when locations
                            <markup:merge-tag>
                            <h3> Locations: </h3>
                            <ul>
                            ,@(mapcar (lambda (location)
                                        <li> ,(progn location) </li>)
                                      locations)
                            </ul>
                            </markup:merge-tag>
                            )))
                ,(progn (let ((opinion (get-opinion (id (car vulns)) (collect-components vulns) (collect-locations vulns) *image-name*)))
                          (when opinion
                            <markup:merge-tag>
                            <h3>Scandy Opinion: </h3>
                            ,(markup:unescaped (cadr opinion))
                            </markup:merge-tag>
                            )))
                <h3>References:</h3>
                <ul>
                <markup:merge-tag>
                ,@(mapcar (lambda (url)
                            <li><a href=url target="_blank"> ,(progn url) </a></li>)
                          (collect-references (id (car vulns)) vulns))
                </markup:merge-tag>
                </ul>
                </div>
                </div>
                </div>
                </div>
                </markup:merge-tag>)
            *ordered-vulns*)))

(markup:deftag page-template (children &key title index)
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="apple-touch-icon" sizes="180x180" href="https://raw.githubusercontent.com/atgreen/scandy/main/images/scandy-180x180.png">
    <link rel="icon" type="image/png" sizes="32x32" href="https://raw.githubusercontent.com/atgreen/scandy/main/images/scandy-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="https://raw.githubusercontent.com/atgreen/scandy/main/images/scandy-16x16.png">
    <meta name="msapplication-TileColor" content="#da532c">
    <meta name="theme-color" content="#ffffff">
    <title>scandy</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/buttons/1.7.1/css/buttons.dataTables.min.css">
    <style>
        body {
            padding-top: 65px;
            margin-bottom: 60px;
            font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
        }
        .navbar-brand {
            font-size: 1.5rem;
        }
        h1, h2 {
            margin: 20px 0;
        }
        table {
            width: 100%;
        }
        table th, table td {
            padding: .75rem;
            text-align: left;
            border: 1px solid #ddd;
        }
        .bg-critical {
            background-color: #ff4d4d;
            color: white;
        }
        .bg-low {
            background-color: #d4edda;
            color: #155724;
        }
        tbody tr:nth-child(odd) {
            background-color: #f9f9f9;
        }
        tbody tr:nth-child(even) {
            background-color: #ffffff;
        }
        tbody tr:hover {
            background-color: #f1f1f1;
        }
        .footer {
            background-color: #f5f5f5;
            padding: 20px 0;
        }
        .modal-body ul {
            padding-left: 20px;
        }
        .modal-body h3 {
            margin-top: 20px;
        }
        .dt-buttons {
            margin-bottom: 10px;
        }
        .filter-checkbox {
            margin-left: 10px;
            margin-bottom: 10px;
            display: inline-block;
        }
        .no-wrap {
            white-space: nowrap;
            word-break: keep-all;
            overflow-wrap: normal;
        }
  </style>
</head>
<body>
    <nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="https://atgreen.github.io/scandy/"><img src="https://raw.githubusercontent.com/atgreen/scandy/main/images/scandy-32x32.png" alt="" width="30" height="30"></a>
            <a class="navbar-brand" href="https://atgreen.github.io/scandy/">scandy</a>
        </div>
    </nav>
    <main class="container" role="main">
        <div class="row">
            <div class="col">
             ,@(progn children)
            </div>
        </div>
    </main>
    <footer class="footer">
        <div class="container">
             <div class="text-center py-3">&copy; 2024 <a href="https://linkedin.com/in/green">Anthony Green</a></div>
  <p>Scandy is an experiment by <a href="https://linkedin.com/in/green">Anthony Green</a>, the source code for which is available under the terms of the MIT license at <a href="https://github.com/atgreen/scandy">https://github.com/atgreen/scandy</a>.  Scandy 'opinions' are not comprehensive and in some cases may be incorrect.  Submit new opinions as pull requests, and questions or comments as <a href="https://github.com/atgreen/scandy/issues/new">github issues</a>.</p>
        </div>
    </footer>
    <modals-template>
    </modals-template>
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/1.7.1/js/dataTables.buttons.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.1.3/jszip.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/1.7.1/js/buttons.html5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/1.7.1/js/buttons.print.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.1.53/pdfmake.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.1.53/vfs_fonts.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.6/umd/popper.min.js" integrity="sha384-wHAiFfRlMFy6i5SRaxvfOCifBUQy1xHdJ/yoi7FRNXMRBu5WHdZYu1hA6ZOblgut" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>
    <script>
      var table;

        $(document).ready(function() {
            // Custom sorting for severity levels
            $.fn.dataTable.ext.type.order['severity-pre'] = function (d) {
                switch (d) {
                    case 'Critical': return 1;
                    case 'High': return 2;
                    case 'Important': return 2;
                    case 'Medium': return 3;
                    case 'Moderate': return 3;
                    case 'Low': return 4;
                    default: return 5;
                }
            };

            // Custom sorting for Age column
            $.fn.dataTable.ext.type.order['age-pre'] = function (d) {
                return d === '?' ? 999999 : parseInt(d, 10);
            };

            ,(progn
               (if (not (string= index "true"))
                   (progn
                     <markup:merge-tag>
                     table = $('#results').DataTable({
                                                     "paging": false,
                                                     "info": true,
                                                     "searching": true,
                                                     "order": [],
                                                     "columnDefs": [
                                                     { "type": "severity", "targets": [3, 4, 5] },
                                                     { "type": "age", "targets": [1] }
                                                     ],
                                                     dom: 'Bfrtip',
                                                     buttons: [
                                                     'copy', 'csv', 'pdf'
                                                     ]
                                                     });
                     </markup:merge-tag>)
                   (progn
                     <markup:merge-tag>
                     table = $('#results').DataTable({
                                                     "paging": false,
                                                     "info": true,
                                                     "searching": true,
                                                     "order": [[1,'asc']],
                                                     "columnDefs": [
                                                     { "type": "severity", "targets": [3] },
                                                     { "type": "age", "targets": [1] }
                                                     ],
                                                     dom: 'Bfrtip',
                                                     buttons: [
                                                     'copy', 'csv', 'pdf'
                                                     ]
                                                     });
                     </markup:merge-tag>)))

            $('[data-bs-toggle="tooltip"]').tooltip();
        });

        function filterSeverity(severity) {
            $('#results').DataTable().search(severity).draw();
        }

        var filterOn = true;

        $('#toggle-filter').on('click', function () {
                filterOn = !filterOn;
                table.draw();
            });

        $.fn.dataTable.ext.search.push(
                function(settings, data, dataIndex) {
                    if (!filterOn) {
                        return true;
                    }
                    return data[2] !== 'kernel-headers'; // 2 is the index of the Component column
                }
            );

          document.addEventListener('DOMContentLoaded', (event) => {
            // Get the server timestamp from the data attribute
            const serverTimestampElement = document.getElementById('server-timestamp');
            const serverTimestamp = serverTimestampElement.getAttribute('data-timestamp');

            // Convert server timestamp to local timezone
            const localDate = new Date(serverTimestamp);
            const options = {
                year: 'numeric', month: 'long', day: 'numeric',
                hour: '2-digit', minute: '2-digit', second: '2-digit',
                timeZoneName: 'short'
            };
            const localTimestamp = localDate.toLocaleString(undefined, options);

            // Display the local timestamp
            serverTimestampElement.textContent = `${localTimestamp}`;
        });
    </script>
</body>
</html> )

(defparameter +severity+ '("" "Unknown" "Low" "Medium" "Moderate" "High" "Important" "Critical"))

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
  "Order two references in our preferred order."
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
    ((or (search "bugzilla.redhat" r1)
         (search "bugzilla.redhat" r2))
     (search "bugzilla.redhat" r1))
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

(defun collect-locations (vulns)
  (let ((locations (loop for v in vulns
                         when (location v)
                           collect (location v))))
    (sort (remove-duplicates locations :test #'string-equal) 'string<)))

(defun collect-components (vulns)
  (let ((components (loop for v in vulns
                          when (component v)
                            collect (component v))))
    (sort (remove-duplicates components :test #'string-equal) 'string<)))

(defun get-redhat-security-data (cve-id)
  (let ((content (cadr (assoc :|content| (dbi:fetch-all (dbi:execute (dbi:prepare *db* "SELECT content from rhcve WHERE cve = ?")
                                                                     (list cve-id)))))))
    (when content
      (log:info "Found cached redhat security API response" cve-id))
    (if content
        content
      (handler-case
          (let ((rhj (dex:get (format nil "https://access.redhat.com/hydra/rest/securitydata/cve/~A" cve-id))))
            (dbi:do-sql *db*
                        "INSERT INTO rhcve (cve, content) VALUES (?, ?)"
                        (list cve-id rhj))
            (log:info "Caching redhat security API response" cve-id)
            rhj)
        (dex:http-request-not-found ()
            (format nil "Red Hat is not tracking ~A" cve-id))))))

(defun opinion-style (opinion)
  (if opinion
      "background-color: #daffb9; border-top: 1px solid #eee; border-bottom: 1px solid #eee;"
      "border-top: 1px solid #eee; border-bottom: 1px solid #eee;"))

(defun severity-style (severity)
  (cond
    ((equal severity "Critical")
     "background-color: #ffcccc; border-top: 1px solid #eee; border-bottom: 1px solid #eee;")
    ((or (equal severity "High") (equal severity "Important"))
     "background-color: #ffdab9; border-top: 1px solid #eee; border-bottom: 1px solid #eee;")
    ((or (equal severity "Medium") (equal severity "Moderate"))
     "background-color: #ffffcc; border-top: 1px solid #eee; border-bottom: 1px solid #eee;")
    (t "")))

(defun severity-class (severity)
  (cond
    ((equal severity "Critical")
     "severity-Critical")
    ((or (equal severity "High") (equal severity "Important"))
     "severity-High")
    ((or (equal severity "Medium") (equal severity "Moderate"))
     "severity-Medium")
    (t "")))

(defun main ()

  (let* ((vuln-table (make-hash-table :test 'equal))
         (report-filename (first (uiop:command-line-arguments)))
         (grype-filename (second (uiop:command-line-arguments)))
         (trivy-filename (third (uiop:command-line-arguments)))
         (image-name (fourth (uiop:command-line-arguments)))
         (grype-json
           (json:decode-json-from-string (uiop:read-file-string grype-filename)))
         (trivy-json
           (json:decode-json-from-string (uiop:read-file-string trivy-filename))))

    (setf *image-name* image-name)

    (setf *ghsa-files* (make-hash-table :test #'equal))

    (log:info "Scanning github security advisory database")
    (cl-fad:walk-directory "advisory-database/advisories/"
                           (lambda (f)
                             (setf (gethash (pathname-name f) *ghsa-files*) f)))

    (log:info "Establishing database connection")
    (get-db-connection)

    (log:info "STARTING ANALYSIS")

    ;; Go through grype results
    (let ((vulns (cdr (assoc :MATCHES grype-json))))
      (dolist (vuln-json vulns)
        (let ((vuln (make-instance 'grype-vulnerability :json vuln-json)))
          (push vuln (gethash (id vuln) vuln-table)))))

    ;; Go through trivy results
    (dolist (vgroup (cdr (assoc :*RESULTS trivy-json)))
      (let ((vulns (cdr (assoc :*VULNERABILITIES vgroup))))
        (dolist (vuln-json vulns)
          (let ((vuln (make-instance 'trivy-vulnerability :json vuln-json)))
            (push vuln (gethash (id vuln) vuln-table))))))

    ;; Create a Red Hat vulnerability record
    (maphash (lambda (id vulns)
               (handler-case
                   (push (make-instance 'redhat-vulnerability :json (json:decode-json-from-string (get-redhat-security-data id))) (gethash id vuln-table))
                 (error (e)
                   (trivial-backtrace:print-backtrace e :output *standard-output* :verbose t)
                   nil)))
             vuln-table)

    (log:info "SORTING VULNS" (hash-table-count vuln-table))

    (let ((ordered-vulns
            (let (vulns)
              (maphash (lambda (id vpair) (push vpair vulns)) vuln-table)
              (reverse (sort vulns 'vuln<)))))

      (setf *ordered-vulns* ordered-vulns)

      (with-open-file (stream report-filename :direction :output
                                              :if-exists :supersede
                                              :if-does-not-exist :create)
        (markup:write-html-to-stream
         <page-template title="scandy" index="false">
         <h1>,(progn image-name)</h1>
         <h2>With RPM updates as of <span id="server-timestamp" data-timestamp=(local-time:format-timestring nil (local-time:now) :format local-time:+rfc-1123-format+) > </span></h2>
         <div class="dt-buttons btn-group">
         <button class="btn" style="background-color: #bbbbbb; border: 1px solid #000" onclick="filterSeverity('')">All</button>
         <button class="btn" style="background-color: #ffcccc; border: 1px solid #000" onclick="filterSeverity('Critical')">Critical</button>
         <button class="btn" style="background-color: #ffdab9; border: 1px solid #000" onclick="filterSeverity('High')">High</button>
         <button class="btn" style="background-color: #ffffcc; border: 1px solid #000" onclick="filterSeverity('Medium')">Medium</button>
         <button class="btn" style="border: 1px solid #000" onclick="filterSeverity('Low')">Low</button>
         <div class="form-check filter-checkbox">
           <input class="form-check-input" type="checkbox" value="" id="toggle-filter">
           <label class="form-check-label" for="toggle-filter">
             Show kernel-headers
           </label>
         </div>
         </div>
         <table class="table table-hover" id="results" >
         <markup:merge-tag>
         <thead class="thead-dark" >
         <tr>
         <th>ID</th>
         <th>Age</th>
         <th>Component</th>
         <th>Trivy Severity</th>
         <th>Grype Severity</th>
         <th>Red Hat Severity</th>
         <th>Scandy Opinion</th>
         </tr>
         </thead>
         <tbody>
         ,@(mapcar (lambda (vulns)
                     (let ((opinion (get-opinion (id (car vulns)) (collect-components vulns) (collect-locations vulns) *image-name*)))
                       <markup:merge-tag>
                       <tr class=(severity-class (redhat-severity vulns)) data-bs-toggle="modal" data-bs-target=(format nil "#~A-modal" (id (car vulns))) >
                       <td class="no-wrap"> ,(id (car vulns)) </td>
                       <td> ,(let ((pdv (find-if (lambda (v) (published-date v)) vulns)))
                               (if pdv
                                   (let ((age (floor
                                               (/ (- (get-universal-time)
                                                     (local-time:timestamp-to-universal
                                                      (published-date pdv)))
                                                  (* 60.0 60.0 24.0)))))
                                     (dbi:do-sql *db*
                                       "INSERT INTO vulns (id, age, components, severity, image) VALUES (?, ?, ?, ?, ?)"
                                       (list (id (car vulns)) age (format nil "~{ ~A~}" (collect-components vulns)) (redhat-severity vulns) image-name))
                                     age)
                                   "?"))
                       </td>
                       <td> ,(format nil "~{~A ~}" (collect-components vulns)) </td>
                       <td style=(severity-style (trivy-severity vulns)) > ,(trivy-severity vulns) </td>
                       <td style=(severity-style (grype-severity vulns)) > ,(grype-severity vulns) </td>
                       <td style=(severity-style (redhat-severity vulns)) > ,(redhat-severity vulns) </td>
                       <td style=(opinion-style opinion) > ,(if opinion (car opinion) "") </td>
                       </tr>
                       </markup:merge-tag>
                       ))
                   ordered-vulns)
         </tbody>
         </markup:merge-tag>
         </table>
         </page-template>
         stream))))

  (dbi:disconnect *db*)

  (sb-ext:quit))

(defun make-index.html ()
  (let ((rows
          (let* ((connection (dbi:connect :sqlite3 :database-name +scandy-db-filename+))
                 (query (dbi:execute (dbi:prepare connection "SELECT id, age, components, severity, image FROM vulns WHERE age <= 7 ORDER BY age ASC"))))
            (unwind-protect
                 (loop for row = (dbi:fetch query)
                       while row
                       collect row)
              (dbi:disconnect connection)))))
    (let ((vulns (make-hash-table :test 'equal)))
      (dolist (row rows)
        (let* ((id (nth 1 row))
               (age (nth 3 row))
               (components (nth 5 row))
               (severity (nth 7 row))
               (image (nth 9 row)))
          (if (gethash id vulns)
              (push (list age components severity image) (gethash id vulns))
              (setf (gethash id vulns) (list (list age components severity image))))))

      (with-open-file (stream "index.html" :direction :output
                                           :if-exists :supersede
                                           :if-does-not-exist :create)
        (markup:write-html-to-stream
         <page-template title="scandy" index="true">
         <br>
         <h2>New CVEs from the last 7 days</h2>
         <div class="form-check filter-checkbox">
           <input class="form-check-input" type="checkbox" value="" id="toggle-filter">
           <label class="form-check-label" for="toggle-filter">
             Show kernel-headers
           </label>
         </div>
         <table class="table table-hover" id="results">
         <markup:merge-tag>
         <thead class="thead-dark" >
         <tr><th>ID</th><th>Age</th><th>Components</th><th>Red Hat Severity</th><th>Images</th></tr>
         </thead>
         <tbody>
         ,@(let ((rows))
             (maphash (lambda (id data-list)
                        (push
                         (progn
                           <markup:merge-tag>
                           <tr>
                           <td class="no-wrap"> ,(progn id) </td>
                           <td> ,(princ-to-string (first (car data-list))) </td>
                           <td> ,(progn (format nil "~{ ~A~}" (loop for data in data-list
                                                                    collect (second data))))
                           </td>
                           <td style=(severity-style (third (car data-list))) > ,(progn (third (car data-list))) </td>
                           <td> <ul>
                           ,@(mapcar (lambda (data)
                                       <markup:merge-tag>
                                       <li> <a href=(format nil "~A-with-updates.html"
                                                            (ppcre:regex-replace-all "/" (ppcre:regex-replace-all ":" (fourth data) "--") "--")) >
                                            ,(progn (fourth data)) </a> </li>
                                       </markup:merge-tag>)
                                     data-list)
                           </ul> </td>
                           </tr>
                           </markup:merge-tag>) rows))
                      vulns)
             (reverse rows))
         </tbody>
         </markup:merge-tag>
         </table>
         <br>
         <h2>Scanned image reports</h2>
         <table class="table table-hover">
         <thead class="thead-dark" >
         <tr><th>Technology</th><th>Images</th></tr>
         </thead>
         <tbody>
         <tr>
         <td>Base</td>
         <td>
         <ul>
         <li><a href="registry.access.redhat.com--ubi8-with-updates.html">registry.access.redhat.com/ubi8</a></li>
         <li><a href="registry.access.redhat.com--ubi9-with-updates.html">registry.access.redhat.com/ubi9</a></li>
         <li><a href="registry.access.redhat.com--ubi9-minimal-with-updates.html">registry.access.redhat.com/ubi9-minimal </a></li>
         <li><a href="registry.access.redhat.com--ubi8-minimal-with-updates.html">registry.access.redhat.com/ubi8-minimal </a></li>
         <li><a href="registry.access.redhat.com--ubi9-micro-with-updates.html">registry.access.redhat.com/ubi9-micro </a></li>
         <li><a href="registry.access.redhat.com--ubi8-micro-with-updates.html">registry.access.redhat.com/ubi8-micro </a></li>
         </ul></td></tr>
         <tr><td>OpenJDK</td><td><ul>
         <li><a href="registry.access.redhat.com--ubi8--openjdk-8-with-updates">registry.access.redhat.com/ubi8/openjdk-8</a></li>
         <li><a href="registry.access.redhat.com--ubi8--openjdk-21-with-updates">registry.access.redhat.com/ubi8/openjdk-21</a></li>
         <li><a href="registry.access.redhat.com--ubi9--openjdk-21-with-updates">registry.access.redhat.com/ubi9/openjdk-21</a></li>
         <li><a href="registry.redhat.io--ubi8--openjdk-8-runtime-with-updates">registry.redhat.io/ubi8/openjdk-8-runtime</a></li>
         <li><a href="registry.redhat.io--ubi8--openjdk-21-runtime-with-updates">registry.redhat.io/ubi8/openjdk-21-runtime</a></li>
         <li><a href="registry.redhat.io--ubi9--openjdk-21-runtime-with-updates">registry.redhat.io/ubi9/openjdk-21-runtime</a></li>
         </ul></td></tr>
         <tr><td>NodeJS</td><td><ul>
         <li><a href="registry.access.redhat.com--ubi9--nodejs-18-with-updates">registry.access.redhat.com/ubi9/nodejs-18</a></li>
         <li><a href="registry.access.redhat.com--ubi9--nodejs-20-with-updates">registry.access.redhat.com/ubi9/nodejs-20</a></li>
         </ul></td></tr>
         <tr><td>Python</td><td><ul>
         <li><a href="registry.access.redhat.com--ubi8--python-39-with-updates.html">registry.access.redhat.com/ubi8/python-39</a></li>
         <li><a href="registry.access.redhat.com--ubi8--python-311-with-updates.html">registry.access.redhat.com/ubi8/python-311</a></li>
         <li><a href="registry.access.redhat.com--ubi8--python-312-with-updates.html">registry.access.redhat.com/ubi8/python-312</a></li>
         <li><a href="registry.access.redhat.com--ubi9--python-39-with-updates.html">registry.access.redhat.com/ubi9/python-39</a></li>
         <li><a href="registry.access.redhat.com--ubi9--python-311-with-updates.html">registry.access.redhat.com/ubi9/python-311</a></li>
         <li><a href="registry.access.redhat.com--ubi9--python-312-with-updates.html">registry.access.redhat.com/ubi9/python-312</a></li>
         </ul></td></tr>
         <tr><td>EAP</td><td><ul>
         <li><a href="registry.redhat.io--jboss-eap-7--eap74-openjdk11-openshift-rhel8-with-updates.html">registry.redhat.io/jboss-eap-7/eap74-openjdk11-openshift-rhel8</a></li>
         <li><a href="registry.redhat.io--jboss-eap-7--eap74-openjdk11-runtime-openshift-rhel8-with-updates.html">registry.redhat.io/jboss-eap-7/eap74-openjdk11-runtime-openshift-rhel8</a></li>
         </ul></td></tr>
         <tr><td>.NET</td><td><ul>
         <li><a href="registry.redhat.io--ubi8--dotnet-80-with-updates.html">registry.redhat.io/ubi8/dotnet-80</a></li>
         <li><a href="registry.redhat.io--ubi8--dotnet-60-with-updates.html">registry.redhat.io/ubi8/dotnet-60</a></li>
         <li><a href="registry.redhat.io--ubi8--dotnet-80-runtime-with-updates.html">registry.redhat.io/ubi8/dotnet-80-runtime</a></li>
         <li><a href="registry.redhat.io--ubi8--dotnet-60-runtime-with-updates.html">registry.redhat.io/ubi8/dotnet-60-runtime</a></li>
         </ul></td></tr>
         <tr><td>Apps</td><td><ul>
         <li><a href="registry.redhat.io--ocp-tools-4--jenkins-rhel8--v4.12.0-1716801209-with-updates">registry.redhat.io/ocp-tools-4/jenkins-rhel8:v4.12.0-1716801209</a></li>
         <li><a href="registry.redhat.io--ocp-tools-4--jenkins-rhel8--v4.14.0-1716468091-with-updates">registry.redhat.io/ocp-tools-4/jenkins-rhel8:v4.14.0-1716468091</a></li>
         <li><a href="registry.redhat.io--ansible-automation-platform-24--ee-supported-rhel8-with-updates">registry.redhat.io/ansible-automation-platform-24/ee-supported-rhel8</a></li>
         </ul></td></tr></tbody></table>
         </page-template>
         stream))))
    (sb-ext:quit))
