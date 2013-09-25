;; -*-emacs-lisp-*-
;;
;; Emacs startup file, e.g.  /etc/emacs/site-start.d/50fail2ban-p2p.el
;; for the Debian fail2ban-p2p package
;;
;; Originally contributed by Nils Naumann <naumann@unileoben.ac.at>
;; Modified by Dirk Eddelbuettel <edd@debian.org>
;; Adapted for dh-make by Jim Van Zandt <jrv@debian.org>

;; The fail2ban-p2p package follows the Debian/GNU Linux 'emacsen' policy and
;; byte-compiles its elisp files for each 'emacs flavor' (emacs19,
;; xemacs19, emacs20, xemacs20...).  The compiled code is then
;; installed in a subdirectory of the respective site-lisp directory.
;; We have to add this to the load-path:
(let ((package-dir (concat "/usr/share/"
                           (symbol-name flavor)
                           "/site-lisp/fail2ban-p2p")))
;; If package-dir does not exist, the fail2ban-p2p package must have
;; removed but not purged, and we should skip the setup.
  (when (file-directory-p package-dir)
    (setq load-path (cons package-dir load-path))
    (autoload 'fail2ban-p2p-mode "fail2ban-p2p-mode"
      "Major mode for editing fail2ban-p2p files." t)
    (add-to-list 'auto-mode-alist '("\\.fail2ban-p2p$" . fail2ban-p2p-mode))))

