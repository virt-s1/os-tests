# os-tests release notes  

## 0.0.36 - 20210701  

- new case test_persistent_route for bz1971527
- new case test_check_systemd_analyze_verify_obsolete for bz1974108
- new case test_check_systemd_analyze_verify_deprecated_unsafe for bz1974184
- include ltp, blktests rpms within os-tests because not all system can access github
- enable auto_registration and disable manage_repos before checking
- enhanced check_log to accept multiple regex
- save code repo address in test debug log
- other minor fixes and enhancements
