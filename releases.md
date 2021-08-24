# os-tests release notes  

## 0.0.37- 20210824  

- new case test_check_cpuusage_exception and test_check_memusage_exception for bz1956248 to catch abnormal high cpu and memory usage
- new case test_check_dmesg_nmi for bz1917824
- new case test_check_sys_modules_parameters for 1619602
- new case test_check_journalctl_denied for bz1978507
- new case test_check_journalctl_not_found for bz1855252
- new case test_check_journalctl_cannot for general log checking
- new case test_check_journalctl_unexpected for general log checking
- added msg_90~msg_96 to know log baseline data
- other minor fixes and enhancements

## 0.0.36 - 20210701  

- new case test_persistent_route for bz1971527
- new case test_check_systemd_analyze_verify_obsolete for bz1974108
- new case test_check_systemd_analyze_verify_deprecated_unsafe for bz1974184
- include ltp, blktests rpms within os-tests because not all system can access github
- enable auto_registration and disable manage_repos before checking
- enhanced check_log to accept multiple regex
- save code repo address in test debug log
- other minor fixes and enhancements
