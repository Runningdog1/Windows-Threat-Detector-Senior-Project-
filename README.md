decrypt_audit_log_to_json.py -> Decryption Code

detections_decrypted.jsonl -> Decrypted Audit Log Sample

eventlog_detector.py -> Main Detection/Alert Code



Window’s Event Log Threat Detector
A Python-based cybersecurity tool that monitors and detects suspicious Windows Event Log activity in real-time. It continuously analyzes system logs for critical security events such as repeated failed login attempts, unauthorized account creations or deletions, privilege escalations, and the execution of non-whitelisted processes. The tool uses PowerShell for event retrieval, Python for rule-based detection logic, and AES-256 encryption to securely store all alerts in an encrypted audit log.

Features:
●	Developed entirely in Python 3.12, consisting of modules for encryption, subprocess control, and log parsing.
●	Real-time monitoring with PowerShell and JSONL output.
●	Detection of Window Security Events (1102, 4625, 4720, 4726, 4728, 4672, 4663, 4688, 4697, 4723, 4724).
●	AES-256-encrypted audit log for secure alert storage.
●	Supports decrypting and viewing full alert history with decrypt_audit_log_to_json.py

Known Issues and Limitations:
●	Currently only supports Windows 11.
●	Must be in Administrator Mode for event access.
●	Only supports English-language Windows event log messages.
●	No automatic log rotation available, the encrypted audit log (detections.log.enc) will continue to grow until manually cleared.
●	AES-256 encryption key (audit_key.bin) must remain in the same directory as the detector; relocation causes decryption errors.

Event ID’s Involved: 
1102: Security Log Cleared
4625: Failed Logins 
4720: Account Created * 
4728: User Added to Security Group *
4726: Account Deleted
4672: Privilege Escalation
4688: Non-Whitelisted Process Creation
4663: Mass File Activity
4697: Service Installed
4723: Password Change
4724: Password Reset 

How to Start/Stop Detector in Window’s Powershell:
1. Open Window’s Powershell as Administrator (Run as administrator)
2. Run the following commands:
cd "C:\Users\Chase McCrary\Downloads\EventLogDetector2"
py -3.12 eventlog_detector.py
3. Stop detector using (Ctrl+C)

NOTE: Directory paths will not be the same as mine. When running commands be sure to write the correct file path that is present on your system.

How to Trigger Event ID’s for Detector:
1102: Security Log Cleared                                                                           
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Event Viewer
3. Expand “Windows Logs” grouping on left pane
4. Click on Security under Windows Logs
5. On right pane, click “Clear Log…”
6. Select “Clear” in pop-up prompt
6. Observe Security Log Cleared Alert by the detector



4625: Failed Logins 
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Additional Window’s Powershell Terminal (Administrator Mode)
3. Run the following command in the Additional Powershell Terminal:
auditpol /set /subcategory:"Logon" /failure:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
4. Press Windows+L
5. Enter Wrong Pin/Password 6 times within 5 minutes to produce >5 failure alert.
6. Enter Wrong Pin/Password 10 times within 5 minutes to produce ≥10 failures alert
7. Enter Wrong Pin/Password 21 times to produce (≥20 failures alert) and onward . . .
8. Unlock using correct Password/Pin
9. Observe Failed Login Alert(s) by the detector
* Note: To revert Windows 11 to its default state (without auditing 4625 Failed Login events), use the following command:
auditpol /set /subcategory:"Logon" /failure:disable
auditpol /set /subcategory:"Account Lockout" /failure:disable


4720: Account Created                                                                                
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Additional Window’s Powershell Terminal (Administrator Mode)
3. Run the following command in the Additional Powershell Terminal:
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
4. Run the following command in the Additional Powershell Terminal:
net user TestDetect123 MyTempP@ssw0rd! /add
5. Type Y and hit enter for: “Do you want to continue this operation? (Y/N) [Y]:”
6. Observe Account Created Alert by detector

4728: User Added to Security Group                                                          
1. Observe alert by detector after Account Creation occurs 
(Refer to 4720: Account Created to produce)

4726: Account Deleted                                                                                 
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Additional Window’s Powershell Terminal (Administrator Mode)
3. Follow right after 4720: Account Created to begin
4. Run the following command in the Additional Powershell Terminal:
net user TestDetect123 /delete
5. Observe Account Deleted Alert by detector
* Note: To revert Windows 11 to its default state (without auditing 4720 Account Created events), use the following command:
auditpol /set /subcategory:"User Account Management" /success:disable /failure:disable

4672: Privilege Escalation                                                                          
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Press Windows+L
3. Unlock using Password/Pin
4. Observe Privilege Escalation Alert by detector

4688: Non-Whitelisted Process Creation                                                       
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Additional Window’s Powershell Terminal (Administrator Mode)
3. Run the following command in the Additional Powershell Terminal:
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
4. Execute an “.exe” process that’s not on the Whitelist to observe a Process Creation alert from the detector.
*Note: Whitelist includes the following processes:
smss.exe, csrss.exe, wininit.exe, services.exe, lsass.exe, lsm.exe, winlogon.exe, dwm.exe, fontdrvhost.exe, spoolsv.exe, svchost.exe, taskhostw.exe, ctfmon.exe, searchindexer.exe, searchapp.exe, shellexperiencehost.exe, runtimebroker.exe, systemsettings.exe, explorer.exe, notepad.exe, wordpad.exe, calc.exe, mspaint.exe, snippingtool.exe, osk.exe, control.exe, mmc.exe, taskmgr.exe, regedit.exe, eventvwr.exe, chrome.exe, msedge.exe, firefox.exe, brave.exe, opera.exe, vivaldi.exe, winword.exe, excel.exe, powerpnt.exe, outlook.exe, onenote.exe, acrobat.exe, acrord32.exe, code.exe, python.exe, py.exe, pycharm64.exe, idea64.exe, conhost.exe, eventlog_detector.py
* Note: To revert Windows 11 to its default state (without auditing 4688 Process Creation events), use the following command:
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable

4663: Mass File Activity                                                                                  
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Additional Window’s Powershell Terminal (Administrator Mode)
3. Run the following command in the Additional Powershell Terminal:
auditpol /set /subcategory:"File System" /success:enable /failure:enable
4. Run the following command in the Additional Powershell Terminal:
1..$count | ForEach-Object {
    $f = "C:\Users\Chase McCrary\Downloads\EventLogDetector2\EventFileBurst\massfile_{0}.txt" -f $_
    Set-Content -Path $f -Value "test $_" -Force
}
5. Observe Mass File Activity alert by the detector
6. Run the following command in the Additional Powershell Terminal to set $count back to 0:
Remove-Item "C:\Users\Chase McCrary\Downloads\EventLogDetector2\EventFileBurst\massfile_*.txt"
* Note: To revert Windows 11 to its default state (without auditing 4663 Process Creation events), use the following command:
auditpol /set /subcategory:"File System" /success:disable /failure:disable

4697: Service Installed                                                                            
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Additional Window’s Powershell Terminal (Administrator Mode)
3. Run the following command in the Additional Powershell Terminal:
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
4. Run the following command in the Additional Powershell Terminal:
sc.exe create TestSvc4697 binPath= "C:\Windows\System32\notepad.exe" start= demand
5. Observe Service Installed alert by the detector
6. Run the following command in the Additional Powershell Terminal to clean up the installation of the test service:
sc.exe delete TestSvc4697
* Note: To revert Windows 11 to its default state (without auditing 4697 Service Installed events), use the following command:
auditpol /set /subcategory:"Security System Extension" /success:disable /failure:disable

4723: Password Change                                                                       
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Additional Window’s Powershell Terminal (Administrator Mode)
3. Run the following command in the Additional Powershell Terminal:
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
4. Press Ctrl + Alt + Del
5. Click “Change a password”
6. Enter current password and confirm a new password
7. Observe Password Change alert by the detector
* Note: An unsuccessful password change attempt will also trigger a 4723 alert.
* Note: To revert Windows 11 to its default state (without auditing 4723 Password Change events), use the following command:
auditpol /set /subcategory:"User Account Management" /success:disable /failure:disable

4724: Password Reset                                                    
1. Have Detector Running in Window’s Powershell (Administrator Mode)
2. Open Additional Window’s Powershell Terminal (Administrator Mode)
3. Run the following command in the Additional Powershell Terminal:
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
4. Create a temporary test account in the Additional Window’s Powershell Terminal:
net user TestUser4724 P@ssw0rd! /add
5. Reset the password for the temporary test account in the Additional Window’s Powershell Terminal:
net user TestUser4724 NewP@ss2024
6. Observe Password Reset alert by the detector
* Note: For cleanup, run the following command to delete the test account in the Additional Window’s Powershell Terminal:
net user TestUser4724 /delete
* Note: To revert Windows 11 to its default state (without auditing 4724 Password Reset events), use the following command:
auditpol /set /subcategory:"User Account Management" /success:disable /failure:disable

How to Access the Encrypted Audit Log:
1. Open “detections_decrypted” to see the audit log decrypted.
2. To update the “detections_decrypted” with the latest alerts, run this command in a Powershell Terminal (Administrator Powershell):
cd "C:\Users\Chase McCrary\Downloads\EventLogDetector2"
py decrypt_audit_log_to_json.py
* Note: “detections.log.enc” is the encrypted audit log that stores the full history of all detector alerts. “audit_key.bin” is the AES-256 encryption key used for both encrypting and decrypting the audit log (it acts as the encrypter and the decrypter). The Python script “decrypt_audit_log_to_json.py” is used to decrypt the log file and output a readable, plaintext version (detections_decrypted.jsonl) containing all previously recorded alerts.
