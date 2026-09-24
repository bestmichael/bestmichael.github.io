# Windows Forensics

## Process Execution

### Overview


| Artifact | XP | Win 7 | Win 10 | Win 11 | Proves Execution? |
| -------- | -- | ----- | ------ | ------ | ----------------- | 
| Prefetch | YES v17 | YES v23 | YES v30 (compressed) | YES v30/31 | Yes | 
| Shimcache (AppCompatCache) | YES (96 Entries)| YES (1024) | YES | YES | XP/7 partial; 10/11 presence only  | 
| RecentFileCache.bcf | NO | YES | NO | NO | NO | Yes (plus presence) | 
| Amcache.hve | NO | NO | YES | YES | Mostly presence with SHA1 | 
| UserAssist | YES | YES | YES | YES | Yes (GUI/Explorer Launches) | 
| BAM/DAM | NO | NO | YES | YES | Yes (last run) | 
| SRUM | NO | NO | YES | YES | Yes (resource Usage) | 
| Windows Timeline | NO | NO | YES | YES | Yes (resource Usage) | 
| PCA (appcompat/pca) | NO | NO | NO | YES | Yes | 
| Jump Lists | NO | YES | YES | YES | Indirect (file use) | 
| Process creation Event | 592 | 4688 | 4688 | 4688 | 
| MUICache | YES | YES | YES | YES | Yes (weak) | 


Here is each artifact from the matrix with a short explanation and a method for assessing execution.

### Prefetch
Windows creates a `.pf` file when an executable is launched, so the application loads faster next time. It records the executable name, a run counter, last run times, and the files and directories loaded during the first seconds of execution.

**How to assess:**

- Parse `C:\Windows\Prefetch\` with `PECmd.exe -d <dir> --csv <out>`.
- The file creation time is roughly the first run, and the embedded last run time(s) are the latest runs. You get one timestamp on XP/7 and up to eight on Win8+.
- Review the loaded files list for the true executable path, suspicious DLLs, and staging directories such as `\Temp\` or `\Users\Public\`.
- A hash in the filename that differs for the same executable name means it ran from different paths, which is typical for masquerading (e.g. `SVCHOST.EXE-<hash>` outside System32).
- Check `EnablePrefetcher` first. A missing `.pf` only means something if Prefetch was enabled.

**Artifacts**

- c:\Windows\Prefetch

**Tool-Overview:**

| Name | Operating System | 
|------|------------------|
| PECmd (EZ-Tools) | Windows |
| Libscca (sccainfo, pyscca) |  Linux,Windows, Mac |
| Velociraptor | Linux, Windows, Mac |

### Shimcache (AppCompatCache)
The Application Compatibility Engine records executables it has checked for compatibility shims, in a registry value in the SYSTEM hive. **It is only written to disk at shutdown or reboot.**

**How to assess:**

- Parse with `AppCompatCacheParser.exe -f SYSTEM --csv <out>` or RegRipper `appcompatcache`.
- Entries are ordered with the most recent at the top. The position gives relative order, not absolute time.
- The timestamp is the file's last modified time, **not** the execution time.
- **XP/7:** the InsertFlag or execution flag can indicate execution, but verify it against other artifacts.
- **Win10/11:** treat entries as proof of presence only.
- For a running system or a memory image, use Volatility3 `windows.shimcachemem` to get entries not yet flushed.

**Artifacts**

- C:\Windows\System32\config\SYSTEM
- C:\Windows\System32\config\SYSTEM.LOG1 and SYSTEM.LOG2 (Transaction Logs)
- C:\Windows\System32\config\RegBack\SYSTEM is an older backup copy.
- Memory Snapshot --> Volatility

### RecentFileCache.bcf
This is the Win7 predecessor of Amcache, located in `C:\Windows\AppCompat\Programs\`. It lists executables recently launched that were discovered by the compatibility scan.

**How to assess:**

- Parse with `RecentFileCacheParser.exe -f RecentFileCache.bcf`.
- It contains full paths only, without timestamps. Use the file's own last modified time as an upper bound for when entries were added.
- Entries typically represent executables launched since the last run of the ProgramDataUpdater task, so it is very useful for recently introduced malware.
- Correlate with Prefetch and Shimcache for timing.

### Amcache.hve
This registry hive in `C:\Windows\AppCompat\Programs\` inventories executables, drivers, and installed programs. It includes the full path, SHA1 hash, file metadata, and first-seen or key-write timestamps.

**How to assess:**

- Parse with `AmcacheParser.exe -f Amcache.hve -i --csv <out>`. Include the `.LOG1`/`.LOG2` files so dirty hive transactions are replayed.
- Focus on `InventoryApplicationFile` (Win10/11) or `File` (Win8/7 with the update).
- Look up the SHA1 in VirusTotal or your threat intelligence. The hash survives even when the binary has been deleted.
- On modern Windows, entries can be created by inventory scans without execution. Treat an entry as presence plus a hash, and confirm execution via Prefetch, BAM, or event logs.

### UserAssist
This per-user registry key in NTUSER.DAT tracks programs and shortcuts launched through Explorer (Start menu, desktop, double-click). Values are ROT13 encoded and hold a run count and last run time.

**How to assess:**

- Parse NTUSER.DAT with Registry Explorer (UserAssist plugin) or RegRipper `userassist`.
- The last run time and run count show that the specific user launched the program interactively.
- On Win7+, focus count and focus time indicate how long the user actually worked with the application.
- Only Explorer-initiated launches are recorded. Execution via cmd, PowerShell, services, or PsExec will not appear. Absence therefore suggests a non-interactive or CLI-based attacker.

### BAM/DAM (Background/Desktop Activity Moderator)
BAM is a Win10 1709+ service for power management that stores the full path and last execution time of executables per user SID in the SYSTEM hive. DAM is the equivalent for modern or desktop apps.

**How to assess:**

- Parse SYSTEM with Registry Explorer or RegRipper `bam`, and navigate to `bam\State\UserSettings\{SID}`.
- Each value name is the full path of the executable (often in `\Device\HarddiskVolumeX\...` notation), and its data contains a FILETIME last run timestamp.
- Map the SID to a user via SAM or ProfileList. This gives you who ran what and when, including CLI and background executions.
- Entries are purged after about a week without execution, so collect early.

### SRUM (System Resource Usage Monitor)
SRUM is an ESE database (`C:\Windows\System32\sru\SRUDB.dat`) that records per-application resource usage in roughly hourly intervals for about 30 to 60 days. This covers CPU time, bytes sent and received, and energy use.

**How to assess:**

- Parse with `SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv <out>` (the SOFTWARE hive resolves interface names).
- The Application Resource Usage table proves that a process consumed CPU in a specific time slot and shows the user SID.
- The Network Usage table shows bytes sent and received per application. This is excellent for spotting exfiltration tools such as rclone or 7z plus an upload tool.
- The database may be dirty. Repair it with `esentutl /r` or `/p` on a copy before parsing.

### Windows Timeline (ActivitiesCache.db)
This SQLite database in `C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\<id>\` records user activities on Win10 1803+, such as launched applications and opened documents, with start and end times. Win11 has largely removed this feature.

**How to assess:**

- Parse with `WxTCmd.exe -f ActivitiesCache.db --csv <out>`.
- In the Activity table, `AppId` identifies the executable, and `StartTime`/`EndTime` show when it was in use.
- Also check `ActivityOperation` for pending or synchronizing records.
- It is useful for building a user-activity timeline including duration, but availability depends heavily on configuration and version.

### PCA (Program Compatibility Assistant)
On Win11 22H2+, plain text logs in `C:\Windows\appcompat\pca\` record programs launched and tracked by the Program Compatibility Assistant. `PcaAppLaunchDic.txt` holds a path and last launch time, and `PcaGeneralDb0.txt` holds additional details.

**How to assess:**

- Open the files in a text editor or use `grep`. They are pipe-delimited, with UTC timestamps.
- Each entry in `PcaAppLaunchDic.txt` is direct evidence of execution with a last launch timestamp.
- `PcaGeneralDb0.txt` can contain errors and exit states, as well as product and vendor names.
- It mainly covers launches via Explorer, similar to UserAssist, but it is system-wide and survives in plain text.

### Jump Lists
Jump Lists were introduced in Win7. They are per-application lists of recently or frequently used files, stored as `*.automaticDestinations-ms` and `*.customDestinations-ms` in `AppData\Roaming\Microsoft\Windows\Recent\`. Each file is named after an AppID that identifies the application.

**How to assess:**

- Parse with `JLECmd.exe -d <Recent dir> --csv <out>`.
- Map the AppID to the application using public AppID lists. The existence of a Jump List for an AppID implies the application was used.
- The embedded LNK entries give target files, timestamps, volume serial numbers, and MAC or NetBIOS info. This shows what the application opened and when, for example `mstsc.exe` Jump Lists revealing RDP targets.
- This is indirect evidence of execution, so combine it with Prefetch for exact run times.

### Process Creation Events (592 / 4688)
When "Audit Process Creation" is enabled, the Security event log records every new process. On Vista+ this is event 4688, including the parent process and optionally the command line. XP recorded it as event 592.

**How to assess:**

- Parse with `EvtxECmd.exe -f Security.evtx --csv <out>` and filter on 4688.
- Key fields are `NewProcessName`, `CommandLine`, `ParentProcessName` (Win10+), `SubjectUserSid`, and `TokenElevationType`.
- Look for suspicious parent-child chains such as `winword.exe → powershell.exe` or `services.exe → cmd.exe`, and for encoded or obfuscated command lines.
- Check the audit policy first (`auditpol /get /category:*` or the policy in the SECURITY hive). If auditing was disabled, missing 4688 events mean nothing.
- Supplement with Sysmon event 1 (with hashes), PowerShell 4104, and task events 4698/106.

### MUICache
The shell caches the display name (FileDescription) of executables launched through Explorer in the user's registry. It is located in NTUSER.DAT on XP and in UsrClass.dat on Vista+.

**How to assess:**

- Parse with Registry Explorer or RegRipper `muicache`.
- Value names contain the full executable path, which shows that the user launched that program at some point.
- There are no per-entry timestamps. Only the key's last write time is available, which reflects the most recent addition.
- It is weak on its own but helpful for finding renamed tools, since the cached FileDescription can reveal the original tool name (e.g. "Mimikatz" behind `svc.exe`).

---

I can also turn this into a Claude Doc for your casework reference if you'd like.

