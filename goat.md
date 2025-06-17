CTH Methodologies
The NIWDC defines 3 separate CTH methodologies:

Analytics-driven

Situational awareness-driven

Intelligence-driven

Analytics-Driven
﻿
The analytics-driven methodology leverages data and analytics. This methodology applies complex queries and algorithms to data sets, often using software automation. A key distinction with the analytics methodology is that it does not require physical access to local machines, networks, or systems. CTH analysts using the analytics-driven methodology gather data artifacts consisting of sensor alerts, system logs, and network traffic. Combining knowledge of data artifacts with knowledge of automated analysis capabilities allows the analysts to develop a picture of the network terrain.

Situational Awareness-Driven 

The situational awareness-driven methodology leverages an advanced understanding of a particular cyberspace terrain to detect anomalous activity. Similar to the analytics methodology, situational awareness does not require physical access to local systems. Data artifacts pertaining to the operating environment are critical to this methodology. CTH analysts examine data artifacts over time in order to understand system normality and detect outliers in behavior. This often leads to discovering potential MCA.

Intelligence-Driven
﻿
The intelligence-driven methodology leverages timely, accurate, mature Cyberspace Threat Intelligence (CTI) to detect advanced cyberspace threats. The intelligence-driven methodology requires physical access to local systems.

The remaining sections of this lesson focus on the intelligence-driven CTH methodology. 

TTPs
﻿
As defined by National Institute of Standards and Technology (NIST), “tactics are high-level descriptions of behavior, techniques are detailed descriptions of behavior in the context of a tactic, and procedures are even lower-level, highly detailed descriptions in the context of a technique.” 

TTPs are a chain, or sequence, of actions taken by the adversary during their actions or campaign. There is a wide variety of TTPs, however, some common TTPs include using a specific malware variant, attack tool, delivery mechanism (such as phishing), or exploit.

As diagrammed in David Bianco’s Pyramid of Pain in Figure 1.1-9, below, TTPs are located at the top of the pyramid. According to Bianco, “at the apex are the TTPs. When you detect and respond at this level, you are operating directly on adversary behaviors, not against their tools.” 

IOCs can include hash values, IP addresses, domain names, and network/host artifacts. All of these items are located below TTPs on the pyramid.

Attack Behaviors and Hunting
The analysis of FireEye’s APT37 intelligence report identified multiple TTPs. Below are just three TTPs from the report, as well as the attack behaviors they each translate to:


Spear-phishing. Adversaries may send emails with a malicious link in an attempt to gain access to victim systems. The email employs links to download malware contained in the email to avoid defenses that may inspect email attachments.

Malicious documents. An adversary may rely upon a user opening a file in order to gain execution. Users may be subjected to social engineering to get them to open a file that leads to code execution.

Command and Control. Adversaries may use an exploited host to communicate with systems under their control within a victim network. 
Translating TTPs into attack behaviors helps narrow the focus of a hunt mission. Each TTP and behavior has specific attributes and components related exclusively to them. These attributes and components may take the form of a piece of software, a type of communication, a type of log file, or an event ID, all of which can be used within a hunt mission. 

IOCs and TTPs
Step 5 of the OP, Tactical Planning and Mission Execution, includes threat intelligence. Threat intelligence typically includes artifacts and evidence found within the operating environment (OE). A threat intelligence report typically includes IOCs and TTPs pertaining to either the network, the threat, or both.

IOCs
﻿
As defined by the CWP an IOC is, “a forensic artifact observed on a computer network or in a computer operating system which indicates an intrusion.” IOCs change and can take on a wide variety of topics and forms. Some common IOCs include the following:

Unexpected network traffic (inbound or outbound)

Unusual internet protocol (IP) addresses

Connections to strange geographic areas

Increased activity by a privileged user

Increased volume of data transmission

Below is a sample intelligence report from a hunt mission. The intelligence report includes specific IOCs and supporting details. 

Intel Flash:
MistyIguana Group Tied to Recent Attacks on Pharmaceutical Companies﻿

A recent intelligence report published by public-sector cybersecurity company Frostgaze has tied several network artifacts used in an attack campaign against pharmaceutical company Draxx, Inc. back to the MistyIguana threat group. The Frostgaze intelligence report released the following network-based IOCs to the public.

The above intelligence report triggers a CPT hunt operation for related MistyIguana activity on the network of Alabaster Corp, a DoD-affiliated contractor. Alabaster Corp is working on a DoD-critical project, and MistyIguana has been known to target defense-related networks in the past.

After receiving intel, the CPT must follow the steps below:

Terrain Identification and Prioritization

Tactical Planning Inputs

Creating the Tactical Plan

Executing Hunts

Hunt Execution Outputs

Intel-Driven Hunting
Cyber Threat Intelligence Overview
﻿
Analysts using the intelligence-driven methodology leverage CTI. CTI is information that has been analyzed to aid an organization in identifying, assessing, monitoring, and responding to cyber threats. Organizations generally produce various types of CTI, which they can share internally for CTH. Information may also be derived externally, from outside of the organization. Examples of CTI include:

Indicators (system artifacts or observables associated with an attack)

TTPs

Security alerts

Threat intelligence reports

Recommended security tool configurations

CTI can trigger a hunt operation by warning of an imminent or already-realized cyber attack, or by reporting on new indicators or adversaries that were recently seen in the wild. For example, intelligence about an adversary beginning to actively target the energy sector may trigger a CPT to perform hunts for evidence of that adversary on energy sector networks. CTI can also inform the Tactical Planning and Mission Execution phase of a hunting operation by allowing an analyst to develop more informed or more targeted hunting hypotheses. An upcoming lesson in this course discusses the features of hunt hypotheses.

Types of CTI 
﻿
Organizations develop different types of CTI, depending on who is receiving the information and what details it includes. The three categories of CTI include the following:

Strategic. Broad, general information that provides high-level threats and activities in a non-technical delivery. 

Tactical. TTP outlines for a technical delivery that explains how the adversary may attempt to attack the network. 

Operational. Purely technical information about specific attacks, experiences, or campaigns that provides actionable information regarding activities that have been previously identified.

CTI Sources

CTI is derived from both internal and external sources. Internal refers to CTI collected from within the network or organization where the hunt operation is occurring. Internal CTI typically includes artifacts such as network event logs, IP Addresses, or records of past incident responses. External CTI refers to CTI collected from sources outside of (or "external" to) the network or organization where the hunt operation is occurring. External CTI typically includes artifacts such as those found on the open internet or technical sources (such as MITRE ATT&CK). A key benefit of external CTI is that organizations can leverage the collective knowledge, experience, and capabilities from the community to gain a more complete understanding of the threats the organization may face.

Cyber Threat Hunting
The Naval Information Warfighting Development Center (NIWDC) defines Cyber Threat Hunting (CTH) in the following way:

“A specialized and detailed scrutiny of friendly cyberspace for threats that have breached security and are difficult for routine detection measures to discover and is aligned to defensive cyberspace operation-internal defensive measures (DCO-IDM).” 

Simply, CTH is the process of actively searching information systems to identify and stop malicious cyberspace activity. The term “hunting” refers only to internal defensive measures that require maneuver within the defended network to identify, locate, and eradicate an advanced, persistent threat. A primary component of threat hunting is based on detecting TTPs. 

CTH operations are centered around analysis and review of the compromised network. Analysis and review involve searching and auditing the endpoint activities a threat actor executes to avoid detection. 

CTH Kill Chain
﻿
Figure 1.1-8, below, illustrates the 5 stages of the CTH kill chain as NIWDC defines it:

The Start. Search for MCA by filtering out legitimate or expected activity on the network.

Refinement. Find suspicious activity. This triggers a deeper investigation and increases search efforts. 

Discovery. Discover the root cause of the malicious behavior. 

Response. Calculate and assess the attack. Remediate the threat based on this information.

Continuous Improvement. Update defenses to prevent future attacks that use the same TTPs discovered during the hunt. 

What is NOT CTH?
﻿
Misconceptions of what CTH comprises make it difficult to understand its value and intent. Timing and approach are what differentiate CTH from other defensive activities. 

CTH starts before any threat has been found. On the other hand, practices such as incident forensics or incident response occur after identifying an incident or compromise. The aim of CTH is to illuminate an adversary before a known incident. This requires analyzing the current environment and its conditions to identify any evidence of intrusion or compromise before any are known to exist.

CTH is also different than simply installing tools and waiting for alerts. While CTH does require technology and data, these tools are used for proactive discovery. Analysts leverage the information they gather to discover known adversary TTPs that validate whether adversary activities are imminent or ongoing. 

What step in the operations process does the development of a hunt hypothesis fall under?
tactical planning and mission execution

event.code:1 and process.command_line.keyword~ localgroup
event.code:(4728 or 4732 or 4746 or 4751 or 4756 or 4761) log on


The following list is an example of tactical KT-C for an APT that is performing data theft in a network:
A list of servers that contains the targeted information
A list of systems that attackers may use to pivot into the system 
A subset of users that have access to the targeted information
Once the tactical KT-C is determined, generating the hunt hypothesis is straightforward. Start with the hypothesis that the attackers have direct access to the servers, as described below:


Hypothesis: Malware is exfiltrating sensitive data to the internet from at least one of the servers responsible for storage of that data.


Based on the KT-C, this hypothesis only makes sense if the servers reach out directly to the internet. If there are robust logs on the network connections of these systems, finding a unique IP address or domain is relatively straightforward.


There is a lot of room for creative solutions to these cyberspace problems. For example, a unique callback domain name is going to be a largely unpopular domain. Using a list like "Cloudflare Radar" (top most popular domains) would remove likely legitimate websites.


Hypothesis: The attackers are accessing sensitive data from servers by pivoting from systems defined in the tactical KT-C.


Going through the logs to test this hypothesis provides a few obvious forensic artifacts. These include odd times the system connects to the server, new or unusual login locations, or credentials used by scripts running interactively.


Hypothesis: The attackers are using compromised credentials to access sensitive information.


With proper analysis, the KT-C identified is a subset of users that includes only accounts with permissions to access the targeted data. Looking for anomalous user activity from within that subset is a good way to see if there are compromised accounts.
A user is logging into the server from a different workstation than they normally use.
Credentials are used to access files, but have not been used to log into a workstation.
"Bursty" network traffic where files are downloaded methodically over a short period of time.
Another detection method to this, although highly impractical, is what if everyone in the organization was told verbally not to authenticate to the server, with no digital trail would the attackers think they are going to keep blending in?

Which internal target would be useful for pivoting into an FTP server that hosts sensitive data?
a user workstation that normally communicates with the ftp server



Which types of access are useful to an APT that steals sensitive data?

user with sensitve data
user access to internal host without sensitve data 
root access to a core piece of networking hardware

kt-c
KT-C Review


The Cyber Defense Analyst-Basic course provides a lesson on KT-C that focuses on strategic level terrain. This lesson focuses on tactical level terrain and illustrates how understanding attackers' goals facilitates the identification of these hosts and reduces the initial search area. Below is a summary identifying KT-C from the lesson Terrain Identification, in the Cyber Defense Analyst-Basic course. 


Tactical Level Terrain
Features that provide the offensive operator an advantage today.

Operational Level Terrain
Features that provide the adversary an advantage over a series of activities and fulfill the overall objectives of their cyber campaign.

Strategic Level Terrain
Three elements in the "triad of security" rate the impact of the various parts of the system.
Availability
Integrity
Confidentiality

Three tiers of key terrain.
Tier - 1: Top value, critical and essential data, applications, critical network services, and information processing 
Tier - 2: Important data and applications
Tier - 3: General data and applications

Kerberos Attacks and Logging
Kerberos Attacks
﻿

Authentication mechanisms are sometimes the only thing preventing an attacker from getting their desired data. This makes any vulnerabilities in the protocol highly sought-after. The most likely attack a defender sees in a network is Kerberoasting. The next most likely attack is overpass-the-hash, followed by the golden ticket. The silver ticket and bronze bit exploits are patched and Authentication Service Response (AS_REP) Roasting requires a user to intentionally disable pre-authentication.

﻿

Pre-Authentication Brute Force
﻿

Pre-authentication brute-forcing is simply just guessing a user's password. Pre-authentication is enabled by default within windows domains and it requires the user's password to be used to encrypt the current time when requesting a TGT. Without this function, any user can request a TGT for any other user, which makes cracking a user's password possible. This attack is referred to as AS-REP roasting, which is explained in more detail, below.

﻿

AS_REP Roasting
﻿

In AS_REP roasting, without pre-authentication, there is no authentication on requesting a TGT, which includes data encrypted by the user's password. This allows a malicious user to request a TGT for a different user and then try to crack the password. 

﻿

Kerberoasting
﻿

Kerberoasting is similar to AS_REP roasting. Kerberoasting requests a TGS for an AP and tries to crack the password. Service accounts have high-complexity passwords that change frequently, however, if a user account is in charge of the service then it might be crackable.

﻿

Overpass-the-hash
﻿

Attackers conduct an overpass-the-hash attack when they use a stolen password hash to request a TGT. This works with Single Sign On (SSO), since users are not repeatedly prompted for a password. Authentication methods, like Kerberos, authenticate someone based on the encrypted version of the password (the hash) and do not require the clear-text version of the credentials.

﻿

Golden Ticket
﻿

The account named krbtgt on the DC is the account that owns the master, trusted keys. It is shorthand for Kerberos TGT, where krb stands for Kerberos. If an attacker steals krbtgt credentials from the DC, they can make any TGT. Attackers can set the expiration date far into the future, allowing persistent access into the network. This exploit is really just how Kerberos works. At some point something has to be trusted and if the attackers have access to the trusted keys there is not much of a defense against that.

﻿

Windows stores the current and last krbtgt account passwords and keeps them valid. That means if there is a golden ticket available, the krbtgt account will need to be changed twice before it becomes invalid. This invalidates every TGT in the network, forcing all accounts to re-authenticate.

﻿

Silver Ticket (CVE-2014-6324)
﻿

The Silver Ticket attack is a PAC that is maliciously modified. It allows the attackers to escalate privileges of any account to be domain administrators.

﻿

Kerberos has two distinct steps: authenticating the user and checking privileges. Windows implementation of Kerberos blends these two steps. The user's permissions only come into play when the user requests access to a  network resource and has nothing to do with the authentication step. In Windows networks, the authentication step returns a PAC which contains the user's permissions. Later on, the PAC is presented to the application server as proof of the user's permissions, which should be secure, since it is signed by the account on the DC. 

﻿

This exploit, which was patched in 2014 (MS 14-068), allowed an attacker to fabricate a PAC that would pass verification due to a logic flaw. Microsoft allowed hashing algorithms that did not require keys, so any valid checksum was treated the same as a checksum that required access to the DC's private key. This means any account could be elevated to domain admin without having to communicate to the DC.

﻿

Bronze Bit (CVE-2020-17049)
﻿

The Bronze Bit attack made it possible to have the service impersonate any user outside the scope of the configured service. This occurred after stealing a hash for an AP service that was configured to allow delegation or forwarding credentials of the user to other services. Delegation is supposed to be limited, however, the flag that denotes a TGT as being limited is protected by the service's hash. This means the service could decrypt that part of the message and flip the bit to make that limited scope TGT to be a TGT that grants full access to the user's account.

﻿

Logging examples
﻿

Pre-Authentication Brute Force Logs
﻿

The process of brute-forcing these accounts leaves some forensic residue in the logs. These authentication failures are not logged with a normal event ID 4625: An account failed to log on. Instead, they produce an event ID 4771 which is only on the DC. This event ID is described below:

﻿

Event ID: 4771, Kerberos pre-authentication failed﻿

Result Code: 0x18 KDC_ERR_PREAUTH_FAILED
Bad password
Result Code: 0x6 KDC_ERR_C_PRINCIPAL_UNKNOWN
Kerberos produces an error if the username is incorrect. Attackers can leverage this to guess usernames.
Defenders should monitor the following with this event log and attack:

High-value accounts, such as domain admins
Off-hours logs
Inactive accounts
Client Address field is outside the internal range
Large volume of logs
Incorrect pre-authentication type for the network
If only smartcards are allowed within the network (pre-authentication type 15) and the 4771 log shows a failure with pre-authentication type 2, then something is trying to use a password.
﻿

Golden Ticket Logs
﻿

Logging associated with a Golden Ticket is an exploit technique, but not directly due to a flaw in Kerberos. The tools executing this attack do not work exactly the same way that the native windows systems work. This creates anomalies within the logging. Below is a snapshot of the event logs associated with this attack and some notable features. The main point of this data is that hacking tools tend to leave odd entries within logs that will be inconsistent with how the legitimate system tools create logs.

﻿

Event ID: 4769, A Kerberos service ticket was requested﻿

Location: Domain controller
Notable activity is a TGS being requested without a preceding TGT 
Event ID: 4627, Group membership information﻿

Location: workstation/Domain controller	
Event ID: 4624, An account was successfully logged on﻿

Location: workstation/Domain controller
Field: Account Domain may be the Fully Qualified Domain Name (FQDN) when it normally is the short domain name
Field: IpAddress may indicate the compromised host
Event ID: 4672, Admin Logon﻿

Location: workstation
Field: Account Domain may be blank when it normally is the short domain name
Event ID: 4634, Account Logoff﻿

Location: workstation
Field: Account Domain may be blank when it normally is the short domain name

og Aggregation and Parsing Fundamentals
Adversaries go to great lengths to remain undetected. A successful attack often hides among other traffic and activity in order to seem less conspicuous. For example, as systems log outgoing traffic, an attacker may try to exfiltrate data to a compromised trusted external cloud asset or move data using a trusted compromised system service. The ability to identify irregularities within normal log data is critical for defenders to be able to recognize abnormal and potentially malicious traffic. This also reduces hunt time lost in chasing down false positives.

﻿

Many Operating Systems (OS) and security applications have advanced logging capabilities that are usually disabled by default. Verbose security logs may contain valuable information, but lead to security personnel missing critical data and system resources becoming quickly overwhelmed with too much logging. This is why knowing what to log, when to log it, and how to interpret log details is fundamental for proper aggregation and parsing. There are four key platforms that provide logs:

Windows
Unix
Applications
Network Defense
Windows Logging Capabilities
﻿

Windows logs are a great way to view application-agnostic logs that indicate different security events, system failures, and abnormal behaviors. The three main types of Windows logs that organizations most commonly aggregate include the following:

System
Security
Application
Windows generates system events, which correspond to driver updates, power faults, and other system-level occurrences. Security events relate to logins, share access, and file creation/deletion. Application events are specific to each program installed on the host. The program developer dictates what their application reports to the event log. Some applications do not report to the event log, but, instead, write logs directly to a text file within their application directories.

﻿

Unix Logging Capabilities
﻿

Unix-based OS logs are different from Windows logs in how they’re generated and what they represent. The first time that an application sends logs to the syslog daemon, it creates an entry in /etc/syslog.conf, which lists the file paths for specific logs. 

﻿

Most Unix distributions place logs into the following categories, or “facilities”: auth, console, cron, daemon, ftp, kern, local*, lpr, mail, news, ntp, user, uucp, syslog, boot, dmesg, faillog, application (httpd, samba, mysql, etc.) and linux systemd journals. 

﻿

Unix application developers often allow administrators to configure the amount of information sent to each facility on a scale of 1 to 9. For example, an ftp connection failure might be categorized as a priority 1, meaning it is always logged. A file transfer may have a priority 9, meaning it is never logged. Users may change severities and elect to completely omit logging any logs that are below a certain priority. This measure helps prevent excessive logging, in which logs meet the host’s rotation threshold and get deleted. Deletion occurs if the log directory grows too large or too old.

﻿

Application Logging Capabilities
﻿

User applications usually also have logging capabilities for various events. Some applications offer very verbose and in-depth logging options, while others offer very little. Most application vendors offer documentation on what logs their software generates and how to find relevant information within those logs.

﻿

Network Defense System Logs
﻿

Firewalls, Intrusion Detection Systems (IDS), Intrusion Prevention Systems (IPS), routers, and other networking devices all contain different kinds of logs based on the traffic that they process. Networking equipment logs can be configured to perform full packet captures. This is when the entirety of the network packets that they process are logged and categorized based on the packet metadata.

﻿

For example, Cisco devices have methods for sending all their logs to a log server so that personnel do not have to manually check the device’s logs. The two most common types of log forwarding are Syslog forwarding and Simple Network Management Protocol (SNMP) trap logging. Syslog forwarding sends all configured device logs to a remote syslog server, while SNMP traps allow CDAs to find changes to both configurations and configured devices.

﻿Data Aggregation Systems and Limitations
Threat hunting and information gathering usually begin by parsing important OS logs from servers and other critical infrastructure devices such as Domain Controllers (DC), Dynamic Host Configuration Protocol (DHCP) servers, Simple Mail Transfer Protocol (SMTP) servers, and other services. Organizations forward these logs to a log aggregator, which makes it easy to query all logs from a single repository. The following are common logging types and data aggregators for log management:

Syslog forwarding

Windows event forwarding

Third-party Security Information and Event Management (SIEM) applications

Syslog Forwarding
﻿

As a standard, the intention for syslog is for its messages to be sent to a syslog aggregator such as Splunk or Elastic. These aggregators normalize logs for easy human consumption. Typically, any host that uses syslogs has the ability to forward logs to a remote host. Aggregators have a dedicated syslog ingestion port and service for managing the intake of the logs. CDAs can use aggregators to view logs for a hunt.

﻿

Windows Event Forwarding
﻿

Windows provides the Windows Event Forwarding (WEF) service to collect and aggregate logs from Windows hosts. IT administrators likely know how to configure log forwarding and create a subscription between source collectors and the log forwarder. However, threat hunters may also need a greater understanding of whether the Group Policy Object (GPO) has been configured to forward logs to the organization’s chosen log management system, log aggregator, or SIEM. A GPO for DC forward logs is available by navigating through the following sequence of settings:

Computer Configuration

Policies

Administrative Templates

Windows Components

Event Forwarding

A configured GPO has all managed devices forwarding logs to the server. Figure 1.4-1, below, displays this GPO configuration:

﻿

﻿

Figure 1.4-1﻿

﻿

Forwarding the entirety of a system’s logs across a network may congest aggregators or overwhelm analytic resources. This also generates a large amount of traffic. Windows Event Viewer has a subscriptions section to choose the log sources to forward, but users must implement this feature carefully. Users must determine how to balance the needs for logging with the additional resources that analyzing large data sets requires.

﻿

Third-Party SIEM Applications
﻿

SIEM applications all have different logging capabilities, but some of the most common ones that an analyst is likely to use include the following:

Solarwinds

Datadog

Splunk

McAfee ESM

Micro Focus ArcSight

Elastic Stack

Each of these applications uses different methods to aggregate, index, and analyze data events. They also have the ability to use the same source log files.

﻿

Common Data Logging Standards
﻿

It is useful for threat hunters to understand the standards with which an organization must comply because it helps identify what information is being logged before beginning threat hunting. The standards by the United States government organizations are especially informative. This includes the National Institute of Standards and Technology (NIST) publication 800-137 Information Security Continuous Monitoring (ISCM). This publication defines processes for monitoring Information Technology (IT) systems and balancing operational risk to technical vulnerabilities.

﻿

Common Issues with Over-Logging
﻿

Excessive logging creates complications in both technical and practical respects. Many SIEM applications archive or delete logs over a certain storage limit, which can lead to losing logs required for an investigation. Likewise, packet captures of encrypted traffic can be logged, but offer little information due to their obfuscated nature. Excessive logging congests the network and system resources of log storage servers. The data storage for constant, verbose logging is both costly and requires additional physical equipment space. Lastly, some SIEM vendors charge customers based on the amount of stored,  ingested, or index log events, which can cause logs to be rejected and not collected. Subscriptions prices may also change dramatically, based on use.


ATT&CK Matrix Logging Strategy
There is a cost to logging everything and a cost to logging nothing. The appropriate strategy is to configure logging based on common indicators of compromise. The Background Intelligent Transfer Service (BITS) tool discussed in previous lessons provides an example of this.

﻿

In Windows, many threat actors attempt to remove evidence of their intrusion with the BITSAdmin tool. Defenders can check the BITS service by running sc query bits. They can also see active BITS tasks with the command bitsadmin /list /allusers /verbose. MITRE® recommends searching the System logs, PowerShell logs, and Windows Event log for activity related to BITS, if an intrusion is suspected. The BITS related events IDs are:

Event ID 3: information about the job creation
Event ID 59: information about the start of the service: "BytesTransferred" value is zero
Event ID 60: status of the job
Event ID 4: completion of the job: "BytesTransferred" value is the size of the downloaded file
MITRE provides a data sources page that is a fantastic resource for finding common valuable log sources for threat detection, especially in relation to an ongoing hunt. The link is available below.

Data Parsing
There are different ways for aggregated data from multiple sources to convey the same information. Parsing is the process of normalizing, or splitting unstructured logs, into common attributes with common reference points, such as time.

﻿

Parsing is required because different systems log the same types of data in different ways. There may be variations in the format of the event fields or timestamps of the systems logging those events. Handling timestamps is not a trivial task in computer science. 

﻿

There are many ways to display and store timestamps. This includes counting the number of seconds since January 1, 1970. Another option is a signed 32-bit integer that represents time as yymmddHHMM. Tools such as syslog omit the year, while additional tools have ambiguous dates due to regional differences in how date references. For example, dates are written in day-month-year order rather than month-day-year. Parsing takes these various attributes and translates them into a common format.

﻿

Many networks that a CDA analyzes contain different tools. Understanding the general scope of what is being collected is more valuable than understanding the specific usage of one tool. The next topic in this lesson covers log data queries that are general enough to apply to any platform. However, as tools change and evolve, a CDA should familiarize themselves with any new log parsing tools they encounter in the field.

﻿(trainee@dmss-kali)-[~/Desktop/dirwalk] $ python3 parser.py -w -i dirwalk_1.txt -o dirwalk_1.csv



4. Modify the object windows_parser_definitions_2 in parser.py to conform to the file dirwalk_2.txt and enter the following command to parse the directory walk:
(trainee@dmss-kali)-[~/Desktop/dirwalk] $ python3 parser.py -x -i dirwalk_2.txt -o dirwalk_2.csv



The script  analyzer.py  has the following options to analyze the output of the script  parser.py :
-i, -input_data file — input CSV file to analyze
-m, -lastDay — files modified in the last day
-b, -knownBad — files that match known a regular expression of "bad" strings
-p, -images — files with extensions matching a list of image file types
Use the script analyzer.py to analyze dirwalk_1.csv and dirwalk_2.csv and answer the following questions. The following is an example of the input you may use:
python3 analyzer.py -i dirwalk_1.csv -p

Which technique is NOT detected by the current data sources?



Step 1: Data Sources


In the first step of the process, analysts describe and score all sources of data. Data sources can be raw logs or events generated by security appliances or systems in a mission partner environment. The descriptions of the data sources that are available to an organization’s security team and their quality are consolidated in user-defined YAML files. The DeTT&CT tool and ATT&CK framework both recognize over 30 different data sources, which are divided into more than 90 data components. These components describe particular properties or values of each data source. Each TTP’s dedicated MITRE ATT&CK page lists the data sources that provide visibility to the specified TTP, under the Detection section of the page.


For example, analyzing the following data sources can help detect the technique T1003 Operating System (OS) Credential Dumping:
DS0026 Active Directory
DS0017 Command
DS0022 File
DS0029 Network Traffic
DS0009 Process
DS0024 Windows Registry

Tools and Data Flow


Elastic Stack


Elastic Stack is a log management platform built on a collection of open-source tools with various functionalities. Elastic Stack tools enable monitoring of diverse and distributed applications and Information Technology (IT) devices. The components of Elastic Stack include the following:
Beats
Logstash
Elasticsearch
Kibana


Security Onion


The components of the Elastic Stack are frequently configured to work within another popular tool, Security Onion. Security Onion is a free and open Linux distribution for threat hunting, enterprise security monitoring, and log management. Security Onion is produced by a different organization than Elastic, so although these tools are often used together, Security Onion is not officially part of the Elastic Stack. Security Onion supports Elastic and its tools by providing a log management platform with nodes. Security Onion offers full packet capture for both network-based and host-based Intrusion Detection Systems (IDS). Security Onion also includes functionality to index, search, and visualize large amounts of data. The Elastic Stack has become a central element in recent versions of the Security Onion Linux distribution.


Data Flow


Figure 2.1-1, below, illustrates the flow of data through the Elastic Stack components and Security Onion. Elastic beats collect data to send to Logstash, which aggregates and processes that data. The data is then sent to ElasticSearch for indexing and storage. Security Onion nodes supply additional resources to support network data aggregation and alerts on suspicious activity. Kibana is used to view this information in a human-readable format. Each of these tools is described in greater detail, below.





Figure 2.1-1


Elastic Stack Components
Beats


Beats are agents that gather data such as Windows event logs. Beat agents are deployed on servers and hosts and centralize the data in Elasticsearch. Beats ship data that conforms with the Elastic Common Schema (ECS). ECS is an open-source specification that is developed with support from the Elastic user community. ECS defines a common set of fields to use when storing event data in Elasticsearch, such as logs and metrics. ECS specifies field names and Elasticsearch data types for each field and provides descriptions. If the data fits into the ECS, users can directly import it into Elasticsearch. Otherwise, the data has to be forwarded to Logstash.


Table 2.1-1, below, lists the types of beats that Elastic supports. This lesson covers the use of two of these beats: Winlogbeat and Packetbeat.







Table 2.1-1


Logstash 


Logstash ingests, transforms, and ships data, regardless of format or complexity. Data is often scattered or distributed across many systems, in many formats. Logstash supports a variety of inputs that synchronously pull events from a multitude of common sources. 


Logstash allows custom filters and pipelines to help users ingest data of different formats and schema. This customization means that a user can write a filter to parse and index the data however they want, regardless of the log, the data input structure, or the fields included in the data. The type of log file and collection location determines the ingestion path into Security Onion and Elasticsearch. The ingestion paths are composed of Security Onion nodes that handle specific data types and are responsible for sending that data type to Security Onion and Elasticsearch. The ingestion path can contain multiple nodes, however, the most common nodes are the manager, manager search, and forward nodes, as described below.


Manager


The manager node runs Security Onion Console (SOC) and Kibana. It has its own local instance of Elasticsearch that handles central configuration. An analyst connects to the manager node from a client workstation to execute queries and retrieve data. A dedicated manager node often requires separate search nodes for large networks. The manager node supports the following components:
SOC
Elasticsearch
Logstash
Kibana
Curator
ElastAlert
Redis
Wazuh



Manager Search


A manager search node is both a manager node and a search node together. It has higher hardware requirements than a normal manager node since it parses, indexes, and searches data. A manager search node supports components such as the following:
SOC
Elasticsearch
Logstash
Kibana
Curator
ElastAlert



Forward


A forward node is a sensor that forwards all logs through Filebeat to Logstash on the manager node. Filebeat is a lightweight shipper for forwarding and centralizing log server data. They are stored in Elasticsearch on either the manager or manager search node. Forward nodes run the following components: 
Zeek
Suricata
Stenographer
Wazuh

The type of data and data collection location decides where the data is sent. Zeek logs, which handle network traffic, are collected at the Forward node, where they are sent through Filebeat to Logstash, located on either the Manager or manager search node. Winlogbeat logs, which handle host logs, are forwarded to the Management or Manager Search node directly through Logstash. 


Elasticsearch


Elasticsearch is an open-source, distributed search engine based in JavaScript Object Notation (JSON). It is often referred to as a Non-Structured Query Language (NoSQL) or document-oriented database since it does not require a user to specify a schema upfront. Elasticsearch functions as a data housing and maintenance location. Elasticsearch stores, searches, and analyzes large volumes of data in near real-time and provides answers in milliseconds.


Kibana


Kibana is a frontend application that is the end-user, Graphic User Interface (GUI) component of the Elastic Stack. It provides search and data visualization capabilities for data indexed in Elasticsearch. Kibana queries the data residing in Elasticsearch and searches across all documents to create visualizations and dashboards.

Sigmac Syntax
Sigmac uses the following syntax to translate a query in Elastic syntax using the Winlogbeat configuration:


python sigmac -t <language> <path to file/rule> -c <configuration>
﻿

This syntax uses the following elements:

Translate (-t)
Configuration (-c) 
﻿
Sigmac Syntax
Sigmac uses the following syntax to translate a query in Elastic syntax using the Winlogbeat configuration:

How does Elastic Stack aggregate data?
an agent such as packetbeat or winlog is deployed on hosts to collect specfic types of data

What was the purpose of modifying the configuration file to include Logstash output at 172.35.1.38:5044?
send collected data to the logstash for parsing and indexing

Besides Elasticsearch, what are the other components that make up the Elastic Stack?
beats, kibana, logstash









































