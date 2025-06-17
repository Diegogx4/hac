Infrastructure and Data Flow
Splunk offers various types of deployments, such as Splunk Cloud and Splunk Enterprise Security. However, each deployment is built on similar principles and architecture. This lesson uses a generic Splunk Enterprise deployment to introduce these underlying concepts, starting with critical Splunk infrastructures and their processes. 

﻿

Instance Data Flow
﻿

Three main components make up a full Splunk deployment: the forwarder, the indexer, and the search head. Combining these components and deploying them together create a Splunk instance. Figure 2.2-1, below, visualizes the flow of data through a Splunk instance. This data flow occurs in two parts. Part 1 ingests raw data with a forwarder, then sends the data to an indexer to parse into events and store within indexes. Part 2 searches for data by using a search head to parse search queries, create search jobs, and distribute the jobs to indexers. The indexers process the search jobs and return the results to the search head for post-processing. Each component and its functions are described in greater detail, below.

﻿

﻿

﻿

Figure 2.2-1﻿

﻿

Forwarder
﻿

Part 1 of the data flow starts with a forwarder. A forwarder collects data from a source and sends that data to either another forwarder or indexer. The two types of forwarders are universal forwarders and heavy forwarders.

﻿

A universal forwarder is a lightweight tool that performs limited forwarding functionality. It is not capable of acting as a full instance of Splunk. This type of forwarder simply collects raw data from a source and sends that raw data to a destination.

﻿

A heavy forwarder has more capabilities than a universal forwarder. These additional capabilities include pre-processing and routing data to different destinations based on defined conditions. A heavy forwarder commonly forwards data directly to indexers, rather than to other forwarders. due to its extra processing ability. A heavy forwarder can act as a full instance of Splunk. 

﻿

A network’s Splunk administrator is responsible for administrating Splunk instances. Additional information about these instances is available in the upcoming Splunk Instances section of this lesson.

﻿

Indexer
﻿

Indexers have important positions in both parts 1 and 2 of the data flow. An indexer handles data processing and storage. It does this by parsing raw data and transforming it into events. These events are then stored in an index located on the indexer. Multiple indexes can exist on a single indexer.

﻿

Advanced Splunk deployments also allow multiple indexers. Usually, these indexers handle data from different sources. Advanced deployments may set up multiple indexers to act as a cluster. Clustered indexers receive and replicate the same data across each indexer in the cluster. This can increase the performance of the Splunk deployment and act as protection against data loss.

﻿

Search Head
﻿

Part 2 of the data flow starts with users submitting search queries to a search head. A search head is responsible for parsing search queries into search jobs and distributing those search jobs to indexers. These queries are written in the Splunk Search Processing Language (SPL). Indexers process a search job against the indexes stored within that indexer and return the results of the search job back to the search head. The search head performs any necessary post-processing of the results before making the results available to the interface that queried the search head. Interfaces are discussed briefly in the upcoming section about Splunk instances.

Key Splunk Terms
This section provides a refresher on common terms for working with Splunk. The first set of terms describes how data is stored and organized, while the second set of terms describes useful tools for processing data.

﻿

Data Organization
﻿

Common terms for storing and organizing data include the following:

Index

Events

Fields

Sourcetype

Index
﻿

After an indexer is done parsing raw data into individual events, Splunk stores these events in an index. An index is the data repository for a Splunk instance. Events located within an index are written to that instance’s disk. Events stored in an index are searchable by a search head.

﻿

Many different indexes may exist within a single Splunk deployment. New indexes can be created by modifying configuration options on the indexer.

﻿

Events
﻿

Events contain event data and additional metadata about the event.  Event data consists of formatted fields that the indexer extracts from the raw data. Event metadata includes, but is not limited to, the following:

Host: The device that generates the event.

Source: Where the event originates, such as a data file.

Sourcetype: Sourcetypes determine how incoming data is formatted.

Event metadata is stored in the default fields of an event. These default fields are shared between all events within an index and are usually great places to start a search query.

﻿

Fields
﻿

A field is a searchable name-value pair within data. For example, a field named ComputerName may contain the machine name of the computer on which a particular event occurred. Fields are the building blocks of searches within Splunk.

﻿

Sourcetype
﻿

When an indexer processes an event, it tries to identify the data structure of the event. An event’s data structure describes the different fields in an event. The data structure contains information that a Splunk indexer uses to parse the event into those different fields. The sourcetype default field for the event stores the name of the data structure parsing that event.

﻿

All events of a specific sourcetype have similar fields within them. For example, events with a sourcetype of WinEventLog:Security are from security-related Windows events, which contain fields such as ComputerName and EventCode. Knowing the different sourcetypes available within a Splunk deployment enables analysts to quickly narrow down the scope of their search when searching across an individual sourcetype.

﻿

Processing Data
﻿

The next three terms refer to tools for processing data:

Lookups

Macros

Splunk Apps


Lookups
﻿

Lookups are tables that store field-value combinations. Analysts can write SPL to find data based on the information in a lookup and modify the lookup based on the results of the search. There are four types of lookups:

Comma-Separated Value (CSV) lookups: Tables of static data.

External lookups: Tables with Python scripts or binaries that pull data from an external source to enrich fields in search results.

Key-Value (KV) store lookups: Tables that match fields in an event to fields in a key-value pair collection to output corresponding fields from the collection to the event.

Geospatial lookups: Tables that match location coordinates in events to geographic feature collections to output fields to events, such as country, state, or county names.

An upcoming section of this lesson dives deeper into how to use Splunk SPL.

﻿

Macros
﻿

A macro is a reusable SPL code. Macros are similar to the functions in programming and can range from very complicated to very simple. Macros allow for modularity when writing SPL code, which improves code reusability.

﻿

For example, a detection engineer uses a macro containing the SPL query action=allowed across multiple searches in Splunk. The engineer is notified that alerts do not work on certain vendor logs. This is due to the vendor logs using the SPL action=accepted instead of action=allowed. Since the engineer uses macros in the code, the engineer is able to update the macro to include an “or” statement to also look for action=accepted. This is more efficient than going through each and every SPL query the engineer had previously made and updating them manually. 

﻿

Splunk Applications
﻿

Splunk applications extend Splunk functionality. Applications are installed from Splunkbase. The options range from vendor-specific applications that assist with standard parsing to applications that contain dashboards and reports for threat hunting. The exercises in this lab leverage some popular applications for working with Splunk data.

﻿Sending Logs to Splunk
Logs are sent to Splunk through forwarders. The most common forwarder is the universal forwarder. The universal forwarder can be installed on both Linux and Windows. It has the following key configuration files:

inputs.conf controls how the forwarder collects data.
outputs.conf controls how the forwarder sends data to an indexer or other forwarder.
server.conf configures connection and performance tuning.
deploymentclient.conf configures deployment server connection.
﻿

While real-time logging is ideal, there are times when it is misconfigured or not set up. In these situations, it is extremely valuable to know how to import and parse a log export to be able to hunt on it. This can be done using a forwarder or using the Splunk front-end upload feature. One caveat for the upload feature is that file types .evt and .evtx do not upload correctly if they are exported from a different machine because they contain information that is specific to the machine that generates those logs. 

﻿

NOTE: This lesson uses the configuration files inputs.conf and output.conf in an upcoming exercise. Use the links provided in the Additional Resources section of this task to review the Splunk documentation for these files.

﻿

Parsing
﻿

Raw log parsing occurs on the Splunk indexer. Splunk handles most raw logs by default. However, for special cases, the configuration file props.conf is on an indexer that is used to set up custom file parsing and field extractions. Field extractions are used to assign data from a log to a field to make it searchable. An upcoming lab in this lesson covers configuring field extractions from the Splunk front end.

﻿What does Splunk use to make specific values from a log file searchable?
 Field Extractions

Hunting with Splunk SPL
SPL Review
﻿

SPL is used in Splunk the way the Kibana Query Language (KQL) is used in Elastic Stack. Using SPL syntax enables efficient searches across datasets. Inefficient searches may cause resource issues on the Splunk index that processes the search. This section introduces the following topics that help run efficient searches in Splunk using SPL:

Wildcards

Escape characters

Transforming searches

Common commands

Query optimization

Search mode selection

Wildcards
﻿

Wildcards allow searching for data that starts with, ends with, or contains a certain value. Wildcards, represented by an asterisk character (*), can be inserted into string search terms to indicate this type of search in a specific location in the string. For example, the search host="cda*” matches against all host values that have “cda” as their first three letters. Examples of host values that successfully match this wildcard query include the following:

cda-win-hunt

cda-acct-1

cdathis-is-not-a-real-machine-name-but-would-be-matched-anyway

This matches because the wildcard can represent an infinite amount of characters.

cda

This matches because the wildcard can also represent zero additional characters after the preceding string.

Although wildcards are useful, they are also inherently more resource-expensive than searching for a specific value. If wildcards are unavoidable, place them at the end of a search value, if possible. For example, searching host="cda*” is more efficient than searching host="*hunt”. Neither of these is as efficient as a more precise search such as host="cda-win-hunt".

﻿

Escape Characters
﻿

The Splunk search head accepts special characters that serve specific functions in a query. When the search head identifies a special character in the query, rather than treating the character as a literal part of the query string, it interprets it as instructions for how to handle the query. For example, the equal sign (=) is a special character in Splunk. Instead of the search head reading it as an equal sign, it identifies it as a special character that separates field names from the value in the query. The type of action the search head performs depends on the special characters the search head encounters in the query.

﻿

The backslash character is a special character within the Splunk query language. The backslash character is known as an escape character. The parser reads any special character as a literal character if an escape character immediately precedes it. This makes it possible to include special characters in a search term without compromising the intent of a query through special functions. For example, a field being searched may include a quotation mark, which is another special character. Adding a backslash before the quotation mark, as in the query field=value_\"to_find, forces the parser to ignore the special function of the query and read the literal quotation mark.

﻿

To force Splunk to interpret a backslash literally, an additional backslash must be added. The first backslash escapes the second, preventing it from being treated as a special character. 

﻿

Transforming Searches
﻿

Transforming searches are where the real power of Splunk lies. A transforming search answers the following extremely specific questions:

What accounts have logged into more than one machine?

What accounts log in most often across the network?

Over which hours does login activity in the network usually occur?

The first step in using a transforming search is to use a raw event search to retrieve events. Then, use the pipe (|) to pass the events into one or more search commands. A search command transforms events and other data into a new format. Multiple search commands can be chained together by separating them with additional pipe characters. In chained commands, the output from one search command becomes the input for the next search command in the chain.

﻿

Common Search Commands
﻿

Splunk has many different search commands built into it. Some of the most common search commands and their functions include the following in Table 2.2-1, below:

The Splunk Command Types page, listed in the Additional Resource section of this task, provides more information about the usage of these and other commands. Selecting the name of a command provides a complete description and examples of the full usage of that command.

﻿

Query Optimization
﻿

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

host="cda*" | stats count by host, EventCode | where EventCode=4688
﻿

Query 2

host="cda*" | where EventCode=4688 | stats count by host, EventCode
﻿

The Splunk documentation provides more information about the different types of commands available. The Splunk Command Types reference document also provides a list of commands broken out by type.

﻿

Search Mode Selection
﻿

Another simple way to improve search efficiency is to use the Splunk search mode selector drop-down, under the search magnifying glass. As displayed in Figure 2.2-4, this drop-down offers three search modes: Fast, Smart, and Verbose. Splunk uses Smart mode by default.

﻿Aggregate Using Stats
Hunting through large data sets can feel like trying to find a needle in a haystack. Using a command like stats increases the efficiency of a hunt. The command stats is a very useful SPL command in search log aggregation because it helps sift through large datasets. Below, use stats to comb through large data sets to find malicious activity.
﻿

5. Run the following search to return the dataset auth.log that was imported in the previous lab:

source="auth.log" host="hr-data" sourcetype="linux_secure"
﻿

6. Search this dataset for threats by appending the following commands to the search, as displayed in Figure 2.2-5, below:

| eval ENV=if(isnull(ENV),"na",ENV) | stats count by host, real_user, process, USER, ENV, COMMAND

This command breaks down the dataset from over 700 entries to 20 entries that are easier to review. It also evaluates the ENV field, filling it in with the string na if it is found to be null. The results, as displayed below in Figure 2.2-6, shows that the user jimmy attempted several privilege escalation methods.

Using the command stats greatly increases the efficiency of hunting through large datasets. This lab provides a simple example of how to use it. Explore the Splunk documentation listed in the Additional Resource section of this task to learn more about ways the command stats helps organize large datasets.

﻿Operationalizing Hunt Searches
Running SPL queries to hunt for data is only the first step of utilizing Splunk for threat hunting. Once a search has been created it must be operationalized. Creating dashboards, reports, and alerts makes SPL queries much more efficient to use regularly for hunts. While dashboards, reports, and alerts can be manually created based on hunts, there are numerous Splunk applications that have sets of pre-loaded dashboards, reports, and alerts to save time for analysts. This task describes each of these options in greater detail.

﻿

Dashboards
﻿

A dashboard is a custom page created within a Splunk instance that contains individual panels. Each panel can be a saved visualization, search, or report. A properly made and maintained dashboard provides quick insights into potentially interesting activity within an environment. This helps with identifying suspicious activity.

﻿

Reports
﻿

A report is the easiest way to operationalize a query. In its most basic form, a report is a saved search that is accessible to many analysts.

﻿

Alerts
﻿

An alert is a combination of a saved search, a trigger, and an alert action. When the saved search meets the trigger conditions, the alert action responds in a predetermined fashion. For example, the alert may send an email notification or activate a webhook. Analysts may create alerts that are either scheduled to run on intervals or set up to respond in real-time. Creating and maintaining a set of real-time alerts further stretches Splunk’s capabilities and allows it to perform as a SIEM solution.

﻿

Splunk Applications
﻿

An example of a useful application for threat hunting is an app called ThreatHunting by Olaf Hartong. The application provides several dashboards and over 120 reports built for threat hunting using Sysmon logs. ThreatHunting uses the MITRE ATT&CK® framework to map most of the searches. More information about the dashboard is available in the resources section, below.

﻿

Another application is the Sysmon App for Splunk by Michael Haag, also known as the “Sysmon Splunk app.” This lesson explores this app in an upcoming lab.

﻿

Using reports, alerts, and dashboards enables CPTs to quickly implement real-time monitoring and alerting in environments where other options may not be available. CPTs use Splunk to quickly operationalize intelligence reports, hunting results, and proposed detection rules in a fully automated fashion.

Use Sysmon App for Splunk
Haag’s Sysmon App for Splunk is one of many apps that provide pre-built resources for threat hunting. Use the Sysmon App for Splunk to explore how powerful a dashboard can be as a tool in the threat hunting arsenal.


5. Select the time drop-down that currently displays 24 hours and change it to All time. 

﻿

6. Select the green submit button.

﻿

NOTE: The time range needs to be updated each time a new dashboard is opened in this app. This lab uses All time since the lab has limited logs. Use All time sparingly in a live production Splunk environment as it is taxing on resources.

﻿

7. Explore the rest of the dashboards in the Sysmon App for Splunk and consider what other dashboards can be created to aid in threat hunting.

﻿

8. Edit dashboards by selecting Edit in the top right corner of the page.

﻿

9. View the source by selecting Source on the top left side of the screen, to see how the dashboards are built, as displayed below in Figure 2.2-7.

10. Modify the panel Events Count by User to count by User and Computer.

﻿

11. With the Sysmon Overview Source page open, press ctrl+f and search for Events Count by User.

﻿

12. Under <title>Events Count by User</title> there is a <query> section. Update the query so that the stats command is also grouping by Computer.

﻿

13. Click the green Save on the top right of the page and make sure all the panes properly load.

﻿

Use the information in this lab to answer the next Knowledge Check.

Using Sigma Rules in Splunk
Writing Sigma Rules
﻿

Sigma is a signature format for writing SIEM agnostic queries. Sigma is a generic rule language for log files, just like Snort is for network traffic and Yet Another Recursive Acronym (YARA) is for files. Sigma rules are written in the format YAML Ain't Markup Language (YAML). The Sigma repository includes the tool Sigmac to translate the rules into SIEM-specific query languages. The tool Uncoder.io is also available for Sigma rule translations. It is a web app provided by SOC Prime.

﻿

Figure 2.2-8, below, describes the different elements of the Sigma rule format and their requirements. It is encouraged to fill out as many fields as possible, however, not all of the fields are required. According to the Sigma documentation, the only required fields are title, logsource, detection, and condition.


Translating Sigma Rules
﻿

Sigmac is a command line tool written in Python. Sigmac translates Sigma rules into SIEM-specific query languages. For Sigmac to work, users must set up the configuration file that contains mappings for the target environment. This ensures that items such as index names and field names align with the target environment. An upcoming lab provides an opportunity to explore this tool more closely.

﻿

A useful tool to use with Sigmac is Sigma2SplunkAlert by Patrick Bareiss. This tool converts Sigma rules to SPL and outputs the full Splunk alert configuration.

﻿

Using Uncoder.io
﻿

Uncoder is a web app that allows for easy Sigma translation to a host of SIEM query languages. Since SOC Prime is in the business of selling access to their correlation rule library, they have some free rules to translate by using the drop-down at the top of the Uncoder page, as highlighted in Figure 2.2-9, below. On the left side of the page in the figure is the Simga rule and on the right side is the translation of the rule into an SPL query.


The downside of Uncoder is that there is no way to set up mappings so that the output aligns with the target environment's field mappings. Analysts must complete this manually on the query.

python sigmac -t splunk -c splunk-linux-custom C:\Users\trainee\Desktop\tools\sudo_priv_esc.yml | clip

Endpoint Visibility Techniques
Endpoint visibility is primarily achieved in one of two ways:

Log Collection: The logs of significant events on a system are collected by log aggregation software and shipped to a central Security Information and Event Management (SIEM) platform.

Endpoint Detection and Response (EDR): An EDR agent is placed on monitored systems to send back custom data and traces of system activity to the SIEM. 

Log Collection
Events that occur in endpoint devices or Information Technology (IT) systems are commonly recorded in log files. Operating systems record events using log files. Each operating system uses its own log files. Applications and hardware devices also generate logs. 

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

Endpoint Detection & Response (EDR)
﻿

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

﻿Endpoint Visibility Tools
After determining which endpoint visibility technique or combination of techniques are best suited for a mission partner’s existing architecture, a security team must consider which tool is suited for the needs of the environment and the systems on which it is deployed.

﻿

Log Collection Tools
﻿

Elastic Beats
﻿

Elastic Beats are applications which ship data from the endpoints on which they are installed to a portion of Elastic Stack for processing and delivery to the Elasticsearch data store. They are open and free and designed for a variety of operating systems. They may be configured to send data to Logstash or Elasticsearch, depending on the configuration of the security architecture. 

﻿

Winlogbeat
﻿

Winlogbeat is an Elastic Beat specifically designed to operate on Windows systems and utilize the application programming interface (API) to read and ship Windows Event Logs. It may be configured to capture events from any of the default Windows logs, such as Application, Security, and System, or to collect other application- or hardware-specific events, such as logs generated via Sysmon. 

﻿

Auditbeat
﻿

Auditbeat is available for both Linux and Windows operating systems. It is used to send audit events to the Elastic Stack, which include user and process activities that the application is configured to monitor. It may be installed with one of several modules which dictate its behavior. The Auditd module is exclusively for Linux hosts and interfaces with the kernel’s auditd service to capture and ship kernel audit events, such as network connections, file access, system calls, and changes to user information. The File Integrity module is used to monitor specific files and folders for changes, with additional metadata and file hashing added to the events shipped to Elastic. The System module is used to detect state changes and significant events regarding logins, uptime, installed packages, running processes, network sockets, and users. 

﻿

Filebeat
﻿

Filebeat is a lightweight solution for shipping new lines of logs or files to Elastic. There are dozens of modules that are precisely tailored to collect and parse logs for their respective applications, such as Apache, MongoDB, Office 365, and Zeek, among many others.

﻿

EDR Tools
﻿Endpoint Visibility Tools
After determining which endpoint visibility technique or combination of techniques are best suited for a mission partner’s existing architecture, a security team must consider which tool is suited for the needs of the environment and the systems on which it is deployed.

﻿

Log Collection Tools
﻿

Elastic Beats
﻿

Elastic Beats are applications which ship data from the endpoints on which they are installed to a portion of Elastic Stack for processing and delivery to the Elasticsearch data store. They are open and free and designed for a variety of operating systems. They may be configured to send data to Logstash or Elasticsearch, depending on the configuration of the security architecture. 

﻿

Winlogbeat
﻿

Winlogbeat is an Elastic Beat specifically designed to operate on Windows systems and utilize the application programming interface (API) to read and ship Windows Event Logs. It may be configured to capture events from any of the default Windows logs, such as Application, Security, and System, or to collect other application- or hardware-specific events, such as logs generated via Sysmon. 

﻿

Auditbeat
﻿

Auditbeat is available for both Linux and Windows operating systems. It is used to send audit events to the Elastic Stack, which include user and process activities that the application is configured to monitor. It may be installed with one of several modules which dictate its behavior. The Auditd module is exclusively for Linux hosts and interfaces with the kernel’s auditd service to capture and ship kernel audit events, such as network connections, file access, system calls, and changes to user information. The File Integrity module is used to monitor specific files and folders for changes, with additional metadata and file hashing added to the events shipped to Elastic. The System module is used to detect state changes and significant events regarding logins, uptime, installed packages, running processes, network sockets, and users. 

﻿

Filebeat
﻿

Filebeat is a lightweight solution for shipping new lines of logs or files to Elastic. There are dozens of modules that are precisely tailored to collect and parse logs for their respective applications, such as Apache, MongoDB, Office 365, and Zeek, among many others.

﻿

EDR Tools
﻿

Examples of EDR tools that may be deployed in mission partner environments are Wazuh, Elastic Endpoint Security Agent, and Carbon Black.

﻿

Wazuh
﻿

Wazuh is an updated version of the Operating System Security (OSSEC) endpoint agent. The agent is designed to deliver data relevant to threat detection, security monitoring, and incident response. The principal mechanism that determines what data is returned from an agent to the Wazuh manager is Wazuh rules, many of which are combined in the configuration to form an agent’s Ruleset. Rules are constructed to filter all system activity through regular expressions to extract fields and values of interest. By default, Wazuh provides a robust ruleset for initial installation. Any events that pass the rule filters are sent to the Wazuh manager as alerts via JavaScript Object Notation (JSON). 

﻿

Elastic Endpoint Security Agent
﻿

The Elastic Endpoint Security Agent that is integrated into the Elastic Stack is the Elastic Agent, which may be installed with the Endpoint Security integration. This EDR solution was formerly known as Endgame. In its current form, Endpoint Security provides kernel-level data visibility and antivirus protection to the endpoint on which it is installed. It also integrates osquery for inspection of host health and state. Osquery is a tool that gathers data about operating system performance in a central database for easy querying.

﻿

Carbon Black
﻿

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

Wazuh
﻿

Wazuh is an updated version of the Operating System Security (OSSEC) endpoint agent. The agent is designed to deliver data relevant to threat detection, security monitoring, and incident response. The principal mechanism that determines what data is returned from an agent to the Wazuh manager is Wazuh rules, many of which are combined in the configuration to form an agent’s Ruleset. Rules are constructed to filter all system activity through regular expressions to extract fields and values of interest. By default, Wazuh provides a robust ruleset for initial installation. Any events that pass the rule filters are sent to the Wazuh manager as alerts via JavaScript Object Notation (JSON). 

﻿

Elastic Endpoint Security Agent
﻿

The Elastic Endpoint Security Agent that is integrated into the Elastic Stack is the Elastic Agent, which may be installed with the Endpoint Security integration. This EDR solution was formerly known as Endgame. In its current form, Endpoint Security provides kernel-level data visibility and antivirus protection to the endpoint on which it is installed. It also integrates osquery for inspection of host health and state. Osquery is a tool that gathers data about operating system performance in a central database for easy querying.

﻿

Carbon Black
﻿

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

YARA Rules for Endpoint Hunting
Another powerful tool for hunting for malicious traces on endpoints is the use of YARA rules for identifying malicious files. YARA (which means YARA: Yet Another Recursive/Ridiculous Acronym) is a pattern-matching tool and standard used by malware researchers to represent fluidly the many malicious files introduced into modern environments every day.

﻿

Each rule requires three sections: a meta section, a strings section, and a condition section.

﻿

Meta
﻿

The meta values are arbitrary key-value pairs that provide enough information to describe the rule, its context, and for what types of files it should be used. Author information and when the rule was created or published are helpful for those who may follow up about rule updates or currency of the signatures contained in it.

﻿

Strings
﻿

The strings section contains hexadecimal or American Standard Code for Information Interchange (ASCII) values to represent data in a file that may identify it as malicious. These strings are referred to with variable names that take the following form:

$name = "value"
﻿

For hexadecimal data, the string variable takes the following form, in which braces enclose the hexadecimal values:

$name = { 01 23 45 67 89 0A BC DE }
﻿

The challenge with choosing good strings for malware rules is to make the strings specific enough to reasonably indicate a file for further inspection, but not so specific as to be no more useful than a file hash. 

﻿

Condition
﻿

The condition value is a Boolean expression that refers to strings using their variable names. The Boolean operations and and or are used to create the condition by which a file is identified as malicious using a given rule. 

﻿

The following conditions are also valid:

any of them: matches if any one string is present.
all of them: matches only when all strings are present.
3 of them: matches if any three strings (but at least three) are present.
﻿

Example rule:

rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
    condition:
        $a or $b or $c
}
﻿

In this rule, if one or more of the specified strings exist in a file, the file matches this YARA rule and is identified by the YARA tool. 

﻿

Writing YARA rules for Endpoint Hunting
﻿

Using an understanding of how and why to create and use YARA rules, create a YARA rule to hunt for malicious Microsoft Office documents and use the rule to find such a document on a mission partner’s workstation. Threat Intelligence indicates that this type of malware delivery is being actively employed against the environment in phishing attempts to gain continued access to additional workstations. 

﻿

1. Log in to the VM eng-wkstn-1 with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Create the file rule.yar on the desktop using Notepad++

﻿

3. Enter the following lines which initiate the rule declaration:

rule Contains_VBA_macro_code
{
﻿

4. Enter the following lines to fill in meta information:

meta:
	author = "yournamehere"
	description = "Detect a MS Office document with embedded VBA macro code"
	date = "YYYY-MM-DD"
	filetype = "Office documents"
﻿

5. Enter the following lines to add strings that are unique to Microsoft Office file types:

strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"
﻿

The initial hexadecimal bytes of a file’s binary data are known as the “magic” bytes. The two lines above declare the magic bytes for legacy Microsoft Office documents and for zip files, which is how modern Office documents, such as those with the extensions .docx and .xlsx, are actually packaged.

﻿

6. Enter the following lines to add strings that indicate Visual Basic for Applications (VBA) code in a legacy Office document:

		$offstr1 = "_VBA_PROJECT_CUR" wide
		$offstr2 = "VBAProject"
		$offstr3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }
﻿

7. Enter the following lines to add strings that indicate Visual Basic code in a zip file:

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"
﻿

8. Enter the following lines to create the condition by which a file matches this rule:

	condition:
		($officemagic at 0 and any of ($offstr*)) or ($zipmagic at 0 and any of ($xmlstr*))
}
﻿

This condition essentially matches the magic bytes of the Office file types and any of the strings which indicate VBA code for that respective file type. 

﻿

9. Open a PowerShell terminal as Administrator.

﻿

10. Run the following command to use the YARA rule to inspect all files in the trainee user’s folders. This command uses the -rn switch to list all files which do NOT match the YARA rule. While there is no guarantee that those files are safe, they do not contain VBA code.

& "C:\Program Files\yara\yara64.exe" -rn C:\Users\trainee\Desktop\rule.yar C:\Users\trainee\Documents\
﻿


11. Run the following command to use the YARA rule to inspect all files in the trainee user’s folders again, this time searching for files that match the rule by using the -r switch:

& "C:\Program Files\yara\yara64.exe" -r C:\Users\trainee\Desktop\rule.yar C:\Users\trainee\Documents\

Network Visibility
Host Versus Network Analysts
﻿

Analysts use different tools and approaches to track host and network activity. This is why it is sensible to have both host and network analysts on the same defense team. Although the roles may be different, each type of analyst benefits from some level of collaboration and understanding of what the other does. It is important for host analysts to understand the capabilities of network analysts and work closely with them. Collaboration includes tipping activity from host or network events to fellow analysts to identify relevant activity. Additionally, host network logs are limited in what they provide host analysts. 

﻿

To build a more complete picture of network activity, analysts must use sensors to capture and categorize activity across the network. This activity is available in the pre-built dashboards in Security Onion, as well as tools such as Arkime, both of which are described below.

﻿

Security Onion Dashboards
﻿

Security Onion is one tool that provides hosts analysts a more complete picture of the network. Security Onion has built-in dashboards that help analysts perform network visibility tasks during a hunt. There are also other dashboards for network data sources, such as Zeek and Suricata, that can all be used for viewing network logs and activity. Security Onion parses the logs from each host and presents them in different style dashboards that can have different filters applied to view the logs. The information that these tools provide can often be used to further an investigation by providing evidence for a hunt. Security Onion has dashboards from the following tools:

Sysmon

Zeek

Snort and Suricata

Sysmon Network
﻿

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

Zeek
﻿

Zeek is used for analyzing network traffic and detecting anomalies on a network. Zeek converts data about network traffic into events and uses a script to translate what those events mean to the security of the network. The metadata that Zeek produces includes connection records, the volume of packets that are sent and received, information about TCP sessions, and other useful data that analysts can use during a hunt.  

﻿

Zeek also has its own programming language, similar to Python, that allows Zeek the ability to have custom network analysis for any environment. Zeek has capabilities such as extracting files from Hypertext Transport Protocol (HTTP) sessions for analysis or detecting malware by interfacing with external registries.

﻿

Similar to Sysmon, Security Onion contains multiple pre-existing dashboards for Zeek that include data such as file names, file sizes, and the source and destination IP addresses of the hosts transferring files. The Zeek dashboard also provides HTTP header information such as the UserAgent, HTTP method, virtual host, and Uniform Resource Identifier (URI). 

﻿

An analyst can use the IP address that was discovered to be in the public range from the previous example to filter out any traffic that had that IP address as the destination. With Zeek, the analyst may also discover any files sent to or from the suspicious host and investigate them as part of the hunt. Using multiple different dashboards and tools during a hunt allows analysts to view data from different angles and pull more data than what one tool offers.           

﻿

Snort and Suricata
﻿

Snort is an open-source Intrusion Prevention System (IPS) that uses a collection of rules to help detect and define malicious activity on a network. Snort detects many different attack methods such as denial of service, buffer overflow, stealth port scans, and distributed denial of service. Snort also finds packets that match the rules so it can alert users. Analysts can configure these rules by changing the variable settings located in the file module.d/snort.yml or by using the command line to override the settings. Each fileset has its own variable settings that analysts can configure to change the behavior of Snort. Snort uses the default configuration when variable settings are not specified. 

﻿

Suricata is very similar to Snort and is also an open-source software that has a network threat detection engine that provides IPS and network security monitor capabilities. Suricata has a dynamic protocol protection capability that is port-agnostic. This allows Suricata to identify some of the more common application layer protocols such as HTTP, Domain Name System (DNS), and Transport Layer Security (TLS), when they are communicating over non-standard ports. 

﻿

Similar to the other tools, Security Onion has built-in dashboards to view alerts from Snort and Suricata. This dashboard contains information such as a list of the rules, source IP address, destination IP address, and destination port. The dashboard also breaks down the rules by severity, category, and rule ID. Additional filtering options are also available. For example, if an analyst wants to only see data under "high" severity rules, they can implement a filter for it. This filter presents the traffic that the rules pick up, which would be related to any high severity events. Suricata also allows analysts to filter out events based on the rule category, such as "Potentially Bad Traffic,” to further filter out traffic during a hunt.             

﻿

Arkime 
﻿

Arkime, formerly known as Moloch, is another tool that can capture the same data as Security Onion. Arkime is a large-scale packet capture and search system that analysts can use to index network traffic in PCAP format. Arkime also provides an index of network sessions. Arkime uses a simple web interface system for PCAP browsing, searching, and exporting. This tool also exports all packets in standard PCAP format. Analysts can also use ingesting tools, such as Wireshark, during PCAP analysis.   

﻿

Arkime allows analysts to create custom rules that specify actions for Arkime to perform when certain criteria or fields are met. The rule files are in the format Yet Another Markup Language (YAML) and are specified in the file config.ini using the setting rulesFiles=. Analysts can have multiple files, using a semicolon-separated list, and include multiple rules in each file. Each rule must have certain values met in order to properly run.

﻿Detection Engineering
Situations may also exist in which analysts do not have access to a full Security Information and Event Manager (SIEM), such as Splunk or Security Onion, to aid in the hunt. In these instances, other tools may be easily deployed to quickly parse collected logs or analyze network traffic captures. This section introduces Jupyter Notebooks and Suricata rulesets and how to use them to streamline a hunt.﻿

﻿

Jupyter Notebooks
﻿

Project Jupyter is an open-source project that creates interactive computing across many different languages. Project Jupyter is most known for Jupyter Notebooks, a software suite for creating interactive web pages for organizing code and documentation. 

﻿

Jupyter Notebooks provides access to notebooks through a web interface that allows users to save input and output of interactive sessions as well as any important notes. With Jupyter, analysts can create and share documents that contain live code, equations, visualizations, and text. Jupyter supports over 40 programming languages, although it was originally built for Python. 

﻿

Analysts can use Jupyter notebooks to analyze logs and events through interactive Python scripts. While there are plenty of pre-built scripts publicly available, analysts can also create their own set of scripts and use them in any environment they wish, with Jupyter Notebooks. Any existing scripts can be uploaded to a running instance of Jupyter Notebooks and used to analyze the logs that are ingested. This is helpful if a CPT wishes to view data from a different perspective or if they wish to document any findings for future use. This is also useful when a log aggregator and indexing solution, like Elastic, is not available.

﻿

Suricata Rules
﻿

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

alert http any any -> any any (content:"index.php"; http_uri; sid:1;)
﻿

Options always have at least one keyword, however not all options have settings. Options such as content have settings that are specified by the keyword of the option. These are written as the keyword, followed by a colon and the settings, as in <keyword>: <settings>. The example above includes two keywords. The first is the keyword content with the setting "index.php". The second keyword is sid with the setting 1.

﻿

Options such as http_uri do not have settings. These options are simply written with their keywords followed by a semicolon, as in the example of http_uri in the complete rule option, above.

﻿

Some keyword functions act as modifiers. The two types of modifiers are content modifiers and sticky buffers.

﻿

A content modifier looks back in the rule. In the previous example of the complete rule option, the pattern "index.php" is modified to inspect the HTTP uri buffer. This example is repeated below:

alert http any any -> any any (content:"index.php"; http_uri; sid:1;)
﻿

A sticky buffer places the buffer name first. All keywords that follow it apply to that buffer. In the following example, the pattern "403 Forbidden" is inspected against the HTTP response line because it follows the keyword http_response_line:

alert http any any -> any any (http_response_line; content:"403 Forbidden"; sid:1;)
The following is an example of a full signature that comprises options with and without settings, as well as modifiers:

alert dns 172.0.0.0/24 any -> $EXTERNAL_NET 53 (msg: "GMAIL PHISHING DETECTED"; dns_query; content:"gmail.com"; nocase; isdataat:1, relative; sid:2000; rev:1;)
﻿
Windows Logging Basics
What Are Windows Event Logs?
﻿

Windows event logs are logs that are stored in the proprietary data format evtx. While these logs are not tamper-proof, they are difficult to modify. This means attackers typically either leave the logs or delete all of them, leaving only a log stating that the event logs were cleared.

﻿

Depending on the version of Windows, the default location for event logs is C:\WINDOWS\system32\config or C:\WINDOWS\system32\winevt. However, analysts can configure this location through the command wevtutil. This command can be used to view, export, archive, and clear Windows event logs.﻿﻿

﻿

Windows Event Log Categories
﻿

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

Auditing Policy
﻿

Event logs are customizable since the system needs to be configured to audit specific things. An audit policy can range from broad to specific, spanning a series of categories and subcategories. The policy may enable all categories or focus on only certain subcategories. An audit policy may even include different configurations based on the user.

﻿

The attachment for this task card, available on the right-side panel, presents these categories and their subcategories. The subcategories take precedence over the categories they are grouped under. If there is a conflict in the policy, the subcategory-based policy is enabled.

﻿

The command auditpol displays the categories and subcategories using the Windows command line. To list all subcategories, enter the following command:

auditpol /list /subcategory:*
﻿

The following command lists the current policy:

auditpol /get /category:*
﻿

Enabling a Specific Policy to Log a Specific Event
﻿

The following scenario is an example of when an analyst may need to enable a specific policy to allow a specific event to be logged. 

﻿

Scenario

﻿

Threat actors use Security Identifier (SID) history injection to manipulate user tokens in a Windows enterprise network environment. SID history supports account migration from one domain to another while retaining previous permissions. The injection attack works by informing an account that the user had access to something from an old domain and should still have access, but also requires domain administrator permissions.

 

In this scenario, an analyst looks up the Microsoft documentation and discovers that Event ID 4765 SID History was added to an account was logged when this technique was executed. The Microsoft documentation for this event labels the subcategory as Audit User Account Management. To enable this log, the analyst must enable this subcategory.

﻿

Use the following command to enable this policy:

auditpol /set /Category:"User Account Management" /success:enable
﻿

Summary
﻿

Windows event logs are stored in a proprietary file format evtx. They are located on the hard disk as a file and can be manipulated with the command wevtutil. The events that get logged are set by the audit policy, which analysts can manipulate on the command line with the command auditpol. Analysts can easily determine what settings to enable for a specific event log by referencing Microsoft documentation.

﻿Windows Logging Options
Configuring a robust logging solution comprises more than just configuring the subcategories in the audit policy. There are several powerful ways to get more robust logging out of a Windows system. These ways also allow more effective log tuning to produce the data sources required to help analysts identify threat actors. The next few sections of this lesson introduce the logging options available in the following tools:

Native Windows
Sysmon
PowerShell specific options
Native Windows Logging Configuration Options
﻿

The security backbone of a Windows network starts with the native Windows logging options. The temptation is to enable all logging options, however excessive logging has additional costs that hamper proper defense. There are two locations on a system that allow malware to persist after a reboot. These are the file system and the registry.

﻿

File System Logging
﻿

File system changes create logs with the Event ID 4663: An attempt was made to access an object. This requires the following subcategories to be enabled:

Audit File System
Audit Kernel Object
Audit Registry
Audit Removable Storage
Registry Logging
﻿

The registry houses Windows configuration information and a significant amount of forensic data. Hundreds, if not thousands, of registry changes happen every minute. While logging registry changes create useful data, they create as much, if not more, unusable data.

﻿

Registry changes create the following event IDs:

4663: An attempt was made to access an object
4657: A registry value was modified

Sysmon Logging Options
Sysmon is a Windows system service and device driver that augments the Windows event logging abilities. Its name is an amalgamation of system and monitor. Sysmon has the potential to create an excessive amount of logs, but this can be configured to meet analyst needs.

﻿

Sysmon is capable of producing only the events listed below. However, these events have been developed to compensate for shortcomings found with the native logging capabilities. Even though Sysmon has been purposely designed to augment native logging, not every event is equally significant. Below are the events supported by Sysmon version 13.33, which was released February 2, 2022.

﻿

Sysmon Events
Event ID 1: Process creation

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

Recommended Configurations
﻿

The PDF attachment Sysmon Logging Options provides a table with several different categories of recommendations for a Sysmon configuration. This figure includes any Windows event IDs that overlap with the listed Sysmon IDs. The table provides notes for each event type, as well as how much noise the event generates. The final column provides examples of offensive tactics from the MITRE ATT&CK® framework that the Sysmon event is expected to log. The recommendations in the table are explained in more detail below. 

﻿

Critical
﻿

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

Overlapping
﻿

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

Threat-Specific
﻿

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

Extensive Filtering
﻿

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

SwiftOnSecurity 
﻿

SwiftOnSecurity is the social media handle for a computer security expert and industry influencer who pretends to be the singer-songwriter Taylor Swift. As of February 2022, they have over 340K followers. The name was chosen as a playful nod to Taylor Swift's caution with digital security.

﻿

The SwiftOnSecurity security researcher, arguably, has the industry-standard Sysmon configuration available on their GitHub account. The configuration file is about 1200 lines long and has multiple comments throughout. A version of this configuration is attached to this task for reference.

﻿

This configuration provides a starting point for filtering events. Some of the events included in the file are named with the MITRE ATT&CK technique that prompted the creation of the rule. The two main approaches to filtering these events are to either only include known-bad events or to only exclude known-good. The SwiftOnSecurity Sysmon configuration for Event ID 12: Registry event, object create/delete is an excellent example of matching on known-bad.

PowerShell Logging Options
PowerShell auditing is incredibly useful for a defender. PowerShell scripts are not normally executed by users, yet are frequently leveraged to execute most Windows exploitation techniques. PowerShell is not just a scripting language, it has the same power as a compiled binary. PowerShell is so integral to Windows exploitations, Microsoft released a patch to add additional logging capabilities in an effort to combat hackers. PowerShell logs contain information regarding PowerShell operations, such as starting and stopping the application, cmdlets used, and files accessed. PowerShell logs may be accessed in a variety of channels, such as directly within a PowerShell session or within the C:\Windows\System32\winevt\Logs directory. PowerShell logging does not work like other native Windows logging categories. It is verbose enough that Sysmon created specific events for PowerShell. Examples of useful Windows Event IDs are as follows:﻿﻿

4688: A new process has been created: New PowerShell commands create the following event when the subcategory Audit Process Creation is configured.

400: Engine state is changed from None to Available: Details when the PowerShell EngineState has started.

800: Pipeline execution details for command line: Write-Host Test: Details the pipeline execution information of a command executed by PowerShell.

Enhanced PowerShell Logging
﻿

Although Microsoft designed PowerShell as a useful tool for administrators, it became a prized tool for hackers, as well. PowerShell works on the Microsoft .NET framework, which borrows its design pattern from the programming language Java. The Java language design minimizes compile times and allows software to work on various types of processors. This makes PowerShell more than just a command-line administration tool. The Java-based design of the .NET framework enables PowerShell to have the exact same capabilities of compiled software, but without requiring a binary on the system.

﻿

The hacking world rapidly adopted PowerShell-based exploitation techniques due to these capabilities. Microsoft responded by adding enhanced PowerShell logging features. Windows 10 has enhanced PowerShell logging natively. Older versions of Windows may need updates to provide enhanced PowerShell logging. This layered approach means that the configuration of PowerShell logging is non-conventional and is not configured the same as other logging. The enhanced PowerShell logging introduced in 2015 has three configurable logging capabilities:

Module logging

Script block logging

Transcription logging

Module Logging
﻿

PowerShell Module Logging records the commands executed and portions of the scripts, but does not deobfuscate all code. This means attackers can create code that is intentionally obscure and confusing. To enable module logging, make the following changes to the registry:

HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging
EnableModuleLogging = 1
﻿

This enables logging for the following Event ID:

4103: Executing Pipeline

﻿

Script Block Logging
﻿

Script block logging logs PowerShell scripts as they are executing within the PowerShell engine. This deobfuscates any PowerShell scripts. Prior to this feature, attackers would create scripts that appeared either benign or unintelligible, then the script would change itself just prior to execution. With script block logging enabled, the entire script is logged after it is processed. This shows the deobfuscated code to defenders. To enable script block logging, make the following changes to the registry:

HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1
﻿

This enables logging for the following Event ID:

4104: Execute a Remote Command

﻿

Transcription Logging
﻿

Transcription logging makes a record for every PowerShell session, including all input and output with timestamps. This is displayed at the command line terminal. To enable transcription logging, make the following changes to the registry:

HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription\
EnableInvocationHeader = 1
EnableTranscripting = 1
OutputDirectory = <path_to_directory>
﻿

This enables logging of the shell's transcript to the configured output directory. 

  Best Event Logs to Monitor
Defense is a filtering game, and the first detection is the most difficult. The decision of what is important for logging needs to be based on what battles can be easily won, given the available defender resources. An organization with many defensive analysts combing through their logs is more capable of investigating false positive alerts. On the other hand, an organization with only a few defenders needs to have a signature set that produces fewer false positives.

﻿

Because most organizations have limited resources, it is important to pinpoint the best event logs to monitor for a given network. The “perfect” logs to monitor are the exact logs that the attacker is creating. However, when “perfect” is not available, the following list provides logging configurations that are likely to be useful in today’s environment:

Legally required events

PowerShell events

Credential usage

Rare or unlikely events

Understanding the rationality of these configurations prepares defenders to better assess the options and opportunities unique to their organizations.

﻿

Legally Required Events
﻿

Depending on the organization, there may be various required security configurations. Government networks commonly must comply with Security Technical Implementation Guide (STIG) requirements. Although STIG requirements are not a tailored fit for every organization’s threat landscape, they provide a decent starting point. They are also mandatory. 

﻿

PowerShell Events
﻿

PowerShell-based tools are the easiest way to move laterally as well as have an easy, portable post-exploitation toolkit. Some of the most advanced techniques are now found as PowerShell scripts on various public blogs and GitHub repositories. As an attacker, public availability to these advanced techniques is great for two reasons. First, the techniques tend to work in most places. Second, it is difficult to determine who the attacker may be because open-source tools and techniques are available to everyone.

﻿

Credential Usage
﻿

Credentials are the inexpensive and easy way to access information by design. An offensive cyber campaign nearly always uses stolen credentials in some form. Defenders are often able to gather contextual information on users during deep, stateful searches of credential usage. Many reasons exist for a file to be on a system, but there are few reasons for someone’s account to log in when that person is scheduled to be on vacation.

﻿

Rare or Unlikely Events
﻿

Many defense organizations block every indicator of a threat group. Most of these indicators do not intimidate attackers because they are not usually aware of the blocks. Indicators of Compromise (IOC), such as file names, file hashes, domain names, and Internet Protocol (IP) addresses, are all easily changed. 

﻿

For example, in the early 2010s, the Air Force would receive threat intelligence information that would include the attacker’s commonly used redirectors. Attackers would mask where they were coming from by redirecting through a third party. It was a constant battle to prevent leadership from blocking that IP address. Imagine a hacker trying to connect to a target system from the other side of the planet but the disposable redirector not working on the first try. It is easy for the attacker to use a different redirector in this case. At the same time, the Air Force would have made a rule for that address because it would be rare to find legitimate traffic from that host.

﻿

Another example is an organization that may not see any reasonable business case for people working late. The organization creates time-based alerts for off-hours access to file systems. The organization may also consider disabling access after a certain time. However, it is just as easy to steal data during business hours as it is after business hours, which makes this measure ineffective. The only change from cutting off access would be in making detection more difficult.

Logging Options Summary
Logging too much is just as debilitating as not logging enough. Defenders need to manage a fine balance between these extremes to employ an optimal logging setup. The right setup allows defenders to obtain information that enables them to discover and thwart offensive attacks. 

Kerberos Logging
Kerberos Review
﻿

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

Expected Kerberos Logs
﻿

Each step of the Kerberos protocol is expected to create specific logs during normal operation. Recognizing which logs are expected helps defenders discern normal activity from unusual and possibly malicious activity. Each logging event listed below occurs in the DC.

﻿

Step 1: Request and Receive TGT
﻿

Requesting the TGT (AS_REQ)
﻿

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

Receiving the TGT (AS_REP)
﻿

For Kerberos to grant tickets based on permissions, Windows adds a Privilege Attribute Certificate (PAC) to the TGT. In Linux environments, this field is blank. The PAC includes the user's IDs as well as group memberships. This section is signed by the domain's Kerberos account on the DC: krbtgt.

﻿

Expected Logging

Event ID: 4768, A Kerberos authentication ticket (TGT) was requested.

Event Type: Success, when a TGT is returned.

Step 2: Request and Receive Service Ticket
﻿

Requesting the TGS (TGS_REQ)
﻿

After the TGT is issued, the user is authenticated to the domain. To gain access to a resource within the domain, the user's account needs to request a service ticket. This request requires the session key that was encrypted by the user's password hash from the previous step, as well as the TGT. Figure 2.5-8 illustrates this step.

﻿

﻿

Figure 2.5-8

﻿

Expected Logging

Event ID: 4769, A Kerberos service ticket was requested. 

Event Type: Failure, when a TGS request fails.

Receiving the TGS (TGS_REP)
﻿

The TGS includes a new session key for the service which is encrypted by the previous session key. The TGS is encrypted with the application server key so that it can be presented to the application service, in the next step, with the username and timestamp encrypted by the new session key.

﻿

Expected Logging

Event ID: 4769, A Kerberos service ticket was requested. 

Event Type: Success, when a TGS is returned.

Event ID: 4770, A Kerberos service ticket was renewed. 

Event Type: Only successful when the TGS is renewed.

Step 3: Request Access to the Resource
﻿

The final step, as illustrated in Figure 2.5-9, is the user's workstation presenting the TGS from step two to the application server for the resource. This step includes optional mutual authentication and an optional PAC check. The PAC check is discussed below.

﻿

﻿

Figure 2.5-9

﻿

Checking the PAC (optional)
﻿

Going back and having the application server verify the PAC sounds foolproof, but there are several important caveats that do not prevent any Kerberos-based attacks at this point. 

﻿

Make the following changes to the registry to enable this option:

HKLM/SYSTEM/CurrentControlSetControl/Lsa/KerberosParameters/
ValidateKdcPacSignature = 1
﻿

This option appears to provide no additional security. It is unclear the exact circumstances when Windows enforces PAC checking. Windows released a confusing statement about PAC checking in an official blog post describing the conditions when Windows would not check the PAC. What is clear is the only exploit that has manipulated a PAC was patched in 2014. Even with that patch removed and PAC checking enabled, security researchers have demonstrated successfully exploiting a DC with the silver ticket attack.

Kerberos Attack Logging
The chart provided in the PDF attachment for this task presents the most common and famous Kerberos attacks. The chart lists the attacker requirements for each attack and the logs generated. The logs are identified by color in the following way:

Green indicates useful logs that can be easily filtered and searched for. 

Blue indicates logs that appear similar to non-malicious logs and do not necessarily require action.

Yellow indicates logs that require greater context to find malicious activity.

This lesson discusses two attack techniques from this chart, in greater depth. These are “Pass-the-Ticket” and “Overpass-the-Hash”, which is also known as “Pass-the-Key (PTK)”. These techniques are not patchable and are likely to be seen in a contested Windows environment.

﻿

Pass-the-Ticket
﻿

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

Overpass-the-Hash/PTK
﻿

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


2. Open PowerShell as an Administrator.


3. Change the working directory to the trainee's desktop by entering the following command:
PS C:\Windows\system32> cd C:\Users\trainee\Desktop



NOTE: If the PowerShell terminal does not have administrative privileges, some log sources are not searchable by the executed commands. These privileges are necessary for this lab.


4. Declare the start time Mar 2, 2022 @ 16:00:00 as a variable by entering the following command:
PS C:\Users\trainee\Desktop> $start = "2022-03-02 4:00:00 PM"



5. Declare the end time Mar 2, 2022 @ 16:20:00 as a variable by entering the following command: 
PS C:\Users\trainee\Desktop> $end = "2022-03-02 4:20:00 PM"



6. Search for Windows PowerShell commands that happened between the selected times from the Windows_PowerShell.evtx file by entering the following command:
PS C:\Users\trainee\Desktop> Get-WinEvent -FilterHashTable @{path="Windows_PowerShell.evtx"; StartTime=$start; EndTime=$end}

 
The results, as displayed in Figure 7.5-20, are similar to viewing the logs Windows_PowerShell in the Event Viewer window. While the cmdlet Get-WinEvent has the option for -path, it is not compatible with the option FilterHashTable. The path needs to be specified as a key-value pair inside of a hash table object, as displayed in Figure 2.5-20.


7. Search for mimikatz across the Windows PowerShell log by entering the following command:
PS C:\Users\trainee\Desktop> Get-WinEvent -FilterHashTable @{path="Windows_PowerShell.evtx"; StartTime=$start; EndTime=$end} | Where-Object {$_.Message -Match ".*mimikatz.*"}



The final set of curly brackets in the command in Step 7 uses the notation $_ to declare a temporary variable for the item in the list. This means the function Where-Object is iterating over each item in the list and putting its value into that temporary variable. 


In this context the function Where-Object filters the results based on where the data is that matches the regular expression.


8. Search for mimikatz across all the event logs by entering the following command:
PS C:\Users\trainee\Desktop> Get-WinEvent -FilterHashTable @{path="*.evtx"; StartTime=$start; EndTime=$end} | Where-Object {$_.Message -Match ".*mimikatz.*"}



The command in Step 6 uses "glob" shell expansion within the path variable path="*.evtx" to specify all the saved event logs. Its output is displayed in Figure 2.5-21.

edit signa rules


  


