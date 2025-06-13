Directories for Internals
All Linux distributions use a standard directory tree as the file structure. These directories are included under the root directory, as displayed in Figure 5.1-1, below. This lesson focuses on /proc, /etc, and /boot because these are the main Linux directories that contain the internals necessary for a running Linux system. Each of these directories has a specific and important purpose. The information within these directories can be used by an analyst during a hunt in order to gain insight into the inner workings of a Linux system.

The directory /proc contains information about currently running processes and kernel parameters. The content within /proc is used by a number of tools to get vital system statistics and runtime system information. For example, the file /proc/cpuinfo has the information necessary to check processor information in Linux.

The directory /etc contains the core configuration files of the system. It is primarily used by administrators and Linux services and contains information such as the password and networking files. Most changes that are made to system configurations occur within /etc. 

The directory /boot contains the files of the kernel and boot image, in addition to Grub or other bootloaders. This directory contains everything required for the boot process. This directory often resides in a partition at the beginning of the disc. Bootloaders allow a user to select different kernel images to execute if there is more than one on the Linux system. If there is only one image, the bootloader loads and executes that image by default.

Manual Observation of Linux Host Processes
Linux Processes
﻿

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

Linux Commands for Analysis
﻿

There are multiple different tools that provide insight into the Linux processes. These tools can be used to gather information about the active processes, provide a real-time view of the kernel-managed tasks, or list out the files and processes that open them. This section reviews the following command tools:

Process status (ps)

Table of processes (top)

List of open files (lsof)

Process Status (ps)
﻿

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

Table of Processes (top)
﻿

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

List of Open Files (lsof)
﻿

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

Observe Linux Host Processes with Scripts
The commands in the previous section are useful for analyzing a process. However, when an analyst is investigating a Linux machine, there may be times when specific commands cannot be used or the commands that are being used do not provide a full picture of the process. In these cases, scripts can be created to further analyze a process and take an in-depth look at how the process is interacting with the Linux system.

﻿

Execute a Script to Further Analyze a Process
﻿

Find a process and execute a script to view detailed information about that process. 

﻿

Workflow
﻿

1. Log in to the VM kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1! 
﻿

2. Open a browser.

﻿

3. Open a terminal console.

﻿

4. In the terminal, enter the following commands:

(trainee@dmss-kali)-[~] $ top
﻿

5. Once the top utility has opened, enter the keys shift and M together to sort the data by the %MEM column. 

﻿

6. Identify the PID for the very top entry, which is the web browser (firefox-esr) that was opened in step 2.

﻿

7. Run the process metrics collection script by entering the following command, where PID is the PID from step 6:

(trainee@dmss-kali)-[~] $ ./process-metrics-collector.sh PID
﻿

This runs the script and collects data about the running process such as CPU usage, memory, Transmission Control Protocol (TCP) connections, and thread count. This script is useful when suspicious processes are identified because it displays additional information about the process in the format .csv.

﻿

8. Allow the script to run for 2-3 minutes.

﻿

9. Enter ctrl and c to stop the script. 

﻿

Since the script is constantly collecting data, it runs until it is stopped.

﻿

10. In the top left of the VM, select the folder drop-down.

﻿

11. Open the data folder.

﻿

12. Open the folder within the data folder.

﻿

13. Open the file metrics.csv.

﻿

14. Select Ok in the Text Import pop-up window. 

﻿

The file metrics.csv displays a table of all the information that was collected. This script can be used to analyze the CPU and memory usage as well as any TCP connections for a specific process. An analyst can run this script if they suspect that a process is using large amounts of memory or CPU at specific times throughout the day. The analyst can then use the data from this script to identify the specific time that a process has high usage and any TCP connections during this time. This information provides analysts the specific timeframe that an attack may have occurred, which is critical information for a hunt.

﻿

15. Display the script and analyze its contents by entering the following command:

(trainee@dmss-kali)-[~] cat process-metrics-collector.sh
﻿

The bottom if section of the script includes the command top. Here, this command serves to get the CPU and memory usage of the specified PID. The command lsof is included to get the TCP connections. Lastly, the command ps is included to get the thread count usage for the specified process. 

﻿

Scripts can be created in order to combine multiple different commands into one single output. Sometimes viewing all the data together provides a different viewpoint of a process and additional clues as to how the process is running or if it is malicious.

Manual Observation of Linux Host Communications
Linux Host Communications
﻿

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

Interface Configuration (ifconfig)
﻿

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

Internet Protocol (ip)
﻿

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

Name Server Lookup (nslookup)
﻿

The name server lookup command, nslookup, provides information from the Domain Name System (DNS) server in a network. This tool is used primarily by network administrators to query the DNS to obtain a domain name or IP address mapping or any other DNS-specific records. The command nslookup is also used to troubleshoot DNS-related issues. 

﻿

The command nslookup is simple, but useful. If an analyst comes across a domain name or the IP address of a domain that appears to be suspicious, nslookup can be used to verify that information. The following are the most commonly used nslookup commands using google.com as an example domain name:

nslookup google.com: Displays the A Record (IP address) of the domain. 

nslookup 192.168.4.44: Provides the DNS name for the specified IP, if there is one, as a reverse DNS lookup.

nslookup -type=any google.com: Performs a lookup for any Name Server (NS) record for the domain specified but also includes non-NS records. 

Domain Information Groper (dig)
﻿

The domain information groper command, dig, retrieves information about DNS name servers. It is used to verify and troubleshoot DNS problems and to perform DNS lookups. The command dig performs similar functions to the command nslookup. The command dig can be used to perform a DNS lookup through domain name or IP address. It can also be used to search for any DNS records. The syntax for this command is as follows, using google.com as the example domain:


dig google.com: Queries the domain A record for the listed domain.

dig google.com +short: Returns only the IP address for the listed domain, rather than the entire A record. 

dig google.com ANY: Displays all DNS record types for the listed domain  but also includes non-DNS records.

dig -x 172.17.14.210: Looks up a domain name by the specified IP address. 

Trace Route (traceroute)
﻿

In Linux, the command traceroute prints the route that a packet takes to reach the intended host. This command is useful when gathering information about a route and all of the hops that a packet takes. The command traceroute tries to get a response from each of the routers at each hop, from the source that runs the command to the destination specified. Network administrators often use this command to find slow routers or to identify where packets are being dropped when a destination is unreachable. The syntax for this command is traceroute google.com, where google.com is replaced with the intended destination.

﻿

Network Statistics (netstat)
﻿

The network statistics command, netstat, is used to display information about various interface statistics, such as the ports that are in use and the processes using them, routing tables, and connection information. This command also displays the sockets that are pending a connection. The command netstat can be useful for analysts who are hunting on a system and suspect that there may be suspicious processes running. Analysts can also use this command to view these processes and the ports that they are using. 

﻿

The command netstat has various options that analysts can use to display additional information. Running the command netstat by itself displays a list of all active sockets on the system. Other options to use with the netstat include the following:

netstat -nap: Searches for suspicious port listeners on a system.

netstat -pnltu: Displays all active listening ports on a system. 

netstat -a | less: Displays all connected and waiting sockets, one page at a time.

netstat -l | less: Displays all sockets that are in a listening state, one page at a time.

netstat -p -at: Lists the PID of any TCP processes using both a socket and the process name. 

netstat -r: Displays the routing table.

netstat -nap | grep "sshd": Searches  for a proc ess by name and identifies th e port it  is using. Alternatively, "sshd" can be replaced by a port  number to  search  for a proc ess that is using a specific port.

NOTE: Many modern Linux distributions (notably, Debian and Ubuntu) do not install older net tools by default. ss is the modern equivalent of netstat.

﻿Observe Linux Host Communications
Manual Observation of Linux Host Communications
﻿

Use the networking commands from the previous section to view detailed information about the Linux system. Then, use the commands to view and observe how a Linux host communicates.

﻿

Workflow
﻿

1. Log in to the VM kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1! 
﻿

2. Open a terminal console.

﻿

3. Display the interfaces with their basic information by entering the following command:

(trainee@dmss-kali)-[~] $ ifconfig
﻿

4. Enter the command ip addr to observe the same interfaces as in step 3 and compare the differences between both commands.

﻿

When using the command ip addr, the MAC address and IP address of each interface are highlighted in color to make them easier to observe. 

﻿

5. Display the default routes for a Linux system by entering the following command:

(trainee@dmss-kali)-[~] $ ip route
﻿

6. Change the interface of eth1 to down by entering the following command:

(trainee@dmss-kali)-[~] $ sudo ip link set eth1 down
[sudo] password for trainee: CyberTraining1! 
﻿

7. Enter the command ip addr to observe the eth1 interface. 

﻿

The interface eth1 displays DOWN in red.

﻿

8. Set eth1 back to up by entering the following command:

(trainee@dmss-kali)-[~] $ sudo ip link set eth1 up
[sudo] password for trainee: CyberTraining1!
﻿

9. Search for suspicious processes on the system by entering the following command:

(trainee@dmss-kali)-[~] $ netstat -nap | less
﻿

This command displays processes from a networking point of view. This command can be used to view the file and protocol that is being used and the state that the process is in.

﻿

10. Search for any instance of the process ssh by entering the following command:

(trainee@dmss-kali)-[~] $ netstat -nap | grep 'ssh'
﻿

Netstat can also be used to search for any instance of a running process by name to determine whether it is in a listening state. This is helpful in searching for any adversaries that are listening for a specific process or port to use in an attack. In the above command, ssh can be replaced with any process or port that is unknown or suspected of being used by an adversary.

﻿

Select the command that searches for any processes using port 5555.
netstat -nap | grep "5555"

Observe Linux Host Communications with Scripts
The Linux OS pulls various network parameters and statistics from the directory /proc/net. Each directory and virtual file within this directory contains different aspects of the networking of the system. For example, the file /proc/net/tcp contains all of the system's TCP connection information. 

﻿

There are times when the common commands that trainees learns from this lesson are not available on a Linux system. In this case, it is common to create a script that pulls the information from the directory /proc.

﻿

Execute a Script to Observe Linux Communications
﻿

Execute a basic script that pulls the TCP information from the file /proc/net/tcp and provides IP address information as the output.

﻿

Workflow
﻿

1. Log in to the VM kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1! 
﻿

2. Open a terminal console.

﻿

3. Populate data into the file /proc/net/tcp and leave the Netcat listener running by entering the following command:

(trainee@dmss-kali)-[~] $ nc -l -p 1337
﻿

4. Open a second terminal.

﻿

5. Display any data within the file /proc/net/tcp by entering the following command:

(trainee@dmss-kali)-[~] $ cat /proc/net/tcp 
﻿

The data within this file is in hexadecimal format. It is not very easy to read. It would be more difficult if there were multiple entries.

﻿

6. Run the networking script with the following command:

(trainee@dmss-kali)-[~] $ ./net.sh
﻿

This script pulls the information from the file /proc/net/tcp and puts it into a more readable format. It provides the local IP address and port of any connections along with the remote address and port. In this example, the connection is the Netcat listener on port 1337. Scripts such as this are useful in an environment that is locked down and does not have internet access.

﻿

7. Display the script by entering the following command:

(trainee@dmss-kali)-[~] $ cat net.sh
﻿

This script uses the command awk to process the hexadecimal text into a more readable format. It then prints the information from the TCP file into "Local - Remote" output. At the very end is the path that the script is specified to search. The path /proc/net/tcp can be changed to /proc/net/udp, as well, to parse through User Datagram Protocol (UDP) files. This output is similar to using the netstat command. While the script does not display whether a port is listening, anything connected to a remote address of 0.0.0.0:0 is a listening port.

Linux Configuration Files
Linux has various configuration files that control system functions such as user permissions, system applications, daemons, services, and other system tasks. Each file serves a specific purpose and most files are structured in different formats. The majority of configuration files on a Linux system are in the directory /etc. Analysts must learn how to identify and modify common Linux configuration files since these files often affect the security of the OS. This section covers the eight configuration files from the directory /etc that are listed in Figure 5.1-5, below.

﻿

﻿

﻿

Figure 5.1-5﻿

﻿

/etc/sudoers
﻿

The file /etc/sudoers is used to determine whether a user has root permissions to run commands or executables that require elevated privileges. If a user attempts to run a command that requires elevated privileges, Linux checks that username against the file sudoers. This happens when the command sudo is used. If Linux does not find the username within the file, the program or command requiring elevated privileges will not run. Root permissions and the tool visudo are required to modify the file /etc/sudoers.

﻿

/etc/hosts, /etc/hosts.allow, and /etc/hosts.deny
﻿

The file /etc/hosts is a simple text file that contains a list of host-to-IP address mappings. This file can be used if the IP of the system is not dynamically generated. The file /etc/hosts is used prior to querying an external DNS server for a hostname-to-IP address mapping. If the Linux system does not find a match in the file /etc/hosts, it checks DNS next. Adversaries often modify the file /etc/hosts when attempting to block security products from successfully connecting to external services. This is done by inserting a bogus entry into the file /etc/hosts that does not actually point to the intended target, such as the localhost (127.0.0.1).

﻿

Each line in the file /etc/hosts consists of an IP address followed by the hostname and then any aliases. The format to add additional entries to the file is IP_ADDRESS HOSTNAME.

﻿

Linux also implements access control lists through the file /etc/hosts to provide added security for network services using the Transmission Control Protocol Wrapper Daemon (TCPD). The file /etc/hosts.allow contains a list of allowed and non-allowed hosts and networks. Connections to network services can be both allowed or denied by defining the access rules in this file. The file /etc/hosts.deny contains a list of hosts or networks that are not allowed to access the Linux system. The access rules in this file can be set up in the file /etc/hosts.allow by using the deny option.

﻿

The access rules in the file /etc/hosts.allow are applied first. These rules take precedence over rules in the file /etc/hosts.deny. If access to a service is allowed in /etc/hosts.allow, any rule denying access to that same service in /etc/hosts.deny is ignored. If there are no rules for a Linux service in either file then access to the service will be granted to all remote hosts.

﻿

The syntax to define an access rule in these files is as follows:

daemon_list : client_list : option 
﻿

The components of this syntax include the following:

daemon_list: A comma-separated list of network services such as Secure Shell (SSH) or File Transfer Protocol (FTP), or the keyword ALL for all daemons.

client_list: A comma-separated list of valid hostnames or IP addresses, or the keyword ALL for all clients.

options: An optional command that is executed when a client tries to access a server daemon.

/etc/fstab and /etc/mtab
﻿

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

/systemd and /system
﻿

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

﻿Modify Linux Configuration Files
Linux offers different types of parameters that can be set to restrict and control network access to a system to provide added security. The files /etc/hosts.allow and /etc/hosts.deny can be configured to allow certain networks and services to be used or disallowed on the Linux system. Rules within these files can be set based on hostname, IP address, user name, or process name. 

﻿

Modify Linux Configuration Files
﻿

Add rules to the files /etc/hosts.allow and /etc/hosts.deny to harden the Linux system.

﻿

Workflow
﻿

1. Log in to the VM kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1! 

﻿

2. Open a terminal console.

﻿

3. To edit the file /etc/hosts.allow, enter the following:

(trainee@dmss-kali)-[~] $ sudo vim /etc/hosts.allow
[sudo] password for trainee: CyberTraining1!

﻿

4. Enter the following on the very first available line:

ALL: 192.168.
﻿

Step 4 allows all hosts within the subnet 192.168.0.0/16 to use all ports and services on the Linux system.

﻿

5. Enter a line break to start a new line, then enter the following to specify items that are allowed:

ALL: dns.google.com, mail.google.com, 212.23.4.12, 172.16.
﻿

This entry specifies that the two hostnames, dns.google.com and mail.google.com, the IP address 212.23.4.12, and the network 172.16.0.0/16 are all allowed.

﻿

6. Enter a line break, then enter the following to allow SSH access for any user with the domain name .abc.com:

sshd: .abc.com
﻿

7. Select esc, and enter :wq! to exit and save the file.

﻿

8. Open the file /etc/hosts.deny with the following command:

(trainee@dmss-kali)-[~] $ sudo vim /etc/hosts.deny
[sudo] password for trainee: CyberTraining1!
﻿

Any entries in the file hosts.allow take precedence over the entries in the file hosts.deny. It is best practice to follow up any allow rules with a deny-all rule in hosts.deny.﻿

﻿

9. In the file /etc/hosts.deny, on the first available line, add the following entry to deny all services to all hosts that were not specified in the allow file.

ALL: ALL
﻿

10. On the next available line, add the following entry to deny access to the service sshd for everyone that was not specified in the file hosts.allow. 

sshd: ALL
﻿

11. On the next available line enter the following to deny access to all services to any host that is part of the 10.0.0.0 network:

ALL: 10.
 ﻿

12. Select esc, and enter :wq! to exit and save the file. 

Which entry in hosts.allow would permit SSH access only to users from the .mil domain? 
sshd: .mil



Which commands provide the open files, CPU usage, and memory usage of a process?
lsof top
﻿
What command searches for any files communicating with port 5555?
lsof -i | grep "5555"

Overview of Exploits and Rootkits
There are many exploitation techniques that adversaries implement on a variety of systems, including both Windows and Linux. Although these exploits are not unique to Linux, they do have unique properties when considering a Linux environment. The next five sections of this lesson describe how to detect and address the following exploits on Linux systems:

Client execution
Ptrace system calls
Proc memory
Rootkit
Kernel modules and extensions

Identifying Exploitation for CE
In the MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) framework, Client Execution [T1203] occurs when an adversary "... exploits software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to insecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system." 

﻿

This section introduces CE exploits that involve the following features:

Remote Code Execution (RCE)

Local systems or applications

Privilege escalation kernels

RCE Exploits
﻿

As discussed in previous lessons, RCE exploitation occurs when an adversary takes advantage of a system or software vulnerability on a target host and runs arbitrary code from another system. Adversaries perform RCE attacks with code injections to obtain a foothold on the network. MITRE provides two Common Weakness Enumerators (CWE) related to RCE exploits: CWE-94 Code Injection and CWE-95 Eval Injection. 

﻿

CWE-94 Code Injection
﻿

MITRE defines code injection as follows: 

“The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment." 

﻿

This means that a code injection attack is possible when a segment of code in an application is not properly sanitizing input. Form fields that accept user entries are commonly vulnerable to code injections. For example, an adversary may enter a caret (^) character in the password field of a login page to escape the password management process. After the caret, the threat actor may execute additional characters as code to perform the code injection attack.

﻿

CWE-95 Eval Injection
﻿

MITRE defines eval injection as follows:

"The software receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call.” 

﻿

A dynamic evaluation call occurs when user input is accepted in unsanitized fields and passed to an eval() statement to be processed as code. In practice, an eval injection attack is similar to a domino effect. Adversaries do not need to run malicious passwords as code to execute an eval injection in a password field. Instead, the malicious password is passed to the internal hashing tool, which is then manipulated by the adversary's code to perform a code injection later in the process chain.

﻿

Local System or Application Exploits
﻿

After an adversary gains local access to a Linux system, they may need to perform additional local exploits to fully realize their goal in the attack chain. Many of these exploits work only with OS or application-specific vulnerabilities. Red Hat Security explains that application vulnerabilities occur when attackers “find faults in desktop and workstation applications (such as email clients) and execute arbitrary code, implant Trojan horses for future compromise, or crash systems. Further exploitation can occur if the compromised workstation has administrative privileges on the rest of the network." 

﻿

There are many compliance regulations specific to different Linux distributions due to the greater granularity of Linux package and application management when compared to a Windows environment. Compliance regulations, such as the Defense Information Systems Agency (DISA) Security Technical Implementation Guides (STIG), provide valuable guidelines for Linux-specific system and application management on a distribution-specific basis. The DISA STIGs are a common compliance standard for many organizations that are updated often. The frequent updates are important because stale and forgotten Linux applications can quickly lead to exploitation.

﻿

Privilege Escalation Kernel Exploits
﻿

The Linux kernel is the code that works directly with the system hardware as the basis for the Linux OS. Properly exploiting a vulnerability in the kernel is a quick way to get root access. Exploits such as “Dirty Copy-On-Write” (DirtyCOW) allow adversaries to take advantage of the way that Linux handles objects in Random Access Memory (RAM). Adversaries use these types of exploits to write to memory addresses that should have been read-only, resulting in root level access.

﻿

In 2016, researchers discovered that all distributions of Linux running the Linux kernel from versions 2.6.22 to 4.8.3 were vulnerable to the DirtyCOW exploit. The vulnerability itself was first discovered by the adversaries who had been secretly exploiting it. At the time of the exploit's discovery, every Linux system on the planet was susceptible to attack. Kernel exploit prevalence highlights the need for update monitoring and maintenance. This is because out-of-date legacy systems may still contain vulnerabilities that have a wide breadth of easily actionable exploitation.

﻿Detecting Process Injection
Process Injection Exploits
﻿

Process injection exploits allow an adversary to hide their malicious code inside a legitimate system process. This technique makes the adversary's malware more difficult to detect and creates a deeper layer of persistence on the exploited system. A common method for hijacking with process injection exploits is by manipulating the variable LD_PRELOAD, which was covered in module 9. This section introduces two other common methods of Linux process injection that involve the system call process trace (ptrace()) and the memory-mapped filesystem /proc.

﻿

ptrace()﻿
﻿

The system call ptrace() [T1055/008] is a very common method for process injection in Linux. The ptrace() tool is normally used to debug or modify another system process. However, ptrace() also allows administrators to perform advanced system functions that directly manipulate how the host handles a given process. If an adversary has access to a user account that can run ptrace() on a system, they can inject code into different process elements. This enables the affected system to execute the adversary's malware inside of the infected process.

﻿

Log monitoring alerts for Linux ptrace() system calls in Security Information and Event Management (SIEM) tools work well to detect possible ptrace() process injection. The specialized nature of ptrace() means that it's very rarely used, therefore any alert indicating ptrace() use is worth investigating. In addition, a process performing abnormal actions can indicate a compromised process. Abnormal actions include opening network connections, reading and writing files, and any other out-of-context behavior.

﻿

/proc﻿
﻿

If an adversary is able to access the filesystem /proc [T1055/009] on a Linux host, they can then enumerate memory mappings and subsequently manipulate the system process stack. Normally, the system's memory mappings are obfuscated by Address Space Layout Randomization (ASLR). However, if the adversary is able to read /proc/[pid]/maps in the filesystem, they can find out exactly where those processes are being stored in RAM. With the memory addresses, the adversary can then overwrite the process data with their own malicious code so that the system executes the malicious code when it references those memory objects.

﻿

To detect potential /proc exploitation, analysts should monitor any changes to /proc files. Any user-related file changes are cause for concern since, in nearly all cases, users should not have the permissions to modify files in this directory.

﻿

SSH Exploits
﻿

In Linux, SSH logins are the most common method for interactive remote user sessions between systems. Adversaries often attempt to gain access to Linux systems over an SSH connection through password brute-forcing or SSH key spraying.

﻿

Metasploit, the penetration testing framework, contains a wide variety of pre-made modules for testing exploits on different systems. The tool’s module ssh_login allows for password brute forcing for known and default accounts. The module simply needs a list of usernames and passwords to attempt, before providing a report on any login combinations that succeed. The module ssh_login_pubkey requires a ssh private key to be obtained from a compromised host. The module then sprays that key across the network to identify which systems accept the compromised keys for login. Even though Metasploit modules are intended to be used for testing purposes, many adversaries use these modules to identify vulnerable systems to attack. 

﻿

Password brute-forcing and SSH key spraying are detected by monitoring port 22 activity using network flow logs and monitoring failed SSH login attempts in host authentication logs. In Debian-based systems, the relevant logs are located in /var/log/auth.log. In systems based in Red Hat Enterprise Linux (RHEL), these logs are located in /var/log/secure. An indicator of brute force activity is a large number of f

Which CE attack occurs when user-supplied input remains unsanitized and is processed as code immediately?
Code Injection

Which CE attack occurs when user-supplied input remains unsanitized and is executed as code later in the program processing?
eval injection

Detecting Process Injection
Process Injection Exploits
﻿

Process injection exploits allow an adversary to hide their malicious code inside a legitimate system process. This technique makes the adversary's malware more difficult to detect and creates a deeper layer of persistence on the exploited system. A common method for hijacking with process injection exploits is by manipulating the variable LD_PRELOAD, which was covered in module 9. This section introduces two other common methods of Linux process injection that involve the system call process trace (ptrace()) and the memory-mapped filesystem /proc.

﻿

ptrace()﻿
﻿

The system call ptrace() [T1055/008] is a very common method for process injection in Linux. The ptrace() tool is normally used to debug or modify another system process. However, ptrace() also allows administrators to perform advanced system functions that directly manipulate how the host handles a given process. If an adversary has access to a user account that can run ptrace() on a system, they can inject code into different process elements. This enables the affected system to execute the adversary's malware inside of the infected process.

﻿

Log monitoring alerts for Linux ptrace() system calls in Security Information and Event Management (SIEM) tools work well to detect possible ptrace() process injection. The specialized nature of ptrace() means that it's very rarely used, therefore any alert indicating ptrace() use is worth investigating. In addition, a process performing abnormal actions can indicate a compromised process. Abnormal actions include opening network connections, reading and writing files, and any other out-of-context behavior.

﻿

/proc﻿
﻿

If an adversary is able to access the filesystem /proc [T1055/009] on a Linux host, they can then enumerate memory mappings and subsequently manipulate the system process stack. Normally, the system's memory mappings are obfuscated by Address Space Layout Randomization (ASLR). However, if the adversary is able to read /proc/[pid]/maps in the filesystem, they can find out exactly where those processes are being stored in RAM. With the memory addresses, the adversary can then overwrite the process data with their own malicious code so that the system executes the malicious code when it references those memory objects.

﻿

To detect potential /proc exploitation, analysts should monitor any changes to /proc files. Any user-related file changes are cause for concern since, in nearly all cases, users should not have the permissions to modify files in this directory.

﻿

SSH Exploits
﻿

In Linux, SSH logins are the most common method for interactive remote user sessions between systems. Adversaries often attempt to gain access to Linux systems over an SSH connection through password brute-forcing or SSH key spraying.

﻿

Metasploit, the penetration testing framework, contains a wide variety of pre-made modules for testing exploits on different systems. The tool’s module ssh_login allows for password brute forcing for known and default accounts. The module simply needs a list of usernames and passwords to attempt, before providing a report on any login combinations that succeed. The module ssh_login_pubkey requires a ssh private key to be obtained from a compromised host. The module then sprays that key across the network to identify which systems accept the compromised keys for login. Even though Metasploit modules are intended to be used for testing purposes, many adversaries use these modules to identify vulnerable systems to attack. 

﻿

Password brute-forcing and SSH key spraying are detected by monitoring port 22 activity using network flow logs and monitoring failed SSH login attempts in host authentication logs. In Debian-based systems, the relevant logs are located in /var/log/auth.log. In systems based in Red Hat Enterprise Linux (RHEL), these logs are located in /var/log/secure. An indicator of brute force activity is a large number of failed logins or a user account attempting to log in to many computers simultaneously.

﻿Which process injection method uses memory address enumeration from the filesystem?
/proc

Which process injection method uses a process debugging system call to inject code into running processes?
()pctrace

Detecting Rootkits
Linux Rootkits
﻿

After compromising a system, many adversaries install a rootkit [T1014] on a target to gain stealth persistence on the affected host. Rootkits are malware that hijack the Linux kernel and allow adversaries full control over how the OS behaves. Adversaries exploit a target with either a user mode rootkit or a kernel mode rootkit [T1547/006].

﻿

User Mode Rootkits
﻿

Many user mode rootkits found today are derived from other common rootkits such as LD_PRELOAD or the JynxKit, which is also based on LD_PRELOAD. These rootkits are designed to function like installed malware. They modify login shells like sshd to maintain a persistent backdoor to a target machine. User mode rootkits can also modify su or sudo to allow easy privilege escalation. These rootkits also modify logging (syslogd), processes (ps, pidof, top), files (ls, find), and many other OS functions to hide the adversary's presence on a host. There are thousands of user mode Linux rootkits. However, the similarity at the core of all Linux rootkits is that they all modify Linux user components in some way to manage the same end of taking control of a system and hiding the rootkit's presence.

﻿

To detect user mode rootkits, analysts can use packet sniffers from outside the suspected host. The packet sniffers can help analysts identify abnormal traffic that may indicate the presence of rootkits. Another option for identifying an installed rootkit is to isolate the affected system and scan the host with another tool. The tools Chkrootkit and Rootkit Hunter (rkhunter) scan local systems and identify malware that attempts to mask its existence on a host. The tool Linux Malware Detect (LMD) cross-references known threat data to identify and remove malware.

﻿

Kernel Mode Rootkits
﻿

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


3. Run Rootkit Hunter to search the filesystem for any potential rootkits using the following case-sensitive command:
# sudo /home/trainee/Downloads/rkhunter-1.4.6/files/rkhunter -c -sk



4. Display the log file at /var/log/rkhunter.log with the following command, to examine a rootkit detection report:
# sudo less /var/log/rkhunter.log



Figure 5.2-1, below, displays the detection report:

5. Search for running processes using the command less and the following command:
/running_procs



6. Enter q to quit the command less.


Some rootkits are tagged based on their activity, while other tags are based on file contents. The logs display the processes and files that are suspicious and should be examined. Use the information from this lab to answer the next question. 

Linux Persistence Overview
A threat actor gains persistence on a Linux system by creating a backdoor, in case access to the target system is lost. Completely ridding a system of a threat actor is therefore difficult for defenders since the adversaries are able to continue gaining access through their persistence methods. If defenders are not aware of persistence TTPs on Linux, they will only be able to remove a portion of the threat actor toolkit, leaving the system vulnerable for the next inevitable attack.

﻿

Adversaries have many methods of establishing persistence from which to choose. Detecting each method requires proper logging. A simple way to gather the required logging is to deploy Elastic’s Auditbeat configured with the auditd, system, and file integrity modules while employing a best practice auditd rule set. Florian Roth offers one such rule set on GitHub, which is provided in the additional resource section of this task. 

﻿

Understanding the basic and advanced methods of Linux persistence and how to detect them allows defenders to more decisively expel adversaries from a system the first time, by ensuring that no backdoors exist. This detection becomes more difficult when threat actors deploy kernel rootkits using a persistence method because kernel rootkits are able to intercept system calls. Additional details about working with this type of TTP is explained in an upcoming module.

Which Elastic Beat provides auditd, system, and file integrity modules?
auditbeat

Common Linux Persistence Methods
There are many different methods of obtaining persistence on a Linux system. Defenders who continuously learn new methods of persistence are better prepared to ensure the detections in place are effective for catching adversaries. This section introduces four advanced methods that fall under the following MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) techniques:

T1543.002 Systemd Service

T1037.004 Run Control (RC) Scripts

T1098 Secure Shell (SSH) Authorized Keys

T1505.003 Web Shell

T1574.008 Path Interception by Search Order Hijacking


Systemd Service and RC Scripts
﻿

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

SSH Authorized Keys
﻿

The SSH file /home/<user>/.ssh/authorized_keys defines the keys that are authorized for use during key-based authentication. Threat actors abuse this feature to gain persistence on a host by creating their own SSH key and adding the public key to the file authorized_keys.

﻿

File integrity logging is useful for detecting this type of activity because changes to the file authorized_keys are uncommon. Defenders can monitor for changes to this file to receive alerts that should prompt further investigation.

﻿

Another file that should be monitored is /etc/ssh/sshd_config. A threat actor may add their public key to authorized_keys and find that the file sshd_config does not allow for public key authentication. In this case, the threat actor must edit the configuration file sshd_config and change the values for the fields PubkeyAuthentication and RSAAuthentication to yes.

﻿

Web Shell
﻿

One type of backdoor on a Linux web server is a web shell. A web shell is a script that allows threat actors to use the web server as a gateway into a network. Analysts can audit changes to public folders to catch any malicious web scripts being added. These folders include /var/www/html and any other directory hosting internet-facing files. Another option is to monitor for web servers accessing files that are not in the web directory or files that are spawning processes that a web server should not need to spawn.

﻿

Path Interception by Search Order Hijacking (Binary Wrapping)
﻿

A threat actor can hijack the use of common system commands on Linux to create a stealthy backdoor. For example, adding a binary named hostname to the directory /usr/local/bin/ hijacks the use of /bin/hostname. This is because the user-specific bin directory has priority over the system-wide bin directory when running a command without the absolute path. The threat actor can add anything they want to the directory /usr/local/bin/hostname, make it executable, and then use that binary in a scheduled task to inconspicuously launch their backdoor. A defender can check the search order by running the command echo $PATH to list the current $PATH configuration. The search order priority is presented left to right. A threat actor can modify the $PATH to change the search order in preparation for a persistence method they plan on using. Organizations should always use absolute paths in system administration scripts to avoid search order hijacking.

﻿

Analysts may need to monitor various types of activities to effectively detect when file permissions are being modified. Auditing the usage of the command chmod may help analysts identify suspicious files in user-specific bin locations that threat actors are making executable. However, a threat actor may not need chmod if they change the command umask to 000 and then create a file because this makes the file globally executable. Analysts should be suspicious if they see a normal system command that is located by default in /bin or if the command is added to /usr/local/bin and made an executable. Additionally, monitoring surrounding network traffic after the execution of a suspicious binary often leads to the detection of suspicious network traffic.

﻿

﻿

Detection Recommendations
﻿

Table 5.3-1, below, provides a quick reference of the items to monitor to detect each of the common persistence TTPs described above. These items comprise a mix of directories and files (paths), commands, and activities.

﻿Indications of Linux Persistence
All four of the common Linux persistence methods were used in the large dataset from the previous workflow. These methods include the following:

Systemd service

SSH authorized_keys

Web shell

Binary wrapping

Systemd Service
﻿

Description
﻿

A malicious service was created called ntsh.service. It was started, enabled, and daemon-reload was run.

﻿

Query
﻿

Running the following query and then creating a table visualization to review all the process.title values reveals the suspicious process:

process.title: (*systemctl* OR *service*)
﻿

SSH Authorized Keys
﻿

Description
﻿

The root user modified /home/JCTE/.ssh/authorized_keys and /etc/ssh/sshd_config.

﻿

Query
﻿

Running the following query reveals this activity:

event.module: file_integrity AND file.path: (*.ssh/authorized_keys* OR */etc/ssh/sshd_config*)
﻿

Web Shell
﻿

Description
﻿

A suspicious php script named bdoor.php was created in /var/www/html.

﻿

Query
﻿

Running the following query reveals this activity:

process.title: */var/www/html* OR file.path: */var/www/html*
﻿

Binary Wrapping
﻿

Description
﻿

A suspicious binary named date was created in /usr/local/bin. The binary date is a standard system binary that is located in /bin by default.

﻿

Query
﻿

Running the following query reveals this activity:

process.title: */usr/local/bin* OR file.path: */usr/local/bin*

MITRE D3FEND
MITRE D3FEND Overview
﻿

MITRE developed D3FEND as a repository of defensive cybersecurity techniques designed to counteract offensive techniques by adversaries. Understanding D3FEND is an asset for any party involved in security systems architecture because it is an effective resource for helping to keep networks as secure as possible. 

﻿

D3FEND consists of five stages. Table 5.4-1, below, presents the critical goal and common defense techniques employed at each stage.

MITRE D3FEND and Incident Response
﻿

Incident response techniques and strategies are found in the isolate, deceive, and evict stages. Once an incident has been detected, it is the role of an incident response team to isolate the activity to a portion of the network, lure the activity to an intended location or object, and then evict the activity from the network. 

incident Response
Incident Response Overview
﻿

Incident response is a primary component of the defense of any network. The National Institute of Standard and Technology (NIST) defines incident response as “the mitigation of violations of security policies and recommended practices.” However, this mitigation does not start solely after an incident occurs. Incident response is an ongoing process, so it is a best practice for analysts and teams to be ready at all times. To conduct effective IR mitigation, defenders require the most recent applicable techniques and threat intelligence to prepare for and respond to adversaries. Below are the tasks surrounding the preparation and response activities that apply to all types of IR. 

﻿

Preparation 
﻿

IR preparation includes methods and strategies for arranging response techniques to an incident. Efficient preparation leads to efficient IR. Common preparation strategies include the following:

Synchronize time across the network
Manage logs
Establish Baseline
Synchronize Time Across the Network﻿

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

Response 
﻿

The response part of IR includes the methods and strategies used to address and mitigate an incident. When responding to an incident, Cyber Protection Teams (CPTs) must complete the following steps:

Analyze the scope
Build a timeline
Confirm the incident
Isolate affected hosts
Deceive and evict adversary activity 
Analyze memory
Step 1: Analyze the Scope﻿

﻿

One component in responding to an incident is to understand the scope. An incident can be triggered with only a small portion of intelligence, however, the scope starts growing as response activities get underway. Defenders may need to triage the incident remotely to prevent the scope of the incident from growing. Endpoint tools are helpful for remote triage. An endpoint tool such as Beats collects and sends data to the Elastic Stack for analysts to view and assess remotely. The remote access to host data enables an effective assessment and effective means of response while also reducing the time to respond.

﻿

Step 2: Build a Timeline﻿

﻿

A timeline helps to understand the time and duration of relevant actions. Construction of a timeline may provide analysts a clear picture of the sequence of events leading to the incident. There are several documents to examine to build a timeline, as covered in the Cyber Defense Analyst - Basic (CDAB) course. Examining external reporting and observing the Operation Notes (OPNOTE) of other analysts are critical tasks at this stage. Building a timeline of the incident involves the following key documents:

Situational Reports (SITREP): Routinely generated to provide updates to higher elements on a daily, weekly, per-phase, or on request.
Tactical Assessments: Low-level assessments that often contain their own Measures of Effectiveness (MOE) and Measures of Performance (MOP).
OPNOTEs: In-depth and technical information about the events that occur during mission execution, containing very specific timestamps and events. When more detail than a high-level summary is needed, consult the OPNOTEs.
OPNOTEs are helpful in developing an execution timeline that includes reports on health and status as well as cyber IR. 

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


![image](https://github.com/user-attachments/assets/ea16a0ad-6a47-42c6-bfc8-45e6696b2221)


![image](https://github.com/user-attachments/assets/204ee590-2fc4-44ea-afef-145eeb12914f)


![image](https://github.com/user-attachments/assets/febdb049-8069-4af3-8c7c-83ed1184fc14)
















