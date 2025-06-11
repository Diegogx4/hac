Examining Linux Shells
Linux shells come in many flavors. The main reason to pick a specific shell is based on how it helps automate the tasks that need to be completed. Users familiar with Linux need to at least know BASH because it is the default shell for most Linux distributions. Other commonly used shells include the following:

Portable Operating System Interface (POSIX) 
Shell

Debian Almquist Shell (DASH)

Z Shell (zsh)

C shell (csh)

Korn Shell (ksh)

Tenex C Shell (tcsh)

Friendly Interactive Shell (fish)

Common features shared by various shells include automatic command or filename completion, loggable command history, text formatting for legibility, and even autocorrection. A common secondary shell for UNIX-based operating systems is Z Shell (zsh) because of its robust feature set. It became the default login shell for MacOS in 2019, and the system shell for Kali Linux in 2020. Understanding how to best use these shells helps defenders more accurately and efficiently hunt for information.

﻿

Comparing Linux Shells
﻿

Linux shells contain a wide range of features. The table below compares some of the most common shells and the systems in which they are found.

Shell Features and Benefits
﻿

Features that assist users with entering commands to a system are described below:

Command History: Use a keyboard shortcut to rerun previously run commands, or view which commands have already been run. The commands are usually referenceable in run order.

Command Scripting: Command shells also double as scripting languages, allowing users to automate instructions on a host.

Tab Completion: Using tab while writing commands causes a shell to attempt to automatically complete the intended command based on context. For example, filename completion is based on the currently active directory when a filename would be too complex or inconvenient to enter manually.

File Globbing: Entering a wildcard such as an asterisk allows the shell to execute commands on all files that match part of a given bit of text. For example, a user could specify that they want to move *.txt which would pattern match all files that end in .txt and move them at the same time.


When not using a shell, users have to be exact in the syntax of the commands they run on the filesystem, and they can normally execute only one task at a time. Since command line shells became standard for many operating systems, using a shell has become the norm.

Specifics of Common Shells
Three of the most commonly used shells are briefly described in this section.

﻿

BASH 
﻿

The Bourne Again Shell (BASH) was a replacement for the default Unix Bourne shell, and is now the default login shell for many distributions of Linux. A version of BASH is also available for Windows 10 via the Windows subsystem for Linux. BASH enables users to run commands concurrently with the session, meaning the commands are executed immediately, or to process commands in a batch so that they're executed in order. BASH also contains built-in bug reporting for debugging scripting issues through the use of the command bashbug.

﻿

Z Shell 
﻿

Z Shell zsh is a UNIX shell that is a version of BASH with improved features. Many power users describe zsh as an upgraded version of BASH, and it is preferred by many professionals seeking more powerful options for scripting. For instance, when entering commands, BASH stops tab completion at the last common character, while zsh cycles through the possible options without needing to be forced to show the user options. For example, if a user wants to execute commands from the folder /usr/bin/things/, but that system also contains the folders /usr/bin/thin/ and /usr/bin/thing/, zsh cycles through each potential completion option with only partial text entered.

﻿

zsh is installed by default on the Kali distribution of Linux. Therefore, many security professionals find it necessary to master zsh if their work involves heavy use of Kali.

﻿

Other useful features of zsh are command history shared among all system shells, better file globbing without needing to run the find command, spelling correction, compatibility modes, and user-loadable modules that contain pre-written snippets of code.

﻿

POSIX
﻿

The POSIX shell comes from the Institute of Electrical and Electronics Engineers (IEEE) POSIX standard, and the shell exists to create a common scripting language between certified operating systems (OS). Any POSIX-certified OS should be able to communicate with any other POSIX-certified OS without users needing to be concerned with specific shell upgrade maintenance. POSIX is based on the C programming language but contains additional features over the American National Standards Institute (ANSI) C standard like file management, regular expressions (regex), networking management, memory management, and system process handling.

Which Linux shell exists to guarantee a scripting standard as long as the operating system is certified?
posix
Although users can enter commands into a terminal one instruction at a time, a shell provides what additional functionalities?

inux File System Overview
Linux File Philosophy
﻿

The Linux operating system is designed with and operates on the philosophy that everything is a file. This concept provides a common abstraction for a variety of input and output operations. Resources such as documents, devices, directories, memory, and even inter-process communications are expressed as file objects.

﻿

Index Nodes (inodes)
﻿

Each file is described by a unique inode. The inode is the data structure that contains all necessary metadata about a file, including type, permissions, number of hard links, ownership, size, timestamps, and a list of pointers to all data blocks in which the file data resides. This list of metadata in the inode is called the File Control Block (FCB). The inode itself is unique on a file system. Two different files, even if named identically, have two different inode numbers. Any hard links to a file, however, share its inode number, since a hard link essentially points to the same file, and changes to a hard link result in changes to an original file. Every file, regardless of its type, has an inode number. 


File Types
﻿

The six Linux file types are listed below:

Regular files

Directories

Special files

Links

Domain Sockets

Named Pipes

Regular Files
﻿
Regular files contain normal data and could be text files, executable files, documents, or any other data-containing file. These are often used for input or output to normal programs.

Directories
﻿
Directories are files that are a list of other files. The list contains the inodes of files that are contained in that directory. 

Special Files
﻿
Special files are mechanisms for input and output to devices and do not contain data. Instead, they serve as the doorway through which data is sent. Special files are primarily located in the /dev directory.

Links

Link files are pointers to an inode located in the file system (hard links) or to a filename that points to an inode located in the file system (soft links). The original file and any of its hard links point to identical data because they are the same inode. So any changes to an original file or any of its hard links are experienced by the others. Hard links may only be made of regular files, and not directories or special files. If the original file is deleted, any hard links continue to successfully operate. Soft links, on the other hand, are broken if the original file is deleted, since they point to that filename rather than the inode itself.

Domain Sockets

These files are a special file type that facilitates inter-process networking and communication. They are protected by the file system’s access control. These are similar to networking sockets, such as those which communicate Transmission Control Protocol (TCP) or User Datagram Protocol (UDP) traffic, but all communication takes place within the Linux kernel rather than over a network interface.

Named Pipes

Named Pipes files are another form of interprocess communication, but do not conform to network socket semantics. However, like regular files, these named pipes have owners, permissions, and metadata.

﻿Linux Standard Directory Structure
In all Linux distributions, the file structure is a standard directory tree. These directories are included under the root directory by convention so that all distributions operate with a similar structure and software, operating knowledge, and tooling is portable across the Linux ecosystem of distributions.

bin
The bin directory contains common programs shared by the system, the system administrator and the users. Bin is short for binary. In Linux, this is where basic programs and applications are located. Binary files are the executable files that contain compiled source code. Almost all basic Linux commands can be found in bin, such as ls, cat, touch, pwd, rm, and echo. The binaries in this directory must be available in order to attain minimal functionality for the purposes of booting and repairing a system.

boot 

The boot directory contains the startup files and the kernel vmlinuz. This is where the boot loader lives. It contains the static bootloader, kernel executable, and configuration files required to boot a computer. Some recent distributions include GRUB data. GRUB is the GRand Unified Bootloader and is an attempt to get rid of the many different boot-loaders available. 

dev
﻿
The dev directory references all the Central Processing Unit (CPU) peripheral hardware, which is represented as two files with special properties: block files and character files. These two types of files allow programs to access the devices themselves, for example, to write data to a serial port and read a hard disk. It is of interest to applications that access devices. These files are known as device nodes, which give user-space access to the device drivers in the operating system’s running kernel.

Block files: These are device files that provide buffered access to system hardware components. They provide a method of communication with device drivers through the file system. Data is written to and read from those devices in “blocks,” which is how these files receive their name.

Character files: These are also device files that provide unbuffered serial access to system hardware components. They work by providing a way of communication with devices by transferring data one character at a time, leading to the name Character files.

etc 

The etc directory contains configuration files for critical system services such as networking, authentication, initialization, and terminals. For example, the files that contain the name of the system, the users and their passwords, the names of machines on the network, and when and where the partitions on the hard disks are mounted.

Of particular note, the file system configuration information is located in /etc/fstab, which is the file system table. The file system table is a configuration file that governs mounting and unmounting the file systems on a machine. This lists each device by its Universally Unique Identifier (UUID), the mount point, the file system type (several of which are discussed later), the read and write privileges, and other options used by the kernel for mounting, backing up a drive, and other operations. 

home
﻿
The home directory contains home directories of the common users, and personal configuration files, which are usually hidden. If there is a conflict between personal and system-wide configuration files, the settings in the personal files take priority.

lib
﻿
The lib directory contains library files and includes files for programs needed by the system and the users. These library files are programs that are shared among other binary applications. Binary files inside bin and sbin use these library files extensively. The directory contains the all-important kernel modules. The kernel modules are drivers that make devices like the video card, sound card, and Wi-Fi, printer function properly.

﻿
media 
﻿
The media directory is where the operating system automatically mounts external removable devices such as Universal Serial Bus (USB) thumb drives.

mnt 

The mnt directory is the standard mount point for external file systems. Any devices or storage mounted here is done manually. This may include external hard drives, network drives, and others. In older file systems that do not include /mount, other plug and play devices may be mounted here as well.

opt 
﻿
The opt directory stands for optional. It typically contains extra and third party software that is optional. Any applications which are manually installed should reside here. Part of the installation process usually involves writing files to /usr/local/bin and /usr/local/lib directories as well.

proc

The proc directory, which is short for process, is the virtual file system containing information about system resources. This includes information about the computer, such as information about the CPU and the kernel that the Linux system is running. More detail about this directory is included later in this lesson.

root 

The root directory is the administrative user's home directory. 

run

Linux distributions since about 2012 have included the run directory as a Temporary File System (TMPFS) which stores Random Access Memory (RAM) runtime data. That means that daemons like systemd and udev, which are started early in the boot process (and perhaps before /var/run was available) have a standardized file system location available where they can store runtime information. Since files in this directory are stored on RAM, they disappear after shutdown.

sbin
﻿
The sbin directory contains programs for use by the system and the system administrator. The shortened term for system binary is sbin. Similar to bin, it is a place for storing executable programs. But these executable programs are essential for system configuration, maintenance, and administrative tasks. Linux has decided to discriminate between normal binaries and these system binaries. In other words, this directory is reserved for programs essential for booting, restoring, and recovering.

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

srv
﻿
The srv directory contains data for servers. If an organization was running a web server from a Linux machine, the Hypertext Markup Language (HTML) files for its sites would go into /srv/http or /srv/www. If they were running a File Transfer Protocol (FTP) server, the files would go into /srv/ftp.

sys﻿

Like /proc and /dev, sys is another virtual directory and also contains information from devices connected to the computer. The Sys File System (SYSFS) contains files that provide information about whether devices are powered on, their vendor name and model, what bus the device is plugged into, etc. These files are used by applications that manage devices. If /dev is the doorway to the device itself, /sys files are the addressing and signage to the devices.

tmp

The tmp directory contains temporary files, usually placed there by applications. The files and directories often contain data that an application doesn’t need when the files are written, but may need later on. The files placed in this directory are often cleaned during reboot, so it is not ideal for persistent storage.
﻿
var
﻿
The var directory is the storage for all variable files and temporary files created by users, such as log files, the mail queue, the print spooler area, or space for temporary storage of downloaded files. These are typically files and directories that are expected to grow in size. For example, /var/crash holds information about every time a process has crashed. Or /var/log contains all log files for the computer and its applications, which grow constantly.

Linux Boot Procedure
File system artifacts in the boot, dev, and etc directories are integral to booting a Linux system. Booting from no power to full operating system capability in Linux is a multi-step process, described below.


Basic Input/Output System (BIOS)

In the first stage of the boot process, the BIOS performs integrity checks of the hard drive. These checks are called Power On Self Test (POST). The boot process then searches for the boot loader program, which is in the Master Boot Record (MBR). The MBR is typically located in the first data sector of the hard drive, in the file /dev/hda or /dev/sda. It contains the GNU GRUB. When the boot loader program is detected, it is loaded into memory, executed, and given control of the system.
﻿

NOTE: Newer Linux systems use Unified Extensible Firmware Interface (UEFI) to conduct the first stage of the boot process. UEFI boots more quickly and allows booting drives larger than two terabytes (TB). Linux systems using UEFI may also use Globally Unique Identifier Partition Table (GPT) instead of MBR. GPT supports more partitions and drives larger than two TB. 

﻿
GRUB

This boot loader uses the file /boot/grub2/grub.conf or the file /boot/grub/grub.conf (in older systems) as the configuration to load itself, load the Linux kernel into memory, then hand execution over to the kernel. The splash screen visible during the boot process is a marker for when the GRUB boot loader is operating. Most operating systems distributed since 2015 are running the second version of the boot loader, GRUB2. 

The Logical Volume Manager (LVM) is often used in parallel with the boot loader. The LVM manages drive storage, allowing users to allocate space between drive partitions without unmounting.

﻿
NOTE: Instead of GRUB, Linux systems using UEFI may use Systemd-boot as their boot loader. Systemd-boot integrates with UEFI, enabling the use of UEFI boot entries. 


Kernel
﻿
The kernel is the core of the operating system in Linux. When it takes control of the boot process, it first loads the init daemon and establishes a temporary file system in the /run directory, known as Initial RAM Disk (INITRD) for the System V init daemon or Initial RAM File System (INITRAMFS) for the systemd init daemon. 

Init Daemon
﻿
The init daemon takes on the process identifier of 1 and is responsible for starting all system services and monitoring them. The System V init daemon was widely used in older versions of Linux and remains in use in the Alpine and Gentoo distributions. All others have replaced this subsystem with the Systemd init daemon, which was designed with faster booting and better dependency management. 

System V init
﻿

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

Systemd
﻿

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


After basic services are started, the dependencies for emergency.target   and multi-user.target are resolved. Depending on the default.target setting, the graphical.target configuration is resolved, and the boot  ﻿ process ends .

Linux Process Directory
The process directory is a unique virtual directory that contains many useful artifacts for understanding the state of running processes and memory on a system. This virtual file system is not representative of data on the hard disk, but encapsulates the Linux philosophy of representing all data, including these objects which exist in memory, as a file. Each process is represented by a directory named for its Process Identifier (PID) and contains a standard structure of subdirectories and files which represent various elements of the process, which are explained below.

﻿

Process Directory Tree
﻿

/proc/PID/cmdline
﻿

The file cmdline contains the command-line arguments. However, since it contains them as a list, there is no whitespace in the output.

/proc/PID/cwd

The file cwd is a symbolic link to the current working directory of the process.

/proc/PID/environ
﻿
The file environ contains the values of environment variables in use by the process.

/proc/PID/exe
﻿
The file exec contains a symbolic link to the executable of this process. Since the inode remains active until the process has died, even if the binary on disk is deleted, it may be retrieved forensically from this hard link while the process remains alive. This is why it is important to preserve the running state of a compromised system, as long as that system is contained from the rest of the network.

/proc/PID/fd
﻿
fd is a directory containing all file descriptors associated with a process.

/proc/PID/status
﻿
The file status lists the process status in human-readable form.

Notable Proc Files
﻿
/proc/cpuinfo

The file cpuinfo contains information about the processor, such as its type, make, model, and performance.

/proc/devices
﻿
The file devices contains a list of device drivers configured into the currently running kernel (block and character).

/proc/meminfo
﻿
The file meminfo contains information about memory usage, both physical and swap.

/proc/mounts
﻿
The file mounts is a list of mounted file systems. The mount command uses this file to display its information.

/proc/net
﻿
The net directory contains status information about network protocols.

/proc/sys

The sys directory is not only a source of information, but also serves as an interface for parameter change within the kernel. These changes may be performed by echoing a new value into the respective file as the root user. An example of this change would be to turn on packet forwarding by editing the file /proc/sys/net/ipv4/conf/all/forwarding. Though since these changes are made to a virtual file system rather than the physical drive, they do not persist through a reboot.

/proc/sys/fs

The fs subdirectory contains file system data, such as file handle, inode, and quota information.

/proc/sys/kernel

The kernel directory reflects general kernel behaviors and the contents are dependent upon the configuration. The most important files are located here, along with descriptions of what they mean and how to use them.

/proc/version
﻿
The version file displays the kernel version.

Linux File System Types and Journaling
The underlying system that manages the hard drive, its volumes, and data reads and writes is the type of file system, of which the Extended File System (Ext) is the most common. The Ext2, Ext3, and Ext4 versions of this file system implemented a concept known as journaling to ensure that data is properly written to the file system, even if interrupted by a system crash.
﻿
Journaling 

Journaling is the process of recording file system changes to a data structure in order to recover a system state after a crash. Since everything in Linux is a file, the journal is no exception, and in the Ext4 file system, the journal’s inode number is usually 8.

In file systems that employ it, the journal is where all the information about the content of the file system is recorded. This log is used at boot time, when mounting the file system, to complete any file action that was incomplete due to an unexpected system shutdown or crash. Some journaling file systems do not employ a log and the journal contains only recent actions. The journal usually has limited space and old entries can be overwritten as soon as the corresponding actions have been written to disk, which typically takes no more than a few seconds. 

While it is important to understand what journaling is and how it works in order to leverage it for forensics purposes, relying on the journal for robust file monitoring from a security perspective is not feasible. It is preferable to leverage a tool such as LoggedFS or Linux’s own audit subsystem to monitor sensitive file activity. The use of the audit subsystem for security monitoring is discussed in a later lesson.
﻿
Disks

Where different disk devices are denoted by C:\ or D:\ in the Windows OS, Linux names those devices under the /dev directory with the naming conventions sda or sdb. This “s” in this name refers to the Small Computer System Interface (SCSI) mass-storage driver, therefore SCSI driver A is sda, and SCSI driver B is sdb, etc.

Partitions﻿

Partitions are distinct storage units on a hard drive. These are recorded in the MBR in a data structure called the partition table. In newer operating systems, the partition table in the MBR has been replaced by GUID Partitioning Table (GPT), which introduces several modernization features. 

There are three types of partitions, which are described below:

Primary: Any partition not explicitly created as an extended or logical partition. There are no more than four primary partitions on a disk drive. Partition numbers start at 1, so the four partitions of the /dev/sda drive would be sda1, sda2, sda3, and sda4. Primary partitions in the MBR are limited to 2 Terabytes (TB) in size. Any disk space beyond those partitions is marked as free, but to the operating system, since it is not partitioned, that space is unusable. 

Extended: To overcome the primary partitioning problem, extended partitions are created. There is no limit to the number of subdivided partitions (logical partitions) under this extended partition, and any free space in this partition is still marked as usable. Only one extended partition may be configured on a single hard drive, so a common structure is to allocate three primary partitions and one extended partition which occupies the remaining hard disk space.

Logical: Subdivisions of an extended partition. 

File Systems
﻿
Ext4

Ext4 is the latest version of the Ext family of file systems and is widely used. It continues to employ journaling to protect against data corruption. However, this file system does not support data deduplication, which is an automated storage management process of preventing excess data from being written to a file system. It also does not support transparent compression, which is the principle of allowing compressed files to be read and written to, just like regular files.

XFS 
﻿
XFS is another journaling file system, and uses a log to write changes to before committing them to the file system. It is particularly suited for very large file systems, such as large storage arrays. It has even become the default file system for Red Hat Enterprise Linux, CentOS, and Oracle distributions.

Btrfs

Known as the “Better File System” (Btrfs) by its proponents, this system employs a copy-on-write (CoW) process to write data to disk rather than a strict journaling method. In this process, when a file is modified, the original file is read from disk, changes are made to its data and then the modified data blocks of that file are written to a new location rather than the original file location. This creates a copy and prevents loss of data in the event of a crash. When all new writes have been successfully completed, the file’s active data blocks are also updated, so that the file always references valid data blocks. This is a fault-tolerant method, in keeping with the file system creators’ philosophy. Since the file system is theoretically always in a correct state, a Btrfs file system does not employ journaling for file integrity.

Zettabyte File System (ZFS)

ZFS is a heavily memory-dependent file system, consuming large amounts of memory for the disk and volume management operations that it requires. It places a high priority on file integrity, employing the use of a checksum during every operation to ensure this. However, it is not a conventional journaling file system, though it employs a very similar construct to prevent data corruption during a crash. This construct is the ZFS Intent Log (ZIL). The system only writes to the ZIL rather than reads from it, unlike the journaling model in Ext4 and XFS file systems in which the journal is managed more. ZFS reads from the ZIL only during crash recovery, to restore proper data integrity for any failed writes. After any file action is successfully performed, the entry is removed again, making this structure unappealing for forensic analysis. 

﻿Linux File System Analysis Tools
The tools described below are useful for determining the characteristics of a Linux device’s file system and the subdirectories in it. Understanding the usage of disk space, the type of file systems present on a disk, and the number and types of mounted drives is important for an analyst to understand before conducting any further forensic copying or analysis of a compromised system.

File System Analysis Tools 
﻿
dd 

The dd utility is used to clone disks or portions of disks. It is useful to recover deleted files if that data is not already overwritten.

du 

The du utility is used for displaying the disk usage of various files or directories on a file system. The ideal use case for this command is to understand how each directory and all subordinate files and directories contribute to the disk usage of a location in the file system.

df
﻿
The df utility is used for displaying used and free disk space in a file system. With the -T flag, it can also be used to display the type of file system for each entry. The flag -h also prints sizes in human-readable format.

mount
The mount utility is used to mount file systems for access, such as Network File Systems (NFS) or external drives. It is also useful in displaying information about those mounted file systems. When used to display information, this utility prints the output of the /proc/mounts file.

lsblk
The lsblk utility lists all attached block devices on a machine. Optimally, the flag -f lists the file system type and UUID.

blkid
﻿
Like lsblk, blkid is used to list block devices on a system, along with the UUID and type of file system and label of the device, if set. However, this command provides less information about the devices to the user and requires root permissions to run.

debugfs

The debugfs utility is a file system debugger employed in the ext family of file systems.

Linux File Analysis
The utilities listed below are native to the Linux operating system, so they are present and available for a host analyst’s use in characterizing the type, function, and metadata of unknown files on a Linux system. If the file is an executable, several of these tools reveal the code linked to the binary file, which is used in behavior analysis of an executable. Both static and dynamic analysis of any files an adversary may have modified or left on a compromised system are objects of interest in a Threat Hunt and Incident Response, so as to determine what tradecraft that adversary employed and which indicators of compromise may be employed to identify other compromised systems.


File Analysis Binaries
﻿
strings
﻿
The strings utility extracts all human-readable strings from a file and prints them to standard output. It is useful for finding artifacts left behind in malicious binaries that reveal a binary’s purpose or information about potential authors. However, this kind of data is also inserted for misdirection by particularly savvy threat actors.
﻿

It is often necessary to pipe the results of this command to a paging utility such as less or more, or to grep to search for specific string patterns. Below is the beginning of the output when running strings on the ls binary.

readelf
﻿
The readelf binary reads the metadata of an Executable and Linkable Format (ELF) object file. Different headers and metadata tags reveal different information about an ELF file, including where the sections of the file are located on the hard drive and what libraries and library calls are linked to it. It even prints a dump of information located in a specific section of the file.


The readelf binary is particularly useful for binary analysis when examining the linked library calls in the relocation symbol table. The functions listed may be looked up by name. Many functions, such as listen() and accept() for network operations, are straightforward in what functionality they give a binary. These entries may be singled out for analysis with the following command:

readelf -r <file> 
﻿
hexdump
The hexdump binary is used to examine a hexadecimal representation of the actual data that a file contains. This can be useful for examining the magic bytes of a file, which are the first several bytes that an operating system uses to determine how to open a file or use which program to use to open or edit it.

If a file is expected to result in a lengthy hexadecimal output, the parameter

–length <number> may be used to truncate the output. If the output is expected to contain American Standard Code for Information Interchange (ASCII) data, the flag 

–canonical may be used to print the ASCII characters in conjunction with the hexadecimal data.

xxd
﻿
The xxd binary can perform all of the same functions as hexdump with one added functionality: It can take a hexadecimal data dump from a file and convert it back into binary data.

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

ltrace
The ltrace utility is similar to strace but lists library calls instead of system calls. In all other ways it operates and provides value to file analysis.

Linux Directory Analysis
Utilize directory analysis to determine which binary was most recently added to the file system. This analysis may be performed across all files and subfolders in a directory to determine what has recently changed or whether applications and users are abusing misconfigurations to access those directories.

﻿

Conduct Directory Analysis
﻿

Much of directory analysis involves comparing known standard layouts and included or expected files to a modified file system state. If a device is compromised, attackers may hide artifacts in locations that are unlikely to be viewed frequently or where they are lost in the noise of other similar files. Additionally, placing malicious software in one of the protected directories in the system path allows for the file to be executed from anywhere in the system.

1. In a terminal window in the VM kali-hunt, analyze the following directories and examine the creation times of the files to determine which binaries were most recently added to the protected binary directories. The next question refers to this step.

/bin
﻿
/sbin
﻿
/usr/bin
﻿
/usr/sbin

ls -alt 

File Permissions Overview
To understand how to find and correct any incorrectly assigned Linux permissions, it is important to first understand what the permissions are and what sort of access each permission gives to a file. It is also important to understand each special permission and how it affects the real access a user has to a file.    

﻿

File Ownership
﻿

The Linux Operating System (OS) has three file ownership types — User, Group, and Other — and each has different roles and accesses. For every file in Linux, there can only be one user, one group, and one other, however, ownership types can be in various combinations. It is important to remember that although Linux views everything as a file, in this lesson, a file refers to directories as well. The Linux OS checks each file ownership type in a specific order to determine the proper access to the file or directory. Linux also has specific codes for each file ownership type: u for User, g for Group, and o for Other.

﻿

User
﻿

The User file ownership type is the owner of the file. This is usually the person who created the file, but file ownership can be transferred to other users. This is also the first file ownership type that Linux checks when reading the permissions to a file. 

﻿

Group
﻿

Every user in Linux is part of a certain group or groups. Groups are created to manage Linux environments and provide proper security to them. When a user creates a file that user's primary group becomes the group owner for that file. The group that has ownership over the file can only be changed by the user that has ownership over the file or by a user logged in as root.

﻿

For example, if there are analysts and system administrators in a Linux environment, creating groups to manage saves time and provides security. The analysts do not need to access the same files as the administrators and the same can be said for the administrators. If groups are created, it also saves time because instead of manually adding permissions for each user, they can be added to a group and that group can have specific permissions over a file.      

﻿

Other   
﻿

Other is every user that has access to the Linux system that is not the user or a member of the group that has ownership of that file. This means that anyone with a valid account on the Linux system can access the file with the given permissions that the Other group has. It is vital to control the permissions of the Other file ownership because this can be a security risk if the correct permissions are not assigned.

﻿

Order of Permissions
﻿

When Linux checks permissions, it uses this order:

If the file is owned by the user, the User permissions determine the access.
If the group of the file is the same as the user's group, the Group permissions determine the access.
If the user is not the file owner and is not in the group, the Other permission is used.
If users are denied permission, Linux does not examine the next group.
﻿
Permission Modes
Every file in Linux has three different permission modes for the three different file ownerships: read, write, and execute. For the Linux permission modes, there is a difference between what read, write, and execute mean for files versus directories. When viewing the permissions on a Linux OS, there are codes for the different permission modes: r for read, w for write, x for execute, and - for permission not granted (rwx-).    

﻿

Read
﻿

For files with read permissions (r), the contents of the file are able to be viewed or copied. The file contents cannot be modified or executed, only viewed. For directories with read permissions, the files within the directory can be listed and copied, but no files can be added or deleted. This means that the ls command can be used to view the files inside the directory but having read permission to a directory does not always mean that the contents of the files can be viewed. 

﻿

Write
﻿

For files with write permissions (w), the contents are able to be modified. Anyone with write permissions for a file can add to the file or even overwrite the file. For users with write permissions for a directory, they can add and delete files from that directory. With write permissions to a directory, files can also be renamed or moved within that directory.

﻿

Execute
﻿

The execute permission mode (x) is the most unique and also complex of the three permission modes. This permission mode is specific to executable binaries and directories. If the file or program is executable, and the user has the execute permission mode, then the file can be run. If the file is a shell script, then adding the execute permission to it tells Linux to treat the file as if it were a program. Users can enter a specific directory using the command cd if they have the execute permission for that directory. The execute permission on directories also affects what level of information can be gained by using the commands ls or find.

﻿

For example, a user who only has read permissions for a directory can only use ls to list the files within a directory. However, a user who has read and execute permissions can use the command ls -al in order to list all of the files, including hidden files, and view other information about the files such as permissions, the owner of the file, file size, and creation date.

﻿

For example, the file myfile has permissions set to read, write, and execute for User (rwx), read and write for Group (rw-), and only read for Other (r–). The permissions for the file are listed as rwxrw-r–. If the file had the permissions set to read and write for the User (rw-), read and write for the Group (rw-), and only read for Other (r–), the permissions appear as rw-rw-r–, with the order of file ownership being User, Group, and Other. Directories also have a symbolic value of d, which is represented before the set of permissions to let users know that it is a directory and not a file. A regular file has a symbolic value of -. 

Octal References
Linux permissions can also be viewed or set using octal references instead of the rwx format. This method of specifying permissions can seem more complex at first but is actually easier to set permissions for files. Octal references refer to using octal numbers (digits 0 – 7) to represent each permission mode. Figure 4.3-2 details the reference values and how they are used to determine the permissions for a file or directory.

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

Linux Permissions Mask
﻿

When a user creates a file or directory, it is created with a default set of permissions. For example, if a new file was created and given the default permissions of 666, then read and write permissions (rw-rw-rw-) have been granted to everyone. Similarly, if a directory was created with the default permissions of 777 (rwxrwxrwx), then anyone can change the contents of the file because all users on the system have search access to the directory and write access to the file. This situation can be avoided by setting the umask value.

﻿

By default, files receive the rw-rw-rw- (666) permissions and directories receive rwxrwxrwx (777) permissions when they are created. This often leaves situations where excess permissions are given out. The umask command specifies the permissions to be subtracted from the default permissions when files and directories are created. For example, if 022 was subtracted from 777 for directories or 666 for files it would create directories with the permissions 755 (drwxr-xr-x) or files with 644 (rw-r–r–). ﻿

﻿

The default value for umask is 022 or 002 depending on the Linux distribution used. The umask value is subtracted from the default permissions after new files or directories are created. The command umask 066 results in file permissions of rw------- (600) and directory permissions of rwx–x–x (711). A umask of 033 results in file permissions of rw–wx-wx (633) and directory permissions of rwxr–r– (744).

Unique Permissions
The Linux OS has unique permissions that can be set on files or directories to give that file or directory different characteristics. These special permissions allow users to run certain applications with other credentials, control how groups inherit permissions, and can keep files from being deleted or changed accidentally. Linux also has the ability to implement Access Control Lists (ACL) to allow administrators to define permissions for more than just one user or group.

﻿

Sticky Bit
﻿

A sticky bit is a special permission set on a file or an entire directory. It grants only the owner (User) of a file or directory the permission to delete or make changes to that file or directory contents. No other user can delete or modify the file or directory. It has the symbolic value of t and a numeric value of 1000. This special permission ensures that important files or directories are not accidentally deleted or modified.

﻿

﻿

Figure 4.3-3

﻿

The sticky bit also has a different meaning when applied to directories than when applied to files. If the sticky bit is set on a directory, a user may only delete files within that directory that they own or for which they have explicit write permissions granted to that file, even when they have write access to the directory. This is designed for directories like /tmp, to which all users have write permissions, but it may not be acceptable to allow any user to delete files at will within the directory. 

﻿

Set User Identifier Bit
﻿

The Set User Identifier (SUID) bit replaces the execute permission to allow programs to run with the permissions of the file owner, not with the permissions of the user who runs the program. The most common use of the SUID bit is to allow users to run a command as the root user. Users do not become the root user, however, the command or program is run with root user permissions. Some programs require the SUID bit to be set to properly function, however, it should be used sparingly as it can be a security issue if used incorrectly. The SUID permission has the symbolic value of s in the first set of permissions for the User and a numerical value of 4000. Any file highlighted in red signifies that there is a SUID sticky bit set on it. Notice in Figure 4.3-4 that myfile has a sticky bit set. 

﻿

﻿

Figure 4.3-4

﻿

Set Group Identifier Bit
﻿

The Set Group Identifier (SGID) bit is similar to the SUID bit in that it replaces the execute permissions for a program or directory. However, for a file, the program runs with the group permissions of the group owner. This allows all members of a group to execute the file with root permissions. For a directory, a newly-created file receives the same group owner as is assigned to the parent directory. This is often used to allow all users to write to a specific directory. The SGID bit has a symbolic value of S and a numeric value of 2000. It is present in the second set of permissions for the Group file ownership. Figure 4.3-5 shows the SGID sticky bit set for myfile.

﻿

﻿

Figure 4.3-5   

﻿

Mutability
﻿

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

sudo chattr +i /etc/passwd
﻿

To set or unset the immutable attribute sudo privileges must be used. With the immutable attribute set, the file cannot be tampered with. To edit the file, the attribute needs to be removed with the command:

sudo chattr -i /etc/passwd

Viewing File Permissions
There are multiple different ways to view the permissions on a file or directory on a Linux OS. The most popular command, and by far the most simple way to view permissions, is to use the ls command. The command namei is also useful. This command views information, such as permissions, for directories and files within a given path. It is useful when troubleshooting permissions errors or when trying to determine if the proper access is applied to a specific file or directory.

﻿

Viewing Permissions with the Command ls
﻿

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

Viewing Permissions with the Command namei
﻿

The command namei is used to view more information about the directories that exist within a path. It can be used to view the permissions, owner, or creation date of directories or files. The namei command uses pathnames as arguments so the syntax to view the permissions for a given pathname looks similar to:

 namei -l /home/trainee/Downloads
﻿

That output returns the permissions and file owner for all the directories listed in the path name. 

﻿

﻿

Figure 4.3-8

﻿

Viewing File Permissions
﻿

Identify file permissions of several different files using the commands learned. 

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1! 
﻿

2. Open a terminal console.

﻿

3. Run the following code to change directories:

cd lab
﻿

4. Run the following code to view the files within the lab directory:

ls
﻿

5. Run the following code to view the file permissions and file owner of the file myfile:

ls -l myfile
﻿

This file has the permissions read, write, execute for User, read and execute for Group, and read for Other.

﻿

6. Run the following command to view the permissions for both files within the lab directory:

ls -l
﻿

7. Look at the permissions for the file project. It has read, write, and execute permissions for all three file ownership types. This is considered the least secure type of permission, and this file is considered insecure.

﻿

8. Run the following commands to create a file, and look at the default permissions for that file:

touch myfile2
ls -l myfile2
﻿

The default permissions for any newly-created files for this system are read and write for User, read for Group, and read for Other. 

﻿

9. Run the following command to change to the home/trainee/analyst directory:

cd ../analyst

Securing Linux Files
There are a number of different commands that Linux offers in order to modify the permissions of a file or directory. These include chmod, chown, and chgrp. Each serves a specific purpose when modifying permissions for a file or directory. For each of these commands, utilize Table 4.3-1 to set the correct permissions.

﻿

﻿

Table 4.3-1

﻿

chmod
﻿

The chmod command changes permissions for a specified file. It adds or subtracts permissions from a file, and is used to explicitly set the permission value for a file equal to the specified permissions. There are two ways to set the permissions, octal and symbolic (r,w,x).

﻿

The following are the different syntaxes that can be used with chmod.

﻿

chmod (file ownership)+(permission)

Adds a permission. The following command adds the execute permission to the file myfile for the User, Group, and Other:

chmod u+x,g+x,o+x myfile
﻿

chmod (file ownership)-(permission)

Subtracts permissions. The following command subtracts the write permissions from the Group and Other for myfile but leaves the User permissions untouched:

chmod g-w,o-w myfile
﻿

chmod (file ownership)=(permission)

Sets the permission equal to the permission specified for a User, Group, or Other for a file or directory. The following command sets the User permissions for the file myfile to read, write, and execute:

chmod u=rwx myfile
﻿

chmod (octal number)

Sets the permissions explicitly to what is represented with the octal reference numbers. The following command sets the permissions of myfile to User read, write, and execute (7) and Group and Other to execute (1):

chmod 711 myfile
﻿

chown and chgrp
﻿

The chown command is used to alter the User and Group ownership of files and directories. This command changes ownership of a directory recursively throughout the directory tree, or it can change the Group ownership to a single file or directory. This command is frequently used in environments where files need to be shared in a specific group. 

﻿

To only change the User file ownership, the command is:

chown trainee myfile
﻿

This sets the User file ownership of the file myfile to the user trainee. If a colon is used after the username, the Group ownership of the file is changed as well. The following command makes trainee the User owner and analyst the Group owner of the file logs:

chown trainee:analyst /project/logs
﻿

The commands chown and chgrp change the Group ownership and are used to recursively change the Group ownership of a file or directory throughout a directory tree. The following command sets the analyst group as the owner of all files within the /project directory:

chown :analyst -R /project
﻿

The following command makes the analyst group the owner of the file logs:

chgrp analyst /project/logs
﻿
Common Permissions Misconfigurations
When a user is given a permission setting that provides access to a wider range of files than is required, this can lead to the exposure of sensitive information or the unintentional modification of files. This is particularly dangerous when users have access to program configuration files or important executables. Not only can a user unintentionally modify these files but adversaries can exploit weak permissions on files that are set to world-readable or readable by anyone with access to the system. 

﻿

For example, the default permissions for home directories is 755, which means that users who have access to the system can view the contents of other home folders. Some users may have scripts or backups of files in their home folders that contain sensitive information.

﻿

Other commonly misconfigured files include the following:

Bootloader Configuration Files
System and Daemon Configuration Files
Firewall Scripts
Web Service
Web files/directory
Configuration files/directory
Sensitive files (encrypted data, password, key)/directory
Log files (security logs, operation logs, admin logs)/directory
Executables (scripts, EXE, Java Archive [JAR], class, Hypertext Preprocessor [PHP], Active Server Pages [ASP])/directory
Database files/directory
Temporary files /directory
Upload files/directory

Conducting File Permissions Audit
The Linux find command is useful to find specific files based on the criteria added to the command. It is used to find specific filenames, permissions, users, file types, etc. The find command locates permissions that are set incorrectly and performs an audit on a file system. 

﻿

World-Writable Files
﻿

World-writable files are files that anyone who has access to the Linux system has write permissions to. One of the main causes of world-writable files is incorrect default permissions for new files and folders. This can be fixed by setting a correct umask of 002. However, to ensure there are no files with incorrect permissions, an audit should be performed to check for these files. This can be done using the find command.

﻿

The command to search for world-writable files is: 

find /dir -xdev -type f -perm -0002 -ls
﻿

The /dir is the directory that should be searched. This lists any files that meet the requirements specified, which is in this case, the Other file ownership type having write permissions. To disable world-writable access to a file, the chmod command is used. chmod o-w myfile removes writable access for Other to the file myfile.    

﻿

Incorrect SUID Permissions
﻿

An incorrectly assigned sticky bit is dangerous because it allows anyone to potentially run a file as a root user. If a file is owned by the root and has the SUID bit set, then it runs with root user permissions. If an adversary compromises a system and comes across a file with root permissions, it can use the file to perform remote commands on the system with root-level permissions. These files can be audited, similarly to how world-writable files were found.

﻿

The command to search for an incorrectly assigned SUID bit is:

find /dir -uid 0 -perm -4000 -type f 2>/dev/null | xargs ls -la
﻿

The /dir can be replaced with the directory that should be searched. This command can also be edited to check for an incorrectly assigned SGID bit. The following command finds any SGID bits that are incorrectly assigned:

find /dir -group 0 -perm -2000 -type f 2>/dev/null | xargs ls -la
﻿

Find and Correct the Incorrect File Permissions
﻿

Use the information learned to find and set file permissions that were incorrectly set on a system critical file within the /etc directory. Use sudo to search the /etc directory. Once the file is located, set the permissions to read and write for User, read for Group, and none for Other.     

﻿find /etc -xdev -type f -perm -0002 -ls              can replace /etc for better search
 
Linux Logging Basics
Linux OSs collect a wide array of technical information and data regarding the host. The collected data contains information on a wide variety of categories, such as communications sent and received or user actions. The logs allow security and engineers on the hosts to see nearly every action performed on the OS. 

﻿

Common Logs for Linux
﻿

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


Severity codes indicate the priority and importance of each message. Table 4.4-2, below, displays syslog severity codes and is viewable within the console by executing the following command:
man syslog


The severity code and the severity name are synonymous within the Linux command line. The two commands below execute the same commands, regardless of whether the severity code or severity name is entered. 


iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-level informational --log-prefix "ping"



iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-level 6 --log-prefix "ping"



Facility codes indicate where and how to store the message on the syslog server. The facility code architecture organizes and keeps the syslog server searchable. Table 4.4-3, below, displays the syslog facility codes:

Format


Syslog contains a standard format usable with all devices and applications. This format is  Figure 9.4-2, below, highlights the three sections of syslog’s format in a syslog entry. In the illustration, the sections are labeled numerically, as follows:
Header
Structured data
Message

The header (1) contains information regarding the Facility, Version, Time, Date, Host Name, Application, Process Identifier (ID), and Message ID. The image below shows the header and the information that composes it. The header comprises only the information preceding the structured data fields.


The structured data section (2) includes the fields Structured-Data and Encoding. Logs can be encoded in different structures, so the structured data comprises how the data is formatted. Most syslog messages are encoded using 8-bit Unicode Transformation Format (UTF-8), however, this can be adjusted based on the needs of the message.


The message section (3) includes everything following the Encoding field. The Message field contains information about the syslog entry. The message contains details pertaining to why the specific entry was recorded. One example of data contained in the message field is a failed logon attempt, as presented in the figure below.

NOTE: The syslog file format is customizable and may differ from the standard format due to configurations defined in /etc/rsyslog.conf or /etc/rsyslog.d/, altering timestamp, metadata, or message structure to suit logging needs. This customizability allows for flexibility to adapt to specific logging requirements.

Audit Basics
The Linux Audit system collects data across multiple categories based on defined rules. Each rule defines which data to collect and what categories to place it in. The Linux Audit log categories and rules are described below.

﻿

Audit Log Categories
﻿

The Audit system collects data across the following three categories:


System calls: The data identifies which system calls were called, along with contextual information such as the arguments passed to it and user information.
File access: This is an alternative way to monitor file access activity, rather than directly monitoring the open system call and related calls. 
Select: These are pre-configured auditable events within the kernel.

Audit Log Rules
﻿

The data that the Audit system collects is based on a specified set of rules. The rules used by the Audit system define what data is captured and how it is handled. The command auditctl allows users to control the Audit system and implement new rules for the host. The rules are categorized into the following categories:


Control: Audit's system and user behaviors. 
File system or File watches: Audit's access or usage of a file or directory.
System call: Audit's system calls on specified programs. 

View and Create Audit Rules
Linux Audit System Overview 
﻿

The Linux Audit system collects logs that include data pertaining to the type of events, the date and time, system calls, files accessed, and processes used. The system contains rules that can be viewed, created, and modified. The next workflow introduces methods to use the Linux Audit system. 

﻿

View Audit Rules and Status
﻿

The Linux Audit system includes rules that dictate what activity is logged. Complete the following workflow to view the rules and the current status of the Linux Audit system.

3. To view the audit rules enter the following command:

(trainee@kali-hunt)-[~] $ sudo auditctl -l
﻿

4. When prompted enter the password for trainee:

CyberTraining1!
﻿

The command -l in step 3 lists all rules that are on the host. It returns the following output:

No rules
﻿

NOTE: This workflow frequently employs the command sudo. Enter the password from step 4, each time the prompt requests it.

﻿

5. Check the status of the Audit system by entering the following command:

(trainee@kali-hunt)-[~] $ sudo auditctl -s
﻿

The command -s lists the status of the Audit system on the host. The top line of the output, enabled 1, indicates that the Audit system is active. If the system is not active, a value of 0 is returned.

﻿

Create a Filesystem Audit Rule
﻿

Continue working in the VM kali-hunt to complete the next workflow. This workflow explores commands to create audit rules based on the filesystem of the host. 

﻿

The following syntax is used to create audit rules:

auditctl -w <path to file> -p <permissions> -k <key name>
﻿

This syntax includes the following elements:

<path to file> is the file or directory that requires auditing.

<permissions> are the permissions that are logged. The values can include r (read), w (write), and a (attribute change). 

<key name> is a string value that allows the user to input text that may help identify the rule. 

2. To create a filesystem rule, enter the following command:

(trainee@kali-hunt)-[~] $ sudo auditctl -w /etc/hosts -p wa -k hosts_file_change 
﻿

The rule audits write and attribute change to anything in the file /etc/hosts. Any change to the file hosts is logged to the audit log with the key name hosts_file_change.

﻿

3. To ensure the rule is in place, enter the following command:

 (trainee@kali-hunt)-[~] $ sudo auditctl -l
﻿

Step 3 returns the following output, which indicates the rule was successfully added to the Linux Audit system:

-w /etc/hosts -p wa -k hosts_file_change 
﻿

4. To ensure the rule is enforced and works as expected, navigate to the following path:

(trainee@kali-hunt)-[~] $ sudo vi /etc/hosts
﻿

5. Select i to insert text to the file. 

﻿

6. On a new line, enter the following:

New Text
﻿

7. Save the text by entering the following command:

:wq!
﻿

8. To confirm the rule is collected query the Audit log with the following command:

(trainee@kali-hunt)-[~] $ ausearch -k hosts_file_change
﻿

The command ausearch allows users to query the Audit log by defined parameters. The query above searches the Audit log for any occurrences of hosts_file_change. Audit logs can be very large, making manual review of the log a nearly impossible task. The command ausearch enables quick and efficient review and discovery of Audit log information. 

﻿

Output from the query is similar to Figure 4.4-4, below, although the exact output differs slightly. Each occurrence of the rule is separated by a line. Within the rule exists information pertaining to the time and date the event occurred, the path of the file, the Process Identifier (PID), and the Parent Process Identifier (PPID). 

﻿Which component of an Audit log file includes string value allowing the input text and identifying information?

Analyze Logs
Read the following scenario. Then, use the skills and information from this lesson to complete the workflow.

﻿

Scenario 
﻿

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

LogFormat "%v %h %l %u %t \"%r\" %>s %b" vhost_common
The format specifiers are:﻿

%v: Virtual host serving the request.

%h: Remote host's IP address.

%l: Remote logname, identd.

%u: Userid of the user making the request.

%t: Time the request was received in the format [day/month/year:hour:minute:second zone].

\"%r\": Request line as the HTTP request method, path, and protocol.

>%s: HTTP status code returned to the client.

%b: Size of the response in bytes, excluding the HTTP header.

The following is an example of a log entry:

77.54.21.11 - - [12/Dec/2018:05:03:34 +0100] "GET /vcityu/student/documents.php?file=220.php&theme=twentysixteen HTTP/1.1" 200 4291 
﻿

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

3. Access the log file, located on the following path:

(trainee@kali-hunt)-[~] less /var/log/apache2/feb28_logs.log.1
﻿

Analyze the log file to answer the next set of questions.

The following log entry contains 12459 bytes sent. The large number of bytes relative to the other logs, paired with its location, prior to any log containing r57.php, indicates this is likely the log of the malicious file upload.


71.55.82.68 - - [28/Feb/2022:09:05:41 +0100] "GET /vcity/student/plugin-install.php HTTP/1.1" 200 12459 "http://www.vcityu.com/victyu/student/plugin-install.php?tab=upload"

HTTP Response Code 302
The following log entry includes the first occurrence of HTTP response code 302. HTTP response code 302 indicates that the URI of the requested resource has been changed temporarily, therefore the response is redirected.

﻿

71.55.82.68 - - [28/Feb/2022:09:02:46 +0100] "POST /student/vcityu-login.php HTTP/1.1" 302 1150 "http://www.vcityu.com/student/vcityu-login.php"
﻿
Username
The following log entry includes unknown or undefined information. The dash "-" indicates unknown or undefined information, so in this case the username is not known or defined in the log. 

﻿

71.55.82.68 - - [28/Feb/2022:09:02:23 +0100] "GET /student/vcityu-login.php HTTP/1.1" 200 1568 "-"









