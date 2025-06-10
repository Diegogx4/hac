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

﻿

﻿

Table 4.1-1

﻿

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



















