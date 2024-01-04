# DLL Search Order Hijacking Using WinSxS Binaries
# Summary
Security researchers have detailed a new variant of a dynamic link library (DLL) search order hijacking technique that could be used by threat actors to bypass security mechanisms and achieve execution of malicious code on systems running Microsoft Windows 10 and Windows 11. This technique leverages executables commonly found in the trusted WinSxS folder and exploits them via the classic DLL Search Order Hijacking technique.

# What is DLL Search Order Hijacking?
A dynamic-link library (DLL) is a module that contains functions and data that can be used by another module (application or DLL). 

It's common for multiple versions of the same dynamic-link library to exist in different file system locations within an operating system. You can control the specific location from which any given DLL is loaded by specifying a full path. But if you don't use that method, then the system searches for the DLL at load time as described in this topic. The DLL loader is the part of the operating system that loads DLLs and/or resolves references to DLLs. The order it searches can change based on it being a packaged app or unpackaged app. A packaged app is packaged by using MSIX technology, and this is concerning because Microsoft has once again disabled MSIX due to threat actor abuse. You can opt out of using MSIX altogether by creating an unpackaged app. But be aware that an unpackaged app doesn't have package identity at runtime. As MSIX is disabled, can we expect more unpackaged apps?

Microsoft has a standard search order for packaged apps and unpackaged apps https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order 
For packaged apps, the system searches in this order:

1. DLL redirection.
2. API sets.
3. Desktop apps only (not UWP apps). SxS manifest redirection.
4. Loaded-module list.
5. Known DLLs.
6. The package dependency graph of the process. This is the application's package plus any dependencies specified as <PackageDependency> in the <Dependencies> section of the application's package manifest. Dependencies are searched in the order they appear in the manifest.
7. The folder the calling process was loaded from (the executable's folder).
8. The system folder (%SystemRoot%\system32).

For unpackaged apps, when an unpackaged app loads a module and doesn't specify a full path, the system searches for the DLL at load time as described in this section. 

The standard DLL search order used by the system depends on whether or not safe DLL search mode is enabled. Safe DLL search mode (which is enabled by default) moves the user's current folder later in the search order. 

If safe DLL search mode is enabled, then the search order is as follows:

1. DLL Redirection.
2. API sets.
3. SxS manifest redirection.
4. Loaded-module list.
5. Known DLLs.
6. Windows 11, version 21H2 (10.0; Build 22000), and later. The package dependency graph of the process. This is the application's package plus any dependencies specified as <PackageDependency> in the <Dependencies> section of the application's package manifest. Dependencies are searched in the order they appear in the manifest.
7. The folder from which the application loaded.
8. The system folder. Use the GetSystemDirectory function to retrieve the path of this folder.
9. The 16-bit system folder. There's no function that obtains the path of this folder, but it is searched.
10. The Windows folder. Use the GetWindowsDirectory function to get the path of this folder.
11. The current folder.
12. The directories that are listed in the PATH environment variable. This doesn't include the per-application path specified by the App Paths registry key. The App Paths key isn't used when computing the DLL search path.

If safe DLL search mode is disabled, then the search order is the same except that the current folder moves from position 11 to position 8 in the sequence (immediately after step 7. The folder from which the application loaded).

We would know if safe dll search mode is disabled if the registry key is set like: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode registry value, and set it to 0. 

# How do Threat Actors abuse this?
When an application dynamically loads a dynamic-link library without specifying a fully qualified path name, Windows attempts to locate the DLL by searching a well-defined set of directories in a particular order, as described in Dynamic-Link Library Search Order. If an attacker gains control of one of the directories on the DLL search path, it can place a malicious copy of the DLL in that directory. This is sometimes called a DLL preloading attack or a binary planting attack. If the system does not find a legitimate copy of the DLL before it searches the compromised directory, it loads the malicious DLL. If the application is running with administrator privileges, the attacker may succeed in local privilege elevation.

For example, suppose an application is designed to load a DLL from the user's current directory and fail gracefully if the DLL is not found. The application calls LoadLibrary with just the name of the DLL, which causes the system to search for the DLL. Assuming safe DLL search mode is enabled and the application is not using an alternate search order, the system searches directories in the following order:

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

Continuing the example, an attacker with knowledge of the application gains control of the current directory and places a malicious copy of the DLL in that directory. When the application issues the LoadLibrary call, the system searches for the DLL, finds the malicious copy of the DLL in the current directory, and loads it. The malicious copy of the DLL then runs within the application and gains the privileges of the user.

# Threat Actors using WinSxS
WinSxS (short for "Windows Side by Side") is a folder (location: C:\Windows\WinSxS) where Windows stores files required for installing Windows and backups or versions of those files. Whenever you need to recover system files or add or remove Windows features, this is where Windows will search for the files required to perform an action. This is why it’s also called the component store. WinSxS also stores files needed to install quality updates and previous versions of Windows components. These files allow you to revert back to the last state in case the update becomes troublesome. 

A security blog, SecurityJoes, has revealed an innovative approach that leverages executables commonly found in the trusted WinSxS folder and exploits them via the classic DLL Search Order Hijacking technique https://www.securityjoes.com/post/hide-and-seek-in-windows-closet-unmasking-the-winsxs-hijacking-hideout

This approach lowers the probability of detection compared to the classic DLL Search Order Hijacking, as the malicious code operates within the memory space of a trusted binary located in the Windows folder WinSxS. Unlike traditional methods, there is no requirement to introduce your own vulnerable binary, as Windows already includes various files stored in the WinSxS directory that can be leveraged.

According to MITRE ATT&CK https://attack.mitre.org/techniques/T1574/001/ there are various methods that adversaries can employ to hijack the DLL loading process. However, all these methods share a common requirement: the targeted application should not specify the full path to the required content. This situation often arises due to oversights in software development. Subsequently, threat actors place a malicious DLL in a directory that is prioritized in the search order ahead of the legitimate DLL directory. Frequently, the preferred location for this manipulation is the working directory of the target application, as it holds a prominent position in the search order.

In practical terms, during the installation of Windows components, updates, or software applications, files are systematically stored in the WinSxS directory. This directory acts as a centralized repository for system files, particularly DLLs, which are shared among various applications and components to ensure compatibility and prevent potential conflicts.

There is a few advantages to using the WinSxS folder for this attack:

1. Circumventing High Privilege Requirements: By targeting applications in the WinSxS folder, our implementation eliminates the need for elevated privileges to execute malicious code within applications located in a Windows folder. 
2. Eliminating the Need for Additional Binaries: Leveraging the WinSxS folder eliminates the requirement to introduce additional, potentially detectable binaries into the attack chain. Since Windows already indexes these files in the WinSxS folder, there's no need to bring our own vulnerable application.
3. Enhancing Stealth: Executing malicious code within the memory space of an application running from the WinSxS folder enhances stealth and minimizes the risk of detection. Security tools and analysts may be less likely to flag this approach as it leverages trusted components already present in the Windows environment.

The layout of these researchers POC is as follows:

![](https://static.wixstatic.com/media/d03b6f_a25d8dccc1c64797bb89f75aa39848bf~mv2.png/v1/fill/w_1110,h_812,al_c,q_90,usm_0.66_1.00_0.01,enc_auto/d03b6f_a25d8dccc1c64797bb89f75aa39848bf~mv2.png)

Here we see they created their custom folder and put their custom "malicious" DLL:

![](https://static.wixstatic.com/media/d03b6f_96c5ca80167c4997b3af724541c0ec70~mv2.png/v1/fill/w_1110,h_531,al_c,q_90,usm_0.66_1.00_0.01,enc_auto/d03b6f_96c5ca80167c4997b3af724541c0ec70~mv2.png)

They also developed an executable with the sole purpose of executing all other binaries located in the WinSxS folder and monitoring their operations, using Process Monitor. This was essentially to see which executables didnt follow specific path DLL search order, but rather loaded the custom DLL they made. 

After the execution of our custom tool, they identified binaries such as "ngentask.exe" and "aspnet_wp.exe" that attempted to search for their respective DLLs within our current directory, labeled as "NOT_A_SYSTEM_FOLDER_MS". This observation indicated the potential for loading their custom DLL simply by renaming it to match the expected DLL file sought by these executables. They focused on the "ngentask.exe" binary for further analysis.

![](https://static.wixstatic.com/media/d03b6f_dc44617e2508439e82977dc32da6bcad~mv2.png/v1/fill/w_1110,h_824,al_c,q_90,usm_0.66_1.00_0.01,enc_auto/d03b6f_dc44617e2508439e82977dc32da6bcad~mv2.png)

From the above screenshot we see that DLLs "webengine4.dll" and "mscorsvc.dll" are searched on the current folder "NOT_A_SYSTEM_FOLDER_MS". This would indicate that ngentask.exe is not specifying the path for loading mscorsvc.dll. So what they did was made a directory called NOT_A_SYSTEM_FOLDER_MS and put a custom dll in there and renamed it to mscorsvc.dll. They opened powershell and navigated to that folder and invoked the ngentask.exe file that resides in the WinSxS folder, but run from this folder location. The intent is to see, with Process Monitor, what search order it uses to load mscorsvc.dll. 

![](https://static.wixstatic.com/media/d03b6f_274c4fdc48c140f3a11011dd2b611b7b~mv2.png/v1/fill/w_1110,h_758,al_c,q_90,usm_0.66_1.00_0.01,enc_auto/d03b6f_274c4fdc48c140f3a11011dd2b611b7b~mv2.png)

Looking at Process Monitor, we see that it did load it from the custom folder, thus allowing injection to happen.

![](https://static.wixstatic.com/media/d03b6f_0a850725b53248719792c52b9296cc3b~mv2.png/v1/fill/w_1110,h_659,al_c,q_90,usm_0.66_1.00_0.01,enc_auto/d03b6f_0a850725b53248719792c52b9296cc3b~mv2.png)

It's important to acknowledge that additional vulnerable binaries may be present in the WinSxS folder as the system undergoes new updates. Below we add a table summarizing the vulnerable executables located in the WinSxS folder during our research and the corresponding resources which are searched during its execution. It's important to clarify that the identification of these files doesn't automatically imply their vulnerability but rather serves as a strong indication, additional tests must be done in each of the binaries to confirm its vulnerability: 

1. Conhost.exe: ClipUp.exe, ipconfig.exe, route.exe and mcbuilder.exe
2. Forfiles.exe: cmd.exe
3. Iediagcmd.exe: ipconfig.exe
4. Stordiag.exe: Systeminfo.exe
5. Aspnet_wp.exe: webengine.dll and webengine4.dll
6. Aspnet_regiis.exe: webengine4.dll
7. Aspnet_state.exe: webengine4.dll
8. Csc.exe: VCRUNTIME140_1_CLR0400.dll
9. Cvtres.exe: VCRUNTIME140_1_CLR0400.dll
10. Ilasm.exe: fusion.dll and VCRUNTIME140_1_CLR0400.dll
11. Ngentask.exe: mscorsvc.dll
12. Ngen.exe: VCRUNTIME140_1_CLR0400.dll
13. NisSrv.exe: mpclient.dll

# Steps to reproduce
1. Create a custom folder somewhere on your computer (like Documents\dlltesting)
2. Download and install Process Monitor from sysinternals
3. Grab a "malicious" DLL from Atomic Red Team https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/src/Win32/T1218.dll 
4. Copy this DLL to your custom folder and rename it mscorsvc.dll (doing the ngentask.exe test)
5. Bring up Process Monitor and set the filter to look for Process Name contains ngentask.exe
6. Bring up powershell and navigate to your custom folder. 
7. Look in your WindowsSxS folder and find the x86_netfx4-ngentask_exe folder. There may be more than one, just pick one and open it and confirm that ngentask.exe is in there.
8. From your Powershell put in that path along with ngentask.exe. Example: C:\Windows\WinSxS\x86_netfx4-ngentask_exe_b03f5f7f11d50a3a_4.0.15805.0_none_1bb0d4ac7da3bfe1\ngentask.exe and hit enter
9. Go to your Process Monitor and search for mscorsvc.dll. You should see multiple attempts at different paths with a NAME NOT FOUND. You should see SUCCESS when it tries your custom folder location. 

# References
https://www.securityjoes.com/post/hide-and-seek-in-windows-closet-unmasking-the-winsxs-hijacking-hideout \
https://attack.mitre.org/techniques/T1574/001/ \
https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security 

# Detection
1. Parent Process Analysis: Examine parent-child relationships between processes, with a specific focus on trusted binaries. Look for activity involving:
* Unusual processes that invoke binaries from the WinSxS folder.
* Legitimate binaries in the WinSxS folder spawning unexpected child processes.
2. Behavior Analysis: Monitor closely all the activities performed by the binaries residing in the WinSxS folder. Focusing on both network communications and file operations. You can look for activity such as:
* WinSxS binaries connecting to remote servers.
* WinSxS binaries loading modules from uncommon folders.
3. Monitor for changes made to .manifest/.local redirection files, or file systems for moving, renaming, replacing, or modifying DLLs. Changes in the set of DLLs that are loaded by a process (compared with past behavior) that do not correlate with known software, patches, etc., are suspicious.
4. Monitor DLLs loaded into a process and detect DLLs that have the same file name but abnormal paths.

# Mitigations
1. Utilize an EDR to look for toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for DLL hijacking weaknesses. Additionally, its popular for the attackers to make a malicious DLL using Metasploit, so an EDR that can catch Meterpreter payloads.
2. Disallow loading of remote DLLs. This is included by default in Windows Server 2012+ 
3. Enable Safe DLL Search Mode to force search for system DLLs in directories with greater restrictions (e.g. %SYSTEMROOT%)to be used before local directory DLLs (e.g. a user's home directory). The Safe DLL Search Mode can be enabled via Group Policy at Computer Configuration > [Policies] > Administrative Templates > MSS (Legacy): MSS: (SafeDllSearchMode) Enable Safe DLL search mode. The associated Windows Registry key for this is located at HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDLLSearchMode


# MITRE
T1574.001 Hijack Execution Flow: DLL Search Order Hijacking \
T1574.002 Hijack Execution Flow: DLL Side-Loading \
T1574.008 Hijack Execution Flow: Path Interception by Search Order Hijacking \
T1548 Abuse Elevation Control Mechanism





