#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
import enum


class PrivilegeValues(enum.Enum):
	SE_CREATE_TOKEN = 2
	SE_ASSIGNPRIMARYTOKEN = 3
	SE_LOCK_MEMORY = 4
	SE_INCREASE_QUOTA = 5
	SE_UNSOLICITED_INPUT = 6
	SE_TCB = 7
	SE_SECURITY = 8
	SE_TAKE_OWNERSHIP = 9
	SE_LOAD_DRIVER = 10
	SE_SYSTEM_PROFILE = 11
	SE_SYSTEMTIME = 12
	SE_PROF_SINGLE_PROCESS = 13
	SE_INC_BASE_PRIORITY = 14
	SE_CREATE_PAGEFILE = 15
	SE_CREATE_PERMANENT = 16
	SE_BACKUP = 17
	SE_RESTORE = 18
	SE_SHUTDOWN = 19
	SE_DEBUG = 20
	SE_AUDIT = 21
	SE_SYSTEM_ENVIRONMENT = 22
	SE_CHANGE_NOTIFY = 23
	SE_REMOTE_SHUTDOWN = 24
	SE_UNDOCK = 25
	SE_SYNC_AGENT = 26
	SE_ENABLE_DELEGATION = 27
	SE_MANAGE_VOLUME = 28
	SE_IMPERSONATE = 29
	SE_CREATE_GLOBAL = 30
	SE_TRUSTED_CREDMAN_ACCESS = 31
	SE_RELABEL = 32
	SE_INC_WORKING_SET = 33
	SE_TIME_ZONE = 34
	SE_CREATE_SYMBOLIC_LINK = 35


class Privileges(enum.Enum):
	# Required to assign the primary token of a process.
	# User Right: Replace a process-level token.
	SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege"

	# Required to generate audit-log entries. Give this privilege to secure servers.
	# User Right: Generate security audits.
	SE_AUDIT_NAME = "SeAuditPrivilege"

	# Required to perform backup operations.
	# This privilege causes the system to grant all read access control to any file, regardless of the access
	# control list (ACL) specified for the file. Any access request other than read is still evaluated with the ACL.
	# This privilege is required by the RegSaveKey and RegSaveKeyExfunctions.
	# The following access rights are granted if this privilege is held:
	SE_BACKUP_NAME = "SeBackupPrivilege"

	# Required to receive notifications of changes to files or directories.
	# This privilege also causes the system to skip all traversal access checks. It is enabled by default for all users.
	SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege"

	# Required to create named file mapping objects in the global namespace during Terminal Services sessions.
	# This privilege is enabled by default for administrators, services, and the local system account.
	# User Right: Create global objects.
	SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege"

	# Required to create a paging file. #User Right: Create a pagefile.
	SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege"

	# Required to create a permanent object.
	# User Right: Create permanent shared objects.
	SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege"

	# Required to create a symbolic link.
	# User Right: Create symbolic links.
	SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege"

	# Required to create a primary token.
	# User Right: Create a token object.
	# You cannot add this privilege to a user account with the "Create a token object" policy.
	# Additionally, you cannot add this privilege to an owned process using Windows APIs.
	# Windows Server 2003 and Windows XP with SP1 and earlier:  Windows APIs can add this privilege to an owned process.
	SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege"

	# Required to debug and adjust the memory of a process owned by another account.
	# User Right: Debug programs.
	SE_DEBUG_NAME = "SeDebugPrivilege"

	# Required to mark user and computer accounts as trusted for delegation.
	# User Right: Enable computer and user accounts to be trusted for delegation.
	SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege"

	# Required to impersonate.
	# User Right: Impersonate a client after authentication.
	SE_IMPERSONATE_NAME = "SeImpersonatePrivilege"

	# Required to increase the base priority of a process.
	# User Right: Increase scheduling priority.
	SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege"

	# Required to increase the quota assigned to a process.
	# User Right: Adjust memory quotas for a process.
	SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege"

	# Required to allocate more memory for applications that run in the context of users.
	# User Right: Increase a process working set.
	SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege"

	# Required to load or unload a device driver.
	# User Right: Load and unload device drivers.
	SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege"

	# Required to lock physical pages in memory.
	# User Right: Lock pages in memory.
	SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege"

	# Required to create a computer account.
	# User Right: Add workstations to domain.
	SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege"

	# Required to enable volume management privileges.
	# User Right: Manage the files on a volume.
	SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege"

	# Required to gather profiling information for a single process.
	# User Right: Profile single process.
	SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege"

	# Required to modify the mandatory integrity level of an object.
	# User Right: Modify an object label.
	SE_RELABEL_NAME = "SeRelabelPrivilege"

	# Required to shut down a system using a network request.
	# User Right: Force shutdown from a remote system.
	SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege"

	# Required to perform restore operations.
	# This privilege causes the system to grant all write access control to any file, regardless of the ACL specified
	# for the file. Any access request other than write is still evaluated with the ACL.
	# Additionally, this privilege enables you to set any valid user or group SID as the owner of a file.
	# This privilege is required by the RegLoadKey function. The following access rights are granted if this
	# privilege is held:
	SE_RESTORE_NAME = "SeRestorePrivilege"

	# Required to perform a number of security-related functions, such as controlling and viewing audit messages.
	# This privilege identifies its holder as a security operator.
	# User Right: Manage auditing and security log.
	SE_SECURITY_NAME = "SeSecurityPrivilege"

	# Required to shut down a local system.
	# User Right: Shut down the system.
	SE_SHUTDOWN_NAME = "SeShutdownPrivilege"

	# Required for a domain controller to use the Lightweight Directory Access Protocol directory synchronization
	# services. This privilege enables the holder to read all objects and properties in the directory, regardless
	# of the protection on the objects and properties. By default, it is assigned to the Administrator and
	# LocalSystem accounts on domain controllers.
	# User Right: Synchronize directory service data.
	SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege"

	# Required to modify the nonvolatile RAM of systems that use this type of memory to store configuration information.
	# User Right: Modify firmware environment values.
	SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege"

	# Required to gather profiling information for the entire system.
	# User Right: Profile system performance.
	SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege"

	# Required to modify the system time.
	# User Right: Change the system time.
	SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege"

	# Required to take ownership of an object without being granted discretionary access. This privilege allows
	# the owner value to be set only to those values that the holder may legitimately assign as the owner of an object.
	# User Right: Take ownership of files or other objects.
	SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege"

	# This privilege identifies its holder as part of the trusted computer base. Some trusted protected subsystems
	# are granted this privilege.
	# User Right: Act as part of the operating system.
	SE_TCB_NAME = "SeTcbPrivilege"

	# Required to adjust the time zone associated with the computer's internal clock.
	# User Right: Change the time zone.
	SE_TIME_ZONE_NAME = "SeTimeZonePrivilege"

	# Required to access Credential Manager as a trusted caller.
	# User Right: Access Credential Manager as a trusted caller.
	SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege"

	# Required to undock a laptop.
	# User Right: Remove computer from docking station.
	SE_UNDOCK_NAME = "SeUndockPrivilege"

	SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege"
