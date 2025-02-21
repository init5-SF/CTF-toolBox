function Read-FileWithSeBackupPrivilege {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    # Define the API functions
    if (-not ("Win32.FileUtils" -as [type])) {
        Add-Type -Namespace Win32 -Name FileUtils -MemberDefinition @'
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile,
            [Out] byte[] buffer,
            uint bytesToRead,
            out uint bytesRead,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool MoveFileEx(
            string lpExistingFileName,
            string lpNewFileName,
            uint dwFlags);

        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const uint MOVEFILE_COPY_ALLOWED = 0x2;
        public const uint MOVEFILE_REPLACE_EXISTING = 0x1;
        public const uint MOVEFILE_WRITE_THROUGH = 0x8;
'@
    }

    # Constants
    $GENERIC_READ = [uint32]"0x80000000"
    $FILE_SHARE_READ = [uint32]1
    $OPEN_EXISTING = [uint32]3
    $FILE_FLAG_BACKUP_SEMANTICS = [uint32]"0x02000000"

    # Open file with backup semantics
    $handle = [Win32.FileUtils]::CreateFile(
        $FilePath,
        $GENERIC_READ,
        $FILE_SHARE_READ,
        [IntPtr]::Zero,
        $OPEN_EXISTING,
        $FILE_FLAG_BACKUP_SEMANTICS,
        [IntPtr]::Zero
    )

    if ($handle -eq [Win32.FileUtils]::INVALID_HANDLE_VALUE) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Failed to open file. Error code: $errorCode"
        exit
    }

    try {
        # Create buffer and read file
        $buffer = New-Object byte[] 4096
        $bytesRead = 0

        # Read the file content
        $success = [Win32.FileUtils]::ReadFile($handle, $buffer, 4096, [ref]$bytesRead, [IntPtr]::Zero)
    
        if ($success) {
            Write-Host "File contents:"
            Write-Host "--------------"
            [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
        }
        else {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "Failed to read file. Error code: $errorCode"
        }
    }
    finally {
        # Close the handle using the already defined method
        [Win32.FileUtils]::CloseHandle($handle)
    }
}


function Copy-FileWithSeBackupPrivilege {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    # Define the API functions if not already defined
    if (-not ("Win32.FileUtils" -as [type])) {
        Add-Type -Namespace Win32 -Name FileUtils -MemberDefinition @'
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile,
            [Out] byte[] buffer,
            uint bytesToRead,
            out uint bytesRead,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(
            IntPtr hFile,
            byte[] buffer,
            uint numberOfBytesToWrite,
            out uint numberOfBytesWritten,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hFile);

        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
'@
    }

    # Constants
    $GENERIC_READ = [uint32]"0x80000000"
    $GENERIC_WRITE = [uint32]"0x40000000"
    $FILE_SHARE_READ = [uint32]1
    $FILE_SHARE_WRITE = [uint32]2
    $OPEN_EXISTING = [uint32]3
    $CREATE_ALWAYS = [uint32]2
    $FILE_FLAG_BACKUP_SEMANTICS = [uint32]"0x02000000"

    # Open source file with backup semantics
    $sourceHandle = [Win32.FileUtils]::CreateFile(
        $SourcePath,
        $GENERIC_READ,
        $FILE_SHARE_READ,
        [IntPtr]::Zero,
        $OPEN_EXISTING,
        $FILE_FLAG_BACKUP_SEMANTICS,
        [IntPtr]::Zero
    )

    if ($sourceHandle -eq [Win32.FileUtils]::INVALID_HANDLE_VALUE) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Failed to open source file. Error code: $errorCode"
        return
    }

    # Create destination file with backup semantics
    $destHandle = [Win32.FileUtils]::CreateFile(
        $DestinationPath,
        $GENERIC_WRITE,
        $FILE_SHARE_WRITE,
        [IntPtr]::Zero,
        $CREATE_ALWAYS,
        $FILE_FLAG_BACKUP_SEMANTICS,
        [IntPtr]::Zero
    )

    if ($destHandle -eq [Win32.FileUtils]::INVALID_HANDLE_VALUE) {
        [Win32.FileUtils]::CloseHandle($sourceHandle)
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Failed to create destination file. Error code: $errorCode"
        return
    }

    try {
        $buffer = New-Object byte[] 8192
        $bytesRead = 0
        $bytesWritten = 0
        $totalBytesCopied = 0

        # Copy the file in chunks
        do {
            $success = [Win32.FileUtils]::ReadFile($sourceHandle, $buffer, 8192, [ref]$bytesRead, [IntPtr]::Zero)
            if (-not $success) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Error "Failed to read from source file. Error code: $errorCode"
                return
            }

            if ($bytesRead -gt 0) {
                $success = [Win32.FileUtils]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)
                if (-not $success) {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Error "Failed to write to destination file. Error code: $errorCode"
                    return
                }
                $totalBytesCopied += $bytesWritten
            }
        } while ($bytesRead -eq 8192)

        Write-Host "Successfully copied $totalBytesCopied bytes"
    }
    finally {
        # Clean up handles
        [Win32.FileUtils]::CloseHandle($sourceHandle)
        [Win32.FileUtils]::CloseHandle($destHandle)
    }
}

#- Optimized version of Lee Holmes' snippet
#- Original code - https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/

$privs = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace TokenManipulator
{
    public class enableTokenPrivs
    {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
        
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        private const int SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int TOKEN_QUERY = 0x00000008;
        private const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        private static readonly string[] Privileges = {
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", 
            "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", 
            "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", 
            "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", 
            "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege",
            "SeDelegateSessionUserImpersonatePrivilege"
        };

        public static void EnablePrivilege()
        {
            using (var process = Process.GetCurrentProcess())
            {
                var htok = IntPtr.Zero;
                if (!OpenProcessToken(process.Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok))
                    return;

                var tp = new TokPriv1Luid { Count = 1, Attr = SE_PRIVILEGE_ENABLED };

                foreach (var privilege in Privileges)
                {
                    LookupPrivilegeValue(null, privilege, ref tp.Luid);
                    AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                }
            }
        }
    }
}
'@
$type = Add-Type $privs -PassThru
$type[0]::EnablePrivilege() 2>&1
