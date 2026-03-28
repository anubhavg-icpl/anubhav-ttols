using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace anubhav_ttols;

/// <summary>
/// Impersonates SYSTEM by borrowing a token from a SYSTEM-owned process.
/// This allows MDM WMI Bridge write operations without PsExec or external tools.
/// Requires the calling process to run as Administrator with SeDebugPrivilege.
/// </summary>
public static class NativeSystem
{
    public static bool IsSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem;
    }

    /// <summary>
    /// Impersonate SYSTEM for the duration of the returned IDisposable.
    /// Usage: using (NativeSystem.ImpersonateSystem()) { /* code runs as SYSTEM */ }
    /// </summary>
    public static SystemImpersonation ImpersonateSystem()
    {
        EnableDebugPrivilege();

        nint systemToken = BorrowSystemToken();
        if (systemToken == 0)
            throw new InvalidOperationException(
                "Failed to obtain SYSTEM token. Ensure you are running as Administrator.");

        nint dupToken = 0;
        try
        {
            if (!DuplicateTokenEx(systemToken, TOKEN_ALL_ACCESS, nint.Zero,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenImpersonation, out dupToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Failed to duplicate SYSTEM token");
            }

            if (!ImpersonateLoggedOnUser(dupToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Failed to impersonate SYSTEM");
            }

            return new SystemImpersonation(dupToken);
        }
        catch
        {
            if (dupToken != 0) CloseHandle(dupToken);
            throw;
        }
        finally
        {
            CloseHandle(systemToken);
        }
    }

    private static nint BorrowSystemToken()
    {
        // Try winlogon first (always runs as SYSTEM), then fallback to lsass
        foreach (string processName in new[] { "winlogon", "lsass", "services" })
        {
            foreach (var proc in Process.GetProcessesByName(processName))
            {
                try
                {
                    nint procHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
                    if (procHandle == 0) continue;

                    try
                    {
                        if (OpenProcessToken(procHandle, TOKEN_DUPLICATE | TOKEN_QUERY, out nint token))
                            return token;
                    }
                    finally
                    {
                        CloseHandle(procHandle);
                    }
                }
                catch
                {
                    // Skip processes we can't access
                }
            }
        }

        return 0;
    }

    private static void EnableDebugPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            out nint tokenHandle))
            return;

        try
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out LUID luid))
                return;

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES[1]
            };
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, nint.Zero, nint.Zero);
        }
        finally
        {
            CloseHandle(tokenHandle);
        }
    }

    public sealed class SystemImpersonation : IDisposable
    {
        private nint _token;

        internal SystemImpersonation(nint token)
        {
            _token = token;
        }

        public void Dispose()
        {
            RevertToSelf();
            if (_token != 0)
            {
                CloseHandle(_token);
                _token = 0;
            }
        }
    }

    // P/Invoke declarations

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_ALL_ACCESS = 0xF01FF;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityImpersonation = 2
    }

    private enum TOKEN_TYPE
    {
        TokenImpersonation = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(nint ProcessHandle, uint DesiredAccess, out nint TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(nint hExistingToken, uint dwDesiredAccess,
        nint lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType, out nint phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateLoggedOnUser(nint hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(nint TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, nint PreviousState, nint ReturnLength);
}
