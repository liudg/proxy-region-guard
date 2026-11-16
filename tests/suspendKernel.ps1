param([int]$KernelPid, [string]$ExpectedExecutable)
$ErrorActionPreference = 'Stop'
$processInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$KernelPid"
if (-not $processInfo -or $processInfo.ExecutablePath -ne $ExpectedExecutable) {
  throw '测试内核进程身份不匹配'
}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KernelSuspend {
  [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr handle);
}
'@
$kernelProcess = Get-Process -Id $KernelPid
$result = [KernelSuspend]::NtSuspendProcess($kernelProcess.Handle)
if ($result -ne 0) { throw "暂停测试内核失败：$result" }
