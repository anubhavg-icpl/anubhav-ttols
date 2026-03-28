using System.Diagnostics;

namespace anubhav_ttols.Tests;

public class CliEndToEndTests
{
    private static readonly string ExePath = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "bin", "Debug", "net10.0-windows", "anubhav-ttols.exe"));

    private static (int ExitCode, string StdOut, string StdErr) RunCli(params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = ExePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var proc = Process.Start(psi)!;
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(10_000);
        return (proc.ExitCode, stdout, stderr);
    }

    [Fact]
    public void NoArgs_ShowsUsage()
    {
        var (exitCode, stdout, _) = RunCli();

        Assert.Contains("WDAC CIP Policy Manager", stdout);
        Assert.Contains("apply", stdout);
        Assert.Contains("remove", stdout);
        Assert.Contains("list", stdout);
    }

    [Fact]
    public void UnknownCommand_ShowsUsageOrElevationError()
    {
        var (exitCode, stdout, stderr) = RunCli("foobar");

        // If not elevated: stderr has elevation error. If elevated: stdout has usage.
        string combined = stdout + stderr;
        Assert.True(
            combined.Contains("Usage") || combined.Contains("WDAC") || combined.Contains("Administrator"),
            "Should show usage or elevation error");
    }

    [Fact]
    public void Apply_MissingFile_ShowsError()
    {
        var (exitCode, _, stderr) = RunCli("apply", @"C:\nonexistent\file.cip");

        // If not elevated, gets elevation error; if elevated, gets file error
        Assert.Equal(1, exitCode);
        Assert.True(
            stderr.Contains("ERROR") || stderr.Contains("Administrator"),
            "Should show an error message");
    }

    [Fact]
    public void Apply_NoFileArgument_ShowsError()
    {
        var (exitCode, _, stderr) = RunCli("apply");

        Assert.Equal(1, exitCode);
        Assert.True(
            stderr.Contains("ERROR") || stderr.Contains("Administrator"),
            "Should show an error message");
    }

    [Fact]
    public void Remove_NoGuidArgument_ShowsError()
    {
        var (exitCode, _, stderr) = RunCli("remove");

        Assert.Equal(1, exitCode);
        Assert.True(
            stderr.Contains("ERROR") || stderr.Contains("Administrator"),
            "Should show an error message");
    }

    [Fact]
    public void ExeExists()
    {
        Assert.True(File.Exists(ExePath), $"Expected exe at: {ExePath}");
    }
}
