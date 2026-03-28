using anubhav_ttols;

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

if (!ElevationCheck.IsElevated())
{
    WriteError("This tool must run as Administrator (or SYSTEM).");
    return 1;
}

var wmi = new WmiProvider();
var manager = new PolicyManager(wmi);

return args[0].ToLowerInvariant() switch
{
    "apply" => RunApply(args, manager),
    "remove" => RunRemove(args, manager),
    "list" => RunList(manager),
    _ => PrintUsage()
};

static int RunApply(string[] args, PolicyManager manager)
{
    string? filePath = null;
    string? guidOverride = null;

    for (int i = 1; i < args.Length; i++)
    {
        if (args[i] is "--guid" && i + 1 < args.Length)
            guidOverride = args[++i];
        else if (filePath is null)
            filePath = args[i];
    }

    if (filePath is null)
    {
        WriteError("Usage: anubhav-ttols apply <path-to-.cip/.bin> [--guid <GUID>]");
        return 1;
    }

    if (!File.Exists(filePath))
    {
        WriteError($"File not found: {filePath}");
        return 1;
    }

    byte[] policyBytes = File.ReadAllBytes(filePath);
    string? policyGuid = PolicyGuidResolver.ResolveGuid(policyBytes, filePath, guidOverride);

    if (policyGuid is null)
    {
        WriteError("Could not determine Policy GUID. Use --guid <GUID> or name the file {GUID}.cip");
        return 1;
    }

    Console.WriteLine($"Deploying policy: {policyGuid}");
    Console.WriteLine($"Source: {Path.GetFileName(filePath)} ({policyBytes.Length} bytes)");

    try
    {
        int result = manager.Apply(filePath, guidOverride);
        if (result == 0)
            WriteSuccess($"Policy {policyGuid} deployed successfully.");
        return result;
    }
    catch (Exception ex)
    {
        WriteError($"Error deploying policy: {ex.Message}");
        return 1;
    }
}

static int RunRemove(string[] args, PolicyManager manager)
{
    if (args.Length < 2)
    {
        WriteError("Usage: anubhav-ttols remove <policy-GUID>");
        return 1;
    }

    string policyGuid = PolicyGuidResolver.NormalizeGuid(args[1]);
    Console.WriteLine($"Removing policy: {policyGuid}");

    try
    {
        int result = manager.Remove(args[1]);
        if (result == 0)
        {
            WriteSuccess($"Policy {policyGuid} removed successfully.");
            Console.WriteLine("Note: Policy stays in effect until next reboot.");
            Console.WriteLine("Tip:  To avoid reboot, first apply an AllowAll policy, then remove it.");
        }
        return result;
    }
    catch (InvalidOperationException)
    {
        WriteError($"Policy {policyGuid} not found.");
        return 1;
    }
    catch (Exception ex)
    {
        WriteError($"Error removing policy: {ex.Message}");
        return 1;
    }
}

static int RunList(PolicyManager manager)
{
    try
    {
        var (exitCode, results) = manager.List();
        if (results.Count == 0)
        {
            Console.WriteLine("No policies deployed via ApplicationControl CSP.");
            return 0;
        }

        Console.WriteLine($"{"GUID",-40} {"Authorized",-12} {"Deployed",-10} {"Effective",-10} {"Status",-8} {"Version"}");
        Console.WriteLine(new string('-', 100));

        foreach (var (policy, info) in results)
        {
            Console.WriteLine($"{policy.InstanceId,-40} {info.IsAuthorized,-12} {info.IsDeployed,-10} {info.IsEffective,-10} {info.Status,-8} {info.Version}");
        }
        return exitCode;
    }
    catch (Exception ex)
    {
        WriteError($"Error listing policies: {ex.Message}");
        return 1;
    }
}

static int PrintUsage()
{
    Console.WriteLine("anubhav-ttols - WDAC CIP Policy Manager");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  anubhav-ttols apply <file.cip|file.bin> [--guid <GUID>]");
    Console.WriteLine("  anubhav-ttols remove <policy-GUID>");
    Console.WriteLine("  anubhav-ttols list");
    Console.WriteLine();
    Console.WriteLine("Requires elevation (run as Administrator).");
    return 0;
}

static void WriteError(string msg)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.Error.WriteLine($"ERROR: {msg}");
    Console.ResetColor();
}

static void WriteSuccess(string msg)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine(msg);
    Console.ResetColor();
}
