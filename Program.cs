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
            Console.WriteLine("No policies deployed.");
            return 0;
        }

        // ── column widths ────────────────────────────────────────────────────
        int wNum    = results.Count.ToString().Length + 1; // e.g. 2 for ≤99 policies
        const int wId     = 36;   // GUID is always 36 chars
        const int wSigned =  7;   // True / False
        const int wBase   =  7;   // True / False
        const int wDep    =  9;   // True
        const int wVer    = 14;   // e.g. 10.29480.0.0
        // total visible width
        int totalW = wNum + wId + wSigned + wBase + wDep + wVer + 15;

        string Bar() => new string('─', totalW);

        // ── header ──────────────────────────────────────────────────────────
        Console.WriteLine(Bar());
        Console.WriteLine(
            " " + "#".PadRight(wNum)            + " │ " +
            "POLICY ID".PadRight(wId)           + " │ " +
            "SIGNED".PadRight(wSigned)          + " │ " +
            "BASE".PadRight(wBase)              + " │ " +
            "DEPLOYED".PadRight(wDep)           + " │ " +
            "VERSION");
        Console.WriteLine(Bar());

        // ── rows ─────────────────────────────────────────────────────────────
        for (int i = 0; i < results.Count; i++)
        {
            var (policy, info) = results[i];

            Console.WriteLine(
                " " + (i + 1).ToString().PadRight(wNum) + " │ " +
                policy.InstanceId.PadRight(wId)         + " │ " +
                info.IsSignedPolicy.PadRight(wSigned)   + " │ " +
                info.IsBasePolicy.PadRight(wBase)       + " │ " +
                info.IsDeployed.PadRight(wDep)          + " │ " +
                info.Version);

            if (info.PolicyOptions != "-")
            {
                string prefix = "   " + new string(' ', wNum) + "   Options : ";
                string indent = new string(' ', prefix.Length);
                PrintWrapped(prefix, indent, info.PolicyOptions, totalW);
            }

            // blank line between entries (but not after the last one)
            if (i < results.Count - 1)
                Console.WriteLine();
        }

        // ── footer ──────────────────────────────────────────────────────────
        Console.WriteLine(Bar());
        Console.WriteLine($"  {results.Count} polic{(results.Count == 1 ? "y" : "ies")}");

        return exitCode;
    }
    catch (Exception ex)
    {
        WriteError($"Error listing policies: {ex.Message}");
        return 1;
    }
}

/// <summary>
/// Prints comma-separated <paramref name="text"/> with word-wrapping at
/// <paramref name="maxWidth"/> columns.  The first line starts with
/// <paramref name="prefix"/>; subsequent continuation lines start with
/// <paramref name="indent"/> (same visual length as prefix).
/// </summary>
static void PrintWrapped(string prefix, string indent, string text, int maxWidth)
{
    string[] tokens = text.Split(", ", StringSplitOptions.RemoveEmptyEntries);
    string current  = prefix;

    foreach (string token in tokens)
    {
        // first token on a new line — no leading separator
        bool isFirst = current == prefix || current == indent;
        string candidate = isFirst ? current + token : current + ", " + token;

        if (candidate.Length > maxWidth && !isFirst)
        {
            Console.WriteLine(current + ",");
            current = indent + token;
        }
        else
        {
            current = candidate;
        }
    }

    if (current.Length > 0)
        Console.WriteLine(current);
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
