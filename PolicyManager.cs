using System.Management;
using System.Security.Principal;

namespace anubhav_ttols;

public interface IWmiProvider
{
    void DeployPolicy(string policyGuid, string policyBase64);
    void DeletePolicy(string policyGuid);
    List<PolicyInstance> GetAllPolicies();
    PolicyInfoResult GetPolicyInfo(string policyGuid);
}

public record PolicyInstance(string InstanceId, string PolicyBase64);

public record PolicyInfoResult(
    string IsAuthorized = "-",
    string IsDeployed = "-",
    string IsEffective = "-",
    string IsBasePolicy = "-",
    string IsSystemPolicy = "-",
    string Status = "-",
    string Version = "-",
    string FriendlyName = "-",
    string BasePolicyId = "-",
    string PolicyOptions = "-");

public sealed class WmiProvider : IWmiProvider
{
    public const string Namespace = @"root\cimv2\mdm\dmmap";
    public const string ClassName = "MDM_ApplicationControl_Policies01_01";
    public const string InfoClassName = "MDM_ApplicationControl_Policies01_01_PolicyInfo01";
    public const string ParentId = "./Vendor/MSFT/ApplicationControl/Policies";

    public void DeployPolicy(string policyGuid, string policyBase64)
    {
        using var mgmtClass = new ManagementClass(Namespace, ClassName, null);
        using var instance = mgmtClass.CreateInstance();
        instance["ParentID"] = ParentId;
        instance["InstanceID"] = policyGuid;
        instance["Policy"] = policyBase64;
        instance.Put();
    }

    public void DeletePolicy(string policyGuid)
    {
        string instancePath = $"{ClassName}.ParentID=\"{ParentId}\",InstanceID=\"{policyGuid}\"";
        using var instance = new ManagementObject(Namespace, instancePath, null);
        instance.Get();
        instance.Delete();
    }

    public List<PolicyInstance> GetAllPolicies()
    {
        var policies = new List<PolicyInstance>();
        using var searcher = new ManagementObjectSearcher(Namespace, $"SELECT * FROM {ClassName}");
        foreach (ManagementObject obj in searcher.Get())
        {
            string id = obj["InstanceID"]?.ToString() ?? "?";
            string policy = obj["Policy"]?.ToString() ?? "";
            policies.Add(new PolicyInstance(id, policy));
        }
        return policies;
    }

    public PolicyInfoResult GetPolicyInfo(string policyGuid)
    {
        return new PolicyInfoResult(
            IsAuthorized: QueryInfoProperty(policyGuid, "IsAuthorized"),
            IsDeployed: QueryInfoProperty(policyGuid, "IsDeployed"),
            IsEffective: QueryInfoProperty(policyGuid, "IsEffective"),
            IsBasePolicy: QueryInfoProperty(policyGuid, "IsBasePolicy"),
            IsSystemPolicy: QueryInfoProperty(policyGuid, "IsSystemPolicy"),
            Status: QueryInfoProperty(policyGuid, "Status"),
            Version: QueryInfoProperty(policyGuid, "Version"),
            FriendlyName: QueryInfoProperty(policyGuid, "FriendlyName"),
            BasePolicyId: QueryInfoProperty(policyGuid, "BasePolicyId"),
            PolicyOptions: QueryInfoProperty(policyGuid, "PolicyOptions"));
    }

    private static string QueryInfoProperty(string policyGuid, string property)
    {
        try
        {
            string instancePath = $"{InfoClassName}.ParentID=\"{ParentId}/{policyGuid}/PolicyInfo\",InstanceID=\"{property}\"";
            using var obj = new ManagementObject(Namespace, instancePath, null);
            obj.Get();
            return obj[property]?.ToString() ?? "-";
        }
        catch
        {
            return "-";
        }
    }
}

public static class PolicyGuidResolver
{
    public static string? TryExtractGuidFromBinary(byte[] policyBytes)
    {
        if (policyBytes.Length < 20)
            return null;

        try
        {
            var guid = new Guid(policyBytes.AsSpan(4, 16));
            if (guid == Guid.Empty)
                return null;
            return guid.ToString("D");
        }
        catch
        {
            return null;
        }
    }

    public static string? TryExtractGuidFromFilename(string filePath)
    {
        string name = Path.GetFileNameWithoutExtension(filePath);
        name = name.Trim('{', '}');
        if (Guid.TryParse(name, out var guid) && guid != Guid.Empty)
            return guid.ToString("D");
        return null;
    }

    public static string NormalizeGuid(string input)
    {
        input = input.Trim('{', '}');
        if (Guid.TryParse(input, out var guid))
            return guid.ToString("D");
        return input;
    }

    public static string? ResolveGuid(byte[] policyBytes, string filePath, string? guidOverride)
    {
        string? resolved = guidOverride is not null ? NormalizeGuid(guidOverride) : null;
        resolved ??= TryExtractGuidFromBinary(policyBytes);
        resolved ??= TryExtractGuidFromFilename(filePath);
        return resolved;
    }
}

public static class ElevationCheck
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}

public class PolicyManager
{
    private readonly IWmiProvider _wmi;

    public PolicyManager(IWmiProvider wmi)
    {
        _wmi = wmi;
    }

    public int Apply(string filePath, string? guidOverride = null)
    {
        if (!File.Exists(filePath))
            return 1;

        byte[] policyBytes = File.ReadAllBytes(filePath);
        string policyBase64 = Convert.ToBase64String(policyBytes);

        string? policyGuid = PolicyGuidResolver.ResolveGuid(policyBytes, filePath, guidOverride);
        if (policyGuid is null)
            return 1;

        _wmi.DeployPolicy(policyGuid, policyBase64);
        return 0;
    }

    public int Remove(string policyGuid)
    {
        string normalized = PolicyGuidResolver.NormalizeGuid(policyGuid);
        _wmi.DeletePolicy(normalized);
        return 0;
    }

    public (int ExitCode, List<(PolicyInstance Policy, PolicyInfoResult Info)> Results) List()
    {
        var policies = _wmi.GetAllPolicies();
        var results = new List<(PolicyInstance, PolicyInfoResult)>();
        foreach (var p in policies)
        {
            var info = _wmi.GetPolicyInfo(p.InstanceId);
            results.Add((p, info));
        }
        return (0, results);
    }
}
