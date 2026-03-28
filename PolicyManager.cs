using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
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

    private static CimSession CreateSession()
    {
        var options = new DComSessionOptions
        {
            Impersonation = ImpersonationType.Impersonate
        };
        return CimSession.Create("localhost", options);
    }

    public void DeployPolicy(string policyGuid, string policyBase64)
    {
        // MDM WMI Bridge write operations require SYSTEM context
        using var impersonation = NativeSystem.IsSystem() ? null : NativeSystem.ImpersonateSystem();
        using var session = CreateSession();

        // Check if policy already exists (for Replace/Update)
        CimInstance? existing = FindInstance(session, ClassName, policyGuid);

        if (existing is not null)
        {
            existing.CimInstanceProperties["Policy"].Value = policyBase64;
            session.ModifyInstance(Namespace, existing);
            existing.Dispose();
        }
        else
        {
            using var newInstance = new CimInstance(ClassName, Namespace);
            newInstance.CimInstanceProperties.Add(
                CimProperty.Create("ParentID", ParentId, CimType.String, CimFlags.Key));
            newInstance.CimInstanceProperties.Add(
                CimProperty.Create("InstanceID", policyGuid, CimType.String, CimFlags.Key));
            newInstance.CimInstanceProperties.Add(
                CimProperty.Create("Policy", policyBase64, CimType.String, CimFlags.Property));
            session.CreateInstance(Namespace, newInstance);
        }
    }

    public void DeletePolicy(string policyGuid)
    {
        // MDM WMI Bridge write operations require SYSTEM context
        using var impersonation = NativeSystem.IsSystem() ? null : NativeSystem.ImpersonateSystem();
        using var session = CreateSession();

        var instance = FindInstance(session, ClassName, policyGuid)
            ?? throw new InvalidOperationException($"Policy {policyGuid} not found");
        session.DeleteInstance(Namespace, instance);
        instance.Dispose();
    }

    public List<PolicyInstance> GetAllPolicies()
    {
        var policies = new List<PolicyInstance>();
        using var session = CreateSession();

        foreach (var obj in session.EnumerateInstances(Namespace, ClassName))
        {
            string id = obj.CimInstanceProperties["InstanceID"]?.Value?.ToString() ?? "?";
            string policy = obj.CimInstanceProperties["Policy"]?.Value?.ToString() ?? "";
            policies.Add(new PolicyInstance(id, policy));
            obj.Dispose();
        }

        return policies;
    }

    public PolicyInfoResult GetPolicyInfo(string policyGuid)
    {
        using var session = CreateSession();
        try
        {
            var instance = FindInstance(session, ClassName, policyGuid);
            if (instance is null)
                return new PolicyInfoResult();

            var result = new PolicyInfoResult(
                IsAuthorized: Prop(instance, "IsAuthorized"),
                IsDeployed: Prop(instance, "IsDeployed"),
                IsEffective: Prop(instance, "IsEffective"),
                IsBasePolicy: Prop(instance, "IsBasePolicy"),
                IsSystemPolicy: Prop(instance, "IsSystemPolicy"),
                Status: Prop(instance, "Status"),
                Version: Prop(instance, "Version"),
                FriendlyName: Prop(instance, "FriendlyName"),
                BasePolicyId: Prop(instance, "BasePolicyId"),
                PolicyOptions: Prop(instance, "PolicyOptions"));
            instance.Dispose();
            return result;
        }
        catch
        {
            return new PolicyInfoResult();
        }
    }

    private static CimInstance? FindInstance(CimSession session, string className, string policyGuid)
    {
        string query = $"SELECT * FROM {className} WHERE InstanceID='{policyGuid}'";
        foreach (var instance in session.QueryInstances(Namespace, "WQL", query))
        {
            return instance;
        }
        return null;
    }

    private static string Prop(CimInstance instance, string name)
    {
        return instance.CimInstanceProperties[name]?.Value?.ToString() ?? "-";
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
