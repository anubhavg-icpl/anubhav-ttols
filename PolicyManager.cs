using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using System.Security.Cryptography.Pkcs;
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
    string PolicyOptions = "-",
    string IsSignedPolicy = "-");

public sealed class WmiProvider : IWmiProvider
{
    public const string Namespace = @"root\cimv2\mdm\dmmap";
    public const string ClassName = "MDM_ApplicationControl_Policies01_01";
    public const string InfoClassName = "MDM_ApplicationControl_Policies01_01_PolicyInfo01";
    public const string ParentId = "./Vendor/MSFT/ApplicationControl/Policies";

    // Ordered by likelihood. Probed once via GetClass() and cached.
    private static readonly string[] InfoClassCandidates =
    [
        "MDM_ApplicationControl_Policies01_PolicyInfo01",      // most common
        "MDM_ApplicationControl_Policies01_01_PolicyInfo01",   // older naming
        "MDM_ApplicationControl_PolicyInfo01",                 // flat naming
    ];
    private static string? _resolvedInfoClass;

    private static CimSession CreateSession()
    {
        var options = new DComSessionOptions
        {
            Impersonation = ImpersonationType.Impersonate
        };
        return CimSession.Create("localhost", options);
    }

    /// <summary>
    /// Returns the first PolicyInfo WMI class that actually exists on this OS build,
    /// probing via GetClass (schema-only, no instance enumeration). Result is cached.
    /// </summary>
    private static string? ResolveInfoClass(CimSession session)
    {
        if (_resolvedInfoClass is not null)
            return _resolvedInfoClass;

        foreach (var candidate in InfoClassCandidates)
        {
            try
            {
                using var cls = session.GetClass(Namespace, candidate);
                // Verify the class actually carries the info properties we need
                if (cls.CimClassProperties["IsAuthorized"] is not null)
                {
                    _resolvedInfoClass = candidate;
                    return _resolvedInfoClass;
                }
            }
            catch
            {
                // Class doesn't exist or has no IsAuthorized — try next
            }
        }

        return null; // no suitable class found on this Windows build
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
        // %SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\ is the OS-maintained
        // canonical store of every active policy. No WMI required.
        var policies = new List<PolicyInstance>();
        string dir = Path.Combine(Environment.SystemDirectory, "CodeIntegrity", "CiPolicies", "Active");

        IEnumerable<string> files;
        try
        {
            if (!Directory.Exists(dir)) return policies;
            files = Directory.GetFiles(dir); // GetFiles buffers upfront; safer than lazy Enumerate
        }
        catch
        {
            return policies;
        }

        foreach (var file in files)
        {
            try
            {
                byte[] bytes = File.ReadAllBytes(file);
                string? id = PolicyGuidResolver.TryExtractGuidFromFilename(file)
                             ?? PolicyGuidResolver.TryExtractGuidFromBinary(bytes);
                if (id is not null)
                    policies.Add(new PolicyInstance(id, Convert.ToBase64String(bytes)));
            }
            catch { /* skip unreadable files */ }
        }

        return policies;
    }

    public PolicyInfoResult GetPolicyInfo(string policyGuid)
    {
        // Primary: WMI PolicyInfo class with SYSTEM impersonation.
        // Works on MDM-enrolled devices where the MDM WMI bridge classes exist.
        try
        {
            using var impersonation = NativeSystem.IsSystem() ? null : NativeSystem.ImpersonateSystem();
            using var session = CreateSession();
            string? infoClass = ResolveInfoClass(session);
            if (infoClass is not null)
            {
                var instance = FindInstance(session, infoClass, policyGuid);
                if (instance is not null)
                {
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
                        PolicyOptions: Prop(instance, "PolicyOptions"),
                        IsSignedPolicy: Prop(instance, "IsSignedPolicy"));
                    instance.Dispose();
                    return result;
                }
            }
        }
        catch { }

        // Fallback: parse what we can directly from the policy binary.
        // Works on any device regardless of MDM enrolment.
        return ParseBinaryInfo(policyGuid);
    }

    /// <summary>
    /// Locates the .cip file for <paramref name="policyGuid"/> in the Active store
    /// and extracts every field encoded in the compiled binary.
    ///
    /// Signed policies are PKCS#7/CMS wrapped (first byte == 0x30).
    /// We unwrap them with <see cref="SignedCms"/> to reach the inner binary and
    /// then parse the same header layout as unsigned policies.
    ///
    /// Unsigned .cip header layout (all little-endian):
    ///   [0x00] uint32  version identifier (currently 8)
    ///   [0x04] GUID    PolicyTypeId  (= BasePolicyId at compile time)
    ///   [0x14] GUID    PlatformId    (zero for most policies)
    ///   [0x24] uint32  option flags  (bit 30 = supplemental; bits 0-20 = rule options)
    ///   [0x38] uint32  version low   (Build &lt;&lt; 16 | Revision)
    ///   [0x3C] uint32  version high  (Major &lt;&lt; 16 | Minor)
    ///
    /// Note: FriendlyName is XML-only and is NOT stored in the compiled binary.
    /// </summary>
    private static PolicyInfoResult ParseBinaryInfo(string policyGuid)
    {
        string dir = Path.Combine(Environment.SystemDirectory, "CodeIntegrity", "CiPolicies", "Active");
        if (!Directory.Exists(dir))
            return new PolicyInfoResult(IsDeployed: "True");

        try
        {
            foreach (var file in Directory.GetFiles(dir))
            {
                try
                {
                    byte[] bytes = File.ReadAllBytes(file);
                    string? id = PolicyGuidResolver.TryExtractGuidFromFilename(file)
                                 ?? PolicyGuidResolver.TryExtractGuidFromBinary(bytes);
                    if (id != policyGuid) continue;

                    // Signed: PKCS#7 envelope — first byte is ASN.1 SEQUENCE tag 0x30.
                    // Unwrap to reach the inner unsigned binary, then parse normally.
                    bool isSigned = bytes.Length > 0 && bytes[0] == 0x30;
                    if (isSigned)
                    {
                        try
                        {
                            var cms = new SignedCms();
                            cms.Decode(bytes);
                            bytes = cms.ContentInfo.Content;
                        }
                        catch
                        {
                            // Can't unwrap — return what little we know
                            return new PolicyInfoResult(IsDeployed: "True", IsSignedPolicy: "True");
                        }
                    }

                    return ParseUnsignedHeader(bytes, isSigned ? "True" : "False");
                }
                catch { /* skip unreadable file */ }
            }
        }
        catch { }

        return new PolicyInfoResult(IsDeployed: "True");
    }

    /// <summary>Parses the fixed-size header of an unsigned .cip binary.</summary>
    private static PolicyInfoResult ParseUnsignedHeader(byte[] bytes, string isSignedPolicy)
    {
        // BasePolicyId = PolicyTypeId at offset 0x04 (16 bytes)
        string basePolicyId = "-";
        if (bytes.Length >= 0x14)
        {
            try
            {
                var policyTypeId = new Guid(bytes.AsSpan(0x04, 16));
                if (policyTypeId != Guid.Empty)
                    basePolicyId = $"{{{policyTypeId:D}}}";
            }
            catch { }
        }

        // Option flags at 0x24:  bit 30 = supplemental, bits 0-20 = rule options
        string isBasePolicy  = "-";
        string policyOptions = "-";
        if (bytes.Length >= 0x28)
        {
            uint flags  = BitConverter.ToUInt32(bytes, 0x24);
            isBasePolicy  = (flags & 0x40000000u) != 0 ? "False" : "True";
            policyOptions = DecodeOptionFlags(flags);
        }

        // Version: two uint32 words at 0x38 (low) and 0x3C (high)
        //   vLow  = (Build << 16) | Revision
        //   vHigh = (Major << 16) | Minor
        string version = "-";
        if (bytes.Length >= 0x40)
        {
            try
            {
                uint vLow  = BitConverter.ToUInt32(bytes, 0x38);
                uint vHigh = BitConverter.ToUInt32(bytes, 0x3C);
                ushort revision = (ushort)(vLow  & 0xFFFF);
                ushort build    = (ushort)(vLow  >> 16);
                ushort minor    = (ushort)(vHigh & 0xFFFF);
                ushort major    = (ushort)(vHigh >> 16);
                version = $"{major}.{minor}.{build}.{revision}";
            }
            catch { }
        }

        return new PolicyInfoResult(
            IsDeployed:    "True",
            IsBasePolicy:  isBasePolicy,
            BasePolicyId:  basePolicyId,
            Version:       version,
            IsSignedPolicy: isSignedPolicy,
            PolicyOptions: policyOptions);
    }

    // Option rule names indexed by bit position (WDAC policy rule option numbers).
    // Source: Microsoft WDAC documentation + BinaryOpsForward.cs (HotCakeX/Harden-Windows-Security)
    private static readonly string?[] s_optionNames =
    [
        "Enabled:UMCI",                                    // bit  0
        "Enabled:Boot Menu Protection",                    // bit  1
        "Required:WHQL",                                   // bit  2
        "Enabled:Audit Mode",                              // bit  3
        "Disabled:Flight Signing",                         // bit  4
        "Enabled:Inherit Default Policy",                  // bit  5
        "Enabled:Unsigned System Integrity Policy",        // bit  6
        "Allowed:Debug Policy Augmented",                  // bit  7
        "Required:EV Signers",                             // bit  8
        "Enabled:Advanced Boot Options Menu",              // bit  9
        "Enabled:Boot Audit on Failure",                   // bit 10
        "Disabled:Script Enforcement",                     // bit 11
        "Required:Enforce Store Applications",             // bit 12
        "Enabled:Managed Installer",                       // bit 13
        "Enabled:Intelligent Security Graph Authorization",// bit 14
        "Enabled:Invalidate EAs on Reboot",               // bit 15
        "Enabled:Update Policy No Reboot",                 // bit 16
        "Enabled:Allow Supplemental Policies",             // bit 17
        "Disabled:Runtime FilePath Rule Protection",       // bit 18
        "Enabled:Dynamic Code Security",                   // bit 19
        "Enabled:Revoked Expired As Unsigned",             // bit 20
    ];

    private static string DecodeOptionFlags(uint flags)
    {
        var opts = new List<string>();
        for (int i = 0; i < s_optionNames.Length; i++)
        {
            if ((flags & (1u << i)) != 0 && s_optionNames[i] is { } name)
                opts.Add(name);
        }
        return opts.Count > 0 ? string.Join(", ", opts) : "-";
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
