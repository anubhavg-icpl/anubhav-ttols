using anubhav_ttols;

namespace anubhav_ttols.Tests;

/// <summary>
/// Tests covering all ApplicationControl CSP use cases from Microsoft docs:
/// - All 8 IsAuthorized/IsDeployed/IsEffective state combinations
/// - Signed policy deletion flow
/// - GUID enforcement (URI GUID must match blob GUID)
/// - PolicyInfo field coverage (all 10 fields)
/// - Policy version as uint64 string
/// - Status code = 0 means OK
/// - Base64 format for Policy node (b64 access type)
/// - Multiple policy coexistence
/// - Rebootless operations
/// </summary>
public class CspUseCaseTests : IDisposable
{
    private readonly MockWmiProvider _wmi = new();
    private readonly PolicyManager _manager;
    private readonly string _tempDir;

    public CspUseCaseTests()
    {
        _manager = new PolicyManager(_wmi);
        _tempDir = Path.Combine(Path.GetTempPath(), $"csp-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private string CreatePolicyFile(Guid guid, string? name = null, int size = 64)
    {
        byte[] binary = new byte[size];
        binary[0] = 0x01;
        guid.TryWriteBytes(binary.AsSpan(4));
        string path = Path.Combine(_tempDir, name ?? $"{{{guid}}}.cip");
        File.WriteAllBytes(path, binary);
        return path;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  CSP State Table: All 8 combinations from docs
    //  IsAuthorized | IsDeployed | IsEffective | Resultant
    // ══════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("True", "True", "True", "Running and in effect")]
    [InlineData("True", "True", "False", "Needs reboot to take effect")]
    [InlineData("True", "False", "True", "Needs reboot to unload from CI")]
    [InlineData("False", "True", "True", "Not reachable")]
    [InlineData("True", "False", "False", "Intermediary state")]
    [InlineData("False", "True", "False", "Intermediary state")]
    [InlineData("False", "False", "True", "Not reachable")]
    [InlineData("False", "False", "False", "Intermediary state")]
    public void StateTable_AllEightCombinations(
        string isAuthorized, string isDeployed, string isEffective, string description)
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(
            IsAuthorized: isAuthorized,
            IsDeployed: isDeployed,
            IsEffective: isEffective);

        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        var (exitCode, results) = _manager.List();
        Assert.Equal(0, exitCode);
        Assert.Single(results);

        var info = results[0].Info;
        Assert.Equal(isAuthorized, info.IsAuthorized);
        Assert.Equal(isDeployed, info.IsDeployed);
        Assert.Equal(isEffective, info.IsEffective);
        Assert.NotEmpty(description);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Signed Policy Deletion Flow (per CSP docs):
    //  1. Replace with signed update allowing unsigned policy
    //  2. Deploy unsigned AllowAll policy
    //  3. Perform DELETE
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void SignedPolicyDeletion_ThreeStepFlow()
    {
        var guid = Guid.Parse("51900001-aaaa-bbbb-cccc-dddddddddddd");

        // Step 0: Deploy original signed policy
        string signedFile = CreatePolicyFile(guid, "signed-policy.bin");
        _manager.Apply(signedFile, guid.ToString("D"));
        Assert.Single(_wmi.DeployedPolicies);

        // Step 1: Replace with signed update allowing unsigned
        byte[] signedUnsignedAllow = new byte[96];
        signedUnsignedAllow[0] = 0xBB;
        guid.TryWriteBytes(signedUnsignedAllow.AsSpan(4));
        string step1File = Path.Combine(_tempDir, "signed-allow-unsigned.bin");
        File.WriteAllBytes(step1File, signedUnsignedAllow);
        _manager.Apply(step1File, guid.ToString("D"));

        var (_, afterStep1) = _manager.List();
        Assert.Single(afterStep1);
        byte[] step1Data = Convert.FromBase64String(afterStep1[0].Policy.PolicyBase64);
        Assert.Equal(0xBB, step1Data[0]);

        // Step 2: Deploy unsigned AllowAll policy (same GUID, replace)
        byte[] allowAll = new byte[80];
        allowAll[0] = 0xCC;
        guid.TryWriteBytes(allowAll.AsSpan(4));
        string step2File = Path.Combine(_tempDir, "unsigned-allowall.bin");
        File.WriteAllBytes(step2File, allowAll);
        _manager.Apply(step2File, guid.ToString("D"));

        var (_, afterStep2) = _manager.List();
        Assert.Single(afterStep2);
        byte[] step2Data = Convert.FromBase64String(afterStep2[0].Policy.PolicyBase64);
        Assert.Equal(0xCC, step2Data[0]);

        // Step 3: DELETE
        _manager.Remove(guid.ToString("D"));
        var (_, afterDelete) = _manager.List();
        Assert.Empty(afterDelete);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  GUID Enforcement: CSP enforces URI GUID matches blob GUID
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void GuidEnforcement_OverrideGuidUsedAsInstanceId()
    {
        // The CSP enforces that the "ID" segment of a given policy URI
        // is the same GUID as the policy ID in the policy blob.
        // Our tool uses --guid override which becomes the InstanceID.
        var blobGuid = Guid.Parse("ab0b0001-1111-2222-3333-444444444444");
        var overrideGuid = "ab0b0002-1111-2222-3333-444444444444";

        string file = CreatePolicyFile(blobGuid, "policy.bin");
        _manager.Apply(file, overrideGuid);

        // The deploy call should use the override GUID as InstanceID
        Assert.Single(_wmi.DeployCalls);
        Assert.Equal(overrideGuid, _wmi.DeployCalls[0]);
    }

    [Fact]
    public void GuidEnforcement_BinaryGuidUsedWhenNoOverride()
    {
        var blobGuid = Guid.Parse("ab0b0003-1111-2222-3333-444444444444");
        string file = CreatePolicyFile(blobGuid, "some-policy.bin");

        _manager.Apply(file);

        Assert.Single(_wmi.DeployCalls);
        Assert.Equal(blobGuid.ToString("D"), _wmi.DeployCalls[0]);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  PolicyInfo: All 10 fields from CSP docs
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void PolicyInfo_AllFieldsPopulated()
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(
            IsAuthorized: "True",
            IsDeployed: "True",
            IsEffective: "True",
            IsBasePolicy: "True",
            IsSystemPolicy: "False",
            Status: "0",
            Version: "2814750396416",  // uint64 representation
            FriendlyName: "Contoso Base Policy",
            BasePolicyId: "ab0b0004-1111-2222-3333-444444444444",
            PolicyOptions: "Enabled:Unsigned System Integrity Policy");

        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        var (_, results) = _manager.List();
        var info = results[0].Info;

        Assert.Equal("True", info.IsAuthorized);
        Assert.Equal("True", info.IsDeployed);
        Assert.Equal("True", info.IsEffective);
        Assert.Equal("True", info.IsBasePolicy);
        Assert.Equal("False", info.IsSystemPolicy);
        Assert.Equal("0", info.Status);
        Assert.Equal("2814750396416", info.Version);
        Assert.Equal("Contoso Base Policy", info.FriendlyName);
        Assert.Equal("ab0b0004-1111-2222-3333-444444444444", info.BasePolicyId);
        Assert.Equal("Enabled:Unsigned System Integrity Policy", info.PolicyOptions);
    }

    [Fact]
    public void PolicyInfo_DefaultValues_WhenNotAvailable()
    {
        // When CSP can't return a field, default should be "-"
        var info = new PolicyInfoResult();
        Assert.Equal("-", info.IsAuthorized);
        Assert.Equal("-", info.IsDeployed);
        Assert.Equal("-", info.IsEffective);
        Assert.Equal("-", info.IsBasePolicy);
        Assert.Equal("-", info.IsSystemPolicy);
        Assert.Equal("-", info.Status);
        Assert.Equal("-", info.Version);
        Assert.Equal("-", info.FriendlyName);
        Assert.Equal("-", info.BasePolicyId);
        Assert.Equal("-", info.PolicyOptions);
    }

    [Fact]
    public void PolicyInfo_StatusZero_MeansOk()
    {
        // Per docs: "Default value is 0, which indicates policy status is OK"
        _wmi.CustomPolicyInfo = new PolicyInfoResult(Status: "0");

        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        var (_, results) = _manager.List();
        Assert.Equal("0", results[0].Info.Status);
    }

    [Fact]
    public void PolicyInfo_VersionAsUint64String()
    {
        // Per docs: "When parsing use a uint64 as the containing data type"
        _wmi.CustomPolicyInfo = new PolicyInfoResult(Version: "281475043819520");

        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        var (_, results) = _manager.List();
        string version = results[0].Info.Version;
        Assert.True(ulong.TryParse(version, out ulong parsed));
        Assert.Equal(281475043819520UL, parsed);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Base64 Format: Policy node uses b64 access type
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void Base64Format_PolicyBinaryRoundTrips()
    {
        var guid = Guid.NewGuid();
        string file = CreatePolicyFile(guid, size: 256);
        byte[] original = File.ReadAllBytes(file);

        _manager.Apply(file);

        string base64 = _wmi.DeployedPolicies[guid.ToString("D")];
        byte[] decoded = Convert.FromBase64String(base64);
        Assert.Equal(original.Length, decoded.Length);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Base64Format_ValidBase64String()
    {
        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        string base64 = _wmi.DeployedPolicies[guid.ToString("D")];

        // Must be valid base64 (no exceptions on decode)
        byte[] decoded = Convert.FromBase64String(base64);
        Assert.NotEmpty(decoded);

        // Re-encode should match
        Assert.Equal(base64, Convert.ToBase64String(decoded));
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Multiple Policy Coexistence (per CSP docs examples)
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void MultiplePolicy_TwoBaseOneSupplemental()
    {
        // CSP docs Example 1+2+3: two base policies + one supplemental
        var base1 = Guid.NewGuid();
        var base2 = Guid.NewGuid();
        var supp1 = Guid.NewGuid();

        Assert.Equal(0, _manager.Apply(CreatePolicyFile(base1)));
        Assert.Equal(0, _manager.Apply(CreatePolicyFile(base2)));
        Assert.Equal(0, _manager.Apply(CreatePolicyFile(supp1)));

        var (_, results) = _manager.List();
        Assert.Equal(3, results.Count);

        // Each has unique InstanceId
        var ids = results.Select(r => r.Policy.InstanceId).ToList();
        Assert.Equal(3, ids.Distinct().Count());
    }

    [Fact]
    public void MultiplePolicy_RemoveOneKeepsOthers()
    {
        var g1 = Guid.NewGuid();
        var g2 = Guid.NewGuid();
        var g3 = Guid.NewGuid();

        _manager.Apply(CreatePolicyFile(g1));
        _manager.Apply(CreatePolicyFile(g2));
        _manager.Apply(CreatePolicyFile(g3));

        _manager.Remove(g2.ToString("D"));

        var (_, results) = _manager.List();
        Assert.Equal(2, results.Count);
        Assert.DoesNotContain(results, r => r.Policy.InstanceId == g2.ToString("D"));
    }

    // ══════════════════════════════════════════════════════════════════════
    //  WMI Bridge: Namespace and class name validation
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void WmiBridge_CorrectNamespace()
    {
        Assert.Equal(@"root\cimv2\mdm\dmmap", WmiProvider.Namespace);
    }

    [Fact]
    public void WmiBridge_CorrectClassName()
    {
        Assert.Equal("MDM_ApplicationControl_Policies01_01", WmiProvider.ClassName);
    }

    [Fact]
    public void WmiBridge_CorrectParentId()
    {
        Assert.Equal("./Vendor/MSFT/ApplicationControl/Policies", WmiProvider.ParentId);
    }

    [Fact]
    public void WmiBridge_CorrectInfoClassName()
    {
        Assert.Equal("MDM_ApplicationControl_Policies01_01_PolicyInfo01", WmiProvider.InfoClassName);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Rebootless operations: CSP supports no-reboot deployment
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void Rebootless_DeployDoesNotRequireReboot()
    {
        // ApplicationControl CSP detects no-reboot option
        // and doesn't schedule a reboot (unlike AppLocker CSP)
        var guid = Guid.NewGuid();
        int result = _manager.Apply(CreatePolicyFile(guid));

        // Deploy succeeds without any reboot mechanism
        Assert.Equal(0, result);
        Assert.Single(_wmi.DeployedPolicies);
    }

    [Fact]
    public void Rebootless_ReplaceDoesNotRequireReboot()
    {
        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        // Replace with new data
        byte[] newData = new byte[100];
        newData[0] = 0xDD;
        guid.TryWriteBytes(newData.AsSpan(4));
        string replaceFile = Path.Combine(_tempDir, "replace.bin");
        File.WriteAllBytes(replaceFile, newData);

        int result = _manager.Apply(replaceFile, guid.ToString("D"));
        Assert.Equal(0, result);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  IsBasePolicy vs Supplemental
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void PolicyType_BasePolicy()
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(IsBasePolicy: "True");
        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        var (_, results) = _manager.List();
        Assert.Equal("True", results[0].Info.IsBasePolicy);
    }

    [Fact]
    public void PolicyType_SupplementalPolicy()
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(IsBasePolicy: "False");
        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        var (_, results) = _manager.List();
        Assert.Equal("False", results[0].Info.IsBasePolicy);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  IsSystemPolicy: managed by Microsoft as part of OS
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void SystemPolicy_IdentifiedCorrectly()
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(IsSystemPolicy: "True");
        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        var (_, results) = _manager.List();
        Assert.Equal("True", results[0].Info.IsSystemPolicy);
    }

    [Fact]
    public void NonSystemPolicy_IdentifiedCorrectly()
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(IsSystemPolicy: "False");
        var guid = Guid.NewGuid();
        _manager.Apply(CreatePolicyFile(guid));

        var (_, results) = _manager.List();
        Assert.Equal("False", results[0].Info.IsSystemPolicy);
    }
}
