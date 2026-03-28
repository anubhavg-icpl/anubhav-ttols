using anubhav_ttols;

namespace anubhav_ttols.Tests;

public class PolicyManagerTests : IDisposable
{
    private readonly MockWmiProvider _wmi = new();
    private readonly PolicyManager _manager;
    private readonly string _tempDir;

    public PolicyManagerTests()
    {
        _manager = new PolicyManager(_wmi);
        _tempDir = Path.Combine(Path.GetTempPath(), $"anubhav-ttols-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private string CreateTestPolicyFile(Guid policyGuid, string? fileName = null)
    {
        // Build a minimal binary with the GUID at offset 4
        byte[] binary = new byte[64];
        // First 4 bytes: dummy header
        binary[0] = 0x01;
        binary[1] = 0x00;
        binary[2] = 0x00;
        binary[3] = 0x00;
        policyGuid.TryWriteBytes(binary.AsSpan(4));

        string path = Path.Combine(_tempDir, fileName ?? $"{{{policyGuid}}}.cip");
        File.WriteAllBytes(path, binary);
        return path;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  APPLY: Deploy policies (CSP ADD operation)
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void Apply_DeploysPolicy_GuidFromBinaryHeader()
    {
        var guid = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        string file = CreateTestPolicyFile(guid, "policy.bin");

        int result = _manager.Apply(file);

        Assert.Equal(0, result);
        Assert.Single(_wmi.DeployedPolicies);
        Assert.True(_wmi.DeployedPolicies.ContainsKey(guid.ToString("D")));
        Assert.Single(_wmi.DeployCalls);
    }

    [Fact]
    public void Apply_DeploysPolicy_GuidFromFilename()
    {
        var guid = Guid.Parse("12345678-1234-1234-1234-123456789abc");
        // Binary has no valid GUID (too short content at offset 4 = zeros = Empty)
        byte[] binary = new byte[64]; // all zeros => Guid.Empty at offset 4
        string file = Path.Combine(_tempDir, $"{{{guid}}}.cip");
        File.WriteAllBytes(file, binary);

        int result = _manager.Apply(file);

        Assert.Equal(0, result);
        Assert.True(_wmi.DeployedPolicies.ContainsKey(guid.ToString("D")));
    }

    [Fact]
    public void Apply_DeploysPolicy_WithGuidOverride()
    {
        var binaryGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var overrideGuid = "22222222-2222-2222-2222-222222222222";
        string file = CreateTestPolicyFile(binaryGuid);

        int result = _manager.Apply(file, overrideGuid);

        Assert.Equal(0, result);
        Assert.True(_wmi.DeployedPolicies.ContainsKey(overrideGuid));
        Assert.False(_wmi.DeployedPolicies.ContainsKey(binaryGuid.ToString("D")));
    }

    [Fact]
    public void Apply_PolicyDataIsBase64Encoded()
    {
        var guid = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        string file = CreateTestPolicyFile(guid);
        byte[] originalBytes = File.ReadAllBytes(file);

        _manager.Apply(file);

        string storedBase64 = _wmi.DeployedPolicies[guid.ToString("D")];
        byte[] decoded = Convert.FromBase64String(storedBase64);
        Assert.Equal(originalBytes, decoded);
    }

    [Fact]
    public void Apply_FileNotFound_Returns1()
    {
        int result = _manager.Apply(@"C:\nonexistent\policy.cip");
        Assert.Equal(1, result);
        Assert.Empty(_wmi.DeployCalls);
    }

    [Fact]
    public void Apply_NoGuidResolvable_Returns1()
    {
        // File exists but name is not a GUID and binary is too short
        string file = Path.Combine(_tempDir, "mypolicy.bin");
        File.WriteAllBytes(file, new byte[10]);

        int result = _manager.Apply(file);

        Assert.Equal(1, result);
        Assert.Empty(_wmi.DeployCalls);
    }

    [Fact]
    public void Apply_MultipleBasePolicies()
    {
        // Per CSP docs: deploy base policy 1, then base policy 2
        var guid1 = Guid.Parse("aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee");
        var guid2 = Guid.Parse("aaaa2222-bbbb-cccc-dddd-eeeeeeeeeeee");

        string file1 = CreateTestPolicyFile(guid1);
        string file2 = CreateTestPolicyFile(guid2);

        Assert.Equal(0, _manager.Apply(file1));
        Assert.Equal(0, _manager.Apply(file2));

        Assert.Equal(2, _wmi.DeployedPolicies.Count);
        Assert.True(_wmi.DeployedPolicies.ContainsKey(guid1.ToString("D")));
        Assert.True(_wmi.DeployedPolicies.ContainsKey(guid2.ToString("D")));
    }

    [Fact]
    public void Apply_SupplementalPolicy_DeploysIndependently()
    {
        // Per CSP docs: supplemental policy already specifies its base
        // and deploys the same way via ADD
        var baseGuid = Guid.Parse("bbbb1111-cccc-dddd-eeee-ffffffffffff");
        var suppGuid = Guid.Parse("bbbb2222-cccc-dddd-eeee-ffffffffffff");

        string baseFile = CreateTestPolicyFile(baseGuid);
        string suppFile = CreateTestPolicyFile(suppGuid);

        Assert.Equal(0, _manager.Apply(baseFile));
        Assert.Equal(0, _manager.Apply(suppFile));

        Assert.Equal(2, _wmi.DeployedPolicies.Count);
    }

    [Fact]
    public void Apply_ReplaceExistingPolicy_Overwrites()
    {
        // CSP supports Replace on the Policy node
        var guid = Guid.Parse("cccc1111-dddd-eeee-ffff-aaaaaaaaaaaa");
        string file1 = CreateTestPolicyFile(guid, $"{{{guid}}}.cip");

        _manager.Apply(file1);
        string firstBase64 = _wmi.DeployedPolicies[guid.ToString("D")];

        // Create a different binary with same GUID
        byte[] binary2 = new byte[128];
        binary2[0] = 0xFF;
        guid.TryWriteBytes(binary2.AsSpan(4));
        string file2 = Path.Combine(_tempDir, $"{{{guid}}}-v2.bin");
        File.WriteAllBytes(file2, binary2);

        _manager.Apply(file2, guid.ToString("D"));
        string secondBase64 = _wmi.DeployedPolicies[guid.ToString("D")];

        Assert.NotEqual(firstBase64, secondBase64);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  REMOVE: Delete policies (CSP DELETE operation)
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void Remove_DeletesDeployedPolicy()
    {
        var guid = Guid.Parse("dddd1111-eeee-ffff-aaaa-bbbbbbbbbbbb");
        string file = CreateTestPolicyFile(guid);
        _manager.Apply(file);

        Assert.Single(_wmi.DeployedPolicies);

        int result = _manager.Remove(guid.ToString("D"));

        Assert.Equal(0, result);
        Assert.Empty(_wmi.DeployedPolicies);
    }

    [Fact]
    public void Remove_AcceptsBracedGuid()
    {
        var guid = Guid.Parse("dddd2222-eeee-ffff-aaaa-bbbbbbbbbbbb");
        string file = CreateTestPolicyFile(guid);
        _manager.Apply(file);

        int result = _manager.Remove($"{{{guid}}}");

        Assert.Equal(0, result);
        Assert.Empty(_wmi.DeployedPolicies);
    }

    [Fact]
    public void Remove_AcceptsUppercaseGuid()
    {
        var guid = Guid.Parse("dddd3333-eeee-ffff-aaaa-bbbbbbbbbbbb");
        string file = CreateTestPolicyFile(guid);
        _manager.Apply(file);

        int result = _manager.Remove(guid.ToString("D").ToUpperInvariant());

        Assert.Equal(0, result);
        Assert.Empty(_wmi.DeployedPolicies);
    }

    [Fact]
    public void Remove_NonExistentPolicy_Throws()
    {
        _wmi.ThrowNotFoundOnDelete = true;
        Assert.ThrowsAny<Exception>(() =>
            _manager.Remove("eeee1111-ffff-aaaa-bbbb-cccccccccccc"));
    }

    // ══════════════════════════════════════════════════════════════════════
    //  LIST: Query all policies (CSP GET operation)
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void List_EmptyWhenNoPolicies()
    {
        var (exitCode, results) = _manager.List();

        Assert.Equal(0, exitCode);
        Assert.Empty(results);
    }

    [Fact]
    public void List_ReturnsAllDeployedPolicies()
    {
        var guid1 = Guid.Parse("ffff1111-aaaa-bbbb-cccc-dddddddddddd");
        var guid2 = Guid.Parse("ffff2222-aaaa-bbbb-cccc-dddddddddddd");

        _manager.Apply(CreateTestPolicyFile(guid1));
        _manager.Apply(CreateTestPolicyFile(guid2));

        var (exitCode, results) = _manager.List();

        Assert.Equal(0, exitCode);
        Assert.Equal(2, results.Count);
        Assert.Contains(results, r => r.Policy.InstanceId == guid1.ToString("D"));
        Assert.Contains(results, r => r.Policy.InstanceId == guid2.ToString("D"));
    }

    [Fact]
    public void List_IncludesPolicyInfoFields()
    {
        // Per CSP docs: IsAuthorized, IsDeployed, IsEffective, Status, Version, etc.
        var guid = Guid.Parse("ffff3333-aaaa-bbbb-cccc-dddddddddddd");
        _manager.Apply(CreateTestPolicyFile(guid));

        var (_, results) = _manager.List();

        Assert.Single(results);
        var info = results[0].Info;
        Assert.Equal("True", info.IsAuthorized);
        Assert.Equal("True", info.IsDeployed);
        Assert.Equal("True", info.IsEffective);
        Assert.Equal("True", info.IsBasePolicy);
        Assert.Equal("False", info.IsSystemPolicy);
        Assert.Equal("0", info.Status);
        Assert.Equal("1.0.0.0", info.Version);
        Assert.Equal("TestPolicy", info.FriendlyName);
    }

    [Fact]
    public void List_QueriesPolicyInfoForEachPolicy()
    {
        var guid1 = Guid.Parse("ffff4444-aaaa-bbbb-cccc-dddddddddddd");
        var guid2 = Guid.Parse("ffff5555-aaaa-bbbb-cccc-dddddddddddd");

        _manager.Apply(CreateTestPolicyFile(guid1));
        _manager.Apply(CreateTestPolicyFile(guid2));
        _wmi.GetPolicyInfoCalls = 0;

        _manager.List();

        Assert.Equal(2, _wmi.GetPolicyInfoCalls);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  IsAuthorized / IsDeployed / IsEffective state combinations
    //  Per CSP docs table
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void PolicyState_AuthorizedDeployedEffective_IsRunning()
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(
            IsAuthorized: "True", IsDeployed: "True", IsEffective: "True");
        var guid = Guid.Parse("abcd0001-0000-0000-0000-000000000000");
        _manager.Apply(CreateTestPolicyFile(guid));

        var (_, results) = _manager.List();
        var info = results[0].Info;

        Assert.Equal("True", info.IsAuthorized);
        Assert.Equal("True", info.IsDeployed);
        Assert.Equal("True", info.IsEffective);
    }

    [Fact]
    public void PolicyState_AuthorizedDeployedNotEffective_NeedsReboot()
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(
            IsAuthorized: "True", IsDeployed: "True", IsEffective: "False");
        var guid = Guid.Parse("abcd0002-0000-0000-0000-000000000000");
        _manager.Apply(CreateTestPolicyFile(guid));

        var (_, results) = _manager.List();
        var info = results[0].Info;

        Assert.Equal("True", info.IsAuthorized);
        Assert.Equal("True", info.IsDeployed);
        Assert.Equal("False", info.IsEffective);
    }

    [Fact]
    public void PolicyState_AuthorizedNotDeployedEffective_NeedsRebootToUnload()
    {
        _wmi.CustomPolicyInfo = new PolicyInfoResult(
            IsAuthorized: "True", IsDeployed: "False", IsEffective: "True");
        var guid = Guid.Parse("abcd0003-0000-0000-0000-000000000000");
        _manager.Apply(CreateTestPolicyFile(guid));

        var (_, results) = _manager.List();
        var info = results[0].Info;

        Assert.Equal("True", info.IsAuthorized);
        Assert.Equal("False", info.IsDeployed);
        Assert.Equal("True", info.IsEffective);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  END-TO-END: Full lifecycle (Apply → List → Remove → List)
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void EndToEnd_FullLifecycle_SinglePolicy()
    {
        var guid = Guid.Parse("e2e00001-1111-2222-3333-444444444444");
        string file = CreateTestPolicyFile(guid);

        // Step 1: Apply
        Assert.Equal(0, _manager.Apply(file));

        // Step 2: List — should show the policy
        var (_, afterApply) = _manager.List();
        Assert.Single(afterApply);
        Assert.Equal(guid.ToString("D"), afterApply[0].Policy.InstanceId);

        // Step 3: Verify base64 round-trip
        byte[] originalBytes = File.ReadAllBytes(file);
        string storedBase64 = afterApply[0].Policy.PolicyBase64;
        Assert.Equal(originalBytes, Convert.FromBase64String(storedBase64));

        // Step 4: Remove
        Assert.Equal(0, _manager.Remove(guid.ToString("D")));

        // Step 5: List — should be empty
        var (_, afterRemove) = _manager.List();
        Assert.Empty(afterRemove);
    }

    [Fact]
    public void EndToEnd_FullLifecycle_MultipleBasePolicies()
    {
        var guid1 = Guid.Parse("e2e00002-aaaa-bbbb-cccc-111111111111");
        var guid2 = Guid.Parse("e2e00003-aaaa-bbbb-cccc-222222222222");

        // Deploy two base policies
        Assert.Equal(0, _manager.Apply(CreateTestPolicyFile(guid1)));
        Assert.Equal(0, _manager.Apply(CreateTestPolicyFile(guid2)));

        // Both should be listed
        var (_, listed) = _manager.List();
        Assert.Equal(2, listed.Count);

        // Remove first, second should remain
        _manager.Remove(guid1.ToString("D"));
        var (_, afterPartialRemove) = _manager.List();
        Assert.Single(afterPartialRemove);
        Assert.Equal(guid2.ToString("D"), afterPartialRemove[0].Policy.InstanceId);

        // Remove second
        _manager.Remove(guid2.ToString("D"));
        var (_, afterFullRemove) = _manager.List();
        Assert.Empty(afterFullRemove);
    }

    [Fact]
    public void EndToEnd_BaseAndSupplementalPolicies()
    {
        var baseGuid = Guid.Parse("e2e00004-ba5e-0000-0000-000000000000");
        var suppGuid = Guid.Parse("e2e00005-5900-0000-0000-000000000000");

        // Deploy base, then supplemental
        Assert.Equal(0, _manager.Apply(CreateTestPolicyFile(baseGuid)));
        Assert.Equal(0, _manager.Apply(CreateTestPolicyFile(suppGuid)));

        var (_, listed) = _manager.List();
        Assert.Equal(2, listed.Count);

        // Remove supplemental first (good practice per docs)
        _manager.Remove(suppGuid.ToString("D"));
        var (_, afterSuppRemove) = _manager.List();
        Assert.Single(afterSuppRemove);
        Assert.Equal(baseGuid.ToString("D"), afterSuppRemove[0].Policy.InstanceId);
    }

    [Fact]
    public void EndToEnd_RebootlessDelete_ReplaceWithAllowAll_ThenDelete()
    {
        // Per CSP docs: to do rebootless delete, first replace with AllowAll,
        // then delete. We simulate this flow.
        var guid = Guid.Parse("e2e00006-1111-2222-3333-444444444444");
        string originalFile = CreateTestPolicyFile(guid);
        _manager.Apply(originalFile);

        // Step 1: Replace with "AllowAll" (different binary, same GUID)
        byte[] allowAllBytes = new byte[128];
        allowAllBytes[0] = 0xAA; // different content
        guid.TryWriteBytes(allowAllBytes.AsSpan(4));
        string allowAllFile = Path.Combine(_tempDir, "AllowAll.bin");
        File.WriteAllBytes(allowAllFile, allowAllBytes);

        _manager.Apply(allowAllFile, guid.ToString("D"));

        // Verify replacement happened (different data)
        var (_, afterReplace) = _manager.List();
        Assert.Single(afterReplace);
        byte[] replacedData = Convert.FromBase64String(afterReplace[0].Policy.PolicyBase64);
        Assert.Equal(0xAA, replacedData[0]);

        // Step 2: Delete
        _manager.Remove(guid.ToString("D"));
        var (_, afterDelete) = _manager.List();
        Assert.Empty(afterDelete);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  CLI argument parsing (via ProcessStartInfo)
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void Apply_GuidOverrideWithBracedGuid()
    {
        var guid = Guid.Parse("c11fe501-1111-2222-3333-444444444444");
        string file = CreateTestPolicyFile(Guid.NewGuid(), "random-name.bin");

        _manager.Apply(file, $"{{{guid}}}");

        Assert.True(_wmi.DeployedPolicies.ContainsKey(guid.ToString("D")));
    }

    // ══════════════════════════════════════════════════════════════════════
    //  WMI Provider contract validation
    // ══════════════════════════════════════════════════════════════════════

    [Fact]
    public void WmiProvider_DeployUsesCorrectParentIdAndInstanceId()
    {
        var guid = Guid.Parse("a0100001-1111-2222-3333-444444444444");
        string file = CreateTestPolicyFile(guid);

        _manager.Apply(file);

        Assert.Single(_wmi.DeployCalls);
        Assert.Equal(guid.ToString("D"), _wmi.DeployCalls[0]);
    }

    [Fact]
    public void WmiProvider_DeleteUsesNormalizedGuid()
    {
        var guid = Guid.Parse("a0200002-1111-2222-3333-444444444444");
        _wmi.DeployedPolicies[guid.ToString("D")] = "dummybase64";

        _manager.Remove($"{{{guid.ToString("D").ToUpperInvariant()}}}");

        Assert.Single(_wmi.DeleteCalls);
        Assert.Equal(guid.ToString("D"), _wmi.DeleteCalls[0]);
    }
}
