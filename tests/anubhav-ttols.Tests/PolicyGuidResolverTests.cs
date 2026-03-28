using anubhav_ttols;

namespace anubhav_ttols.Tests;

public class PolicyGuidResolverTests
{
    // ── TryExtractGuidFromFilename ──────────────────────────────────────

    [Fact]
    public void ExtractGuid_FromFilename_StandardCipConvention()
    {
        // Standard WDAC output: {GUID}.cip
        string path = @"C:\policies\{a1b2c3d4-e5f6-7890-abcd-ef1234567890}.cip";
        var result = PolicyGuidResolver.TryExtractGuidFromFilename(path);
        Assert.Equal("a1b2c3d4-e5f6-7890-abcd-ef1234567890", result);
    }

    [Fact]
    public void ExtractGuid_FromFilename_NoBraces()
    {
        string path = @"C:\policies\a1b2c3d4-e5f6-7890-abcd-ef1234567890.cip";
        var result = PolicyGuidResolver.TryExtractGuidFromFilename(path);
        Assert.Equal("a1b2c3d4-e5f6-7890-abcd-ef1234567890", result);
    }

    [Fact]
    public void ExtractGuid_FromFilename_BinExtension()
    {
        string path = @"C:\policies\a1b2c3d4-e5f6-7890-abcd-ef1234567890.bin";
        var result = PolicyGuidResolver.TryExtractGuidFromFilename(path);
        Assert.Equal("a1b2c3d4-e5f6-7890-abcd-ef1234567890", result);
    }

    [Fact]
    public void ExtractGuid_FromFilename_NonGuidName_ReturnsNull()
    {
        string path = @"C:\policies\MyPolicy.cip";
        var result = PolicyGuidResolver.TryExtractGuidFromFilename(path);
        Assert.Null(result);
    }

    [Fact]
    public void ExtractGuid_FromFilename_EmptyGuid_ReturnsNull()
    {
        string path = @"C:\policies\{00000000-0000-0000-0000-000000000000}.cip";
        var result = PolicyGuidResolver.TryExtractGuidFromFilename(path);
        Assert.Null(result);
    }

    // ── TryExtractGuidFromBinary ────────────────────────────────────────

    [Fact]
    public void ExtractGuid_FromBinary_ValidGuidAtOffset4()
    {
        var guid = Guid.Parse("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        byte[] binary = new byte[64];
        guid.TryWriteBytes(binary.AsSpan(4));

        var result = PolicyGuidResolver.TryExtractGuidFromBinary(binary);
        Assert.Equal("a1b2c3d4-e5f6-7890-abcd-ef1234567890", result);
    }

    [Fact]
    public void ExtractGuid_FromBinary_TooShort_ReturnsNull()
    {
        byte[] binary = new byte[10]; // less than 20 bytes
        var result = PolicyGuidResolver.TryExtractGuidFromBinary(binary);
        Assert.Null(result);
    }

    [Fact]
    public void ExtractGuid_FromBinary_AllZeros_ReturnsNull()
    {
        byte[] binary = new byte[64]; // all zeros = Guid.Empty
        var result = PolicyGuidResolver.TryExtractGuidFromBinary(binary);
        Assert.Null(result);
    }

    [Fact]
    public void ExtractGuid_FromBinary_ExactlyMinimumSize()
    {
        var guid = Guid.Parse("deadbeef-1234-5678-9abc-def012345678");
        byte[] binary = new byte[20]; // exactly minimum
        guid.TryWriteBytes(binary.AsSpan(4));

        var result = PolicyGuidResolver.TryExtractGuidFromBinary(binary);
        Assert.Equal("deadbeef-1234-5678-9abc-def012345678", result);
    }

    // ── NormalizeGuid ───────────────────────────────────────────────────

    [Fact]
    public void NormalizeGuid_WithBraces()
    {
        var result = PolicyGuidResolver.NormalizeGuid("{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}");
        Assert.Equal("a1b2c3d4-e5f6-7890-abcd-ef1234567890", result);
    }

    [Fact]
    public void NormalizeGuid_WithoutBraces()
    {
        var result = PolicyGuidResolver.NormalizeGuid("A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
        Assert.Equal("a1b2c3d4-e5f6-7890-abcd-ef1234567890", result);
    }

    [Fact]
    public void NormalizeGuid_AlreadyLowercase()
    {
        var result = PolicyGuidResolver.NormalizeGuid("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        Assert.Equal("a1b2c3d4-e5f6-7890-abcd-ef1234567890", result);
    }

    [Fact]
    public void NormalizeGuid_InvalidGuid_ReturnsInputTrimmed()
    {
        var result = PolicyGuidResolver.NormalizeGuid("not-a-guid");
        Assert.Equal("not-a-guid", result);
    }

    // ── ResolveGuid (priority: override > binary > filename) ────────────

    [Fact]
    public void ResolveGuid_OverrideTakesPriority()
    {
        var binaryGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");
        byte[] binary = new byte[64];
        binaryGuid.TryWriteBytes(binary.AsSpan(4));

        string filePath = @"C:\22222222-2222-2222-2222-222222222222.cip";
        string overrideGuid = "33333333-3333-3333-3333-333333333333";

        var result = PolicyGuidResolver.ResolveGuid(binary, filePath, overrideGuid);
        Assert.Equal("33333333-3333-3333-3333-333333333333", result);
    }

    [Fact]
    public void ResolveGuid_BinaryFallback_WhenNoOverride()
    {
        var binaryGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");
        byte[] binary = new byte[64];
        binaryGuid.TryWriteBytes(binary.AsSpan(4));

        string filePath = @"C:\22222222-2222-2222-2222-222222222222.cip";

        var result = PolicyGuidResolver.ResolveGuid(binary, filePath, null);
        Assert.Equal("11111111-1111-1111-1111-111111111111", result);
    }

    [Fact]
    public void ResolveGuid_FilenameFallback_WhenBinaryHasNoGuid()
    {
        byte[] binary = new byte[10]; // too short for binary extraction
        string filePath = @"C:\22222222-2222-2222-2222-222222222222.cip";

        var result = PolicyGuidResolver.ResolveGuid(binary, filePath, null);
        Assert.Equal("22222222-2222-2222-2222-222222222222", result);
    }

    [Fact]
    public void ResolveGuid_ReturnsNull_WhenAllMethodsFail()
    {
        byte[] binary = new byte[10];
        string filePath = @"C:\MyPolicy.bin";

        var result = PolicyGuidResolver.ResolveGuid(binary, filePath, null);
        Assert.Null(result);
    }
}
