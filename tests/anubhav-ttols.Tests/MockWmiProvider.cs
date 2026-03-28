using anubhav_ttols;

namespace anubhav_ttols.Tests;

public class MockWmiProvider : IWmiProvider
{
    public Dictionary<string, string> DeployedPolicies { get; } = new();
    public List<string> DeployCalls { get; } = new();
    public List<string> DeleteCalls { get; } = new();
    public int GetAllPoliciesCalls { get; private set; }
    public int GetPolicyInfoCalls { get; set; }

    public bool ThrowOnDeploy { get; set; }
    public bool ThrowNotFoundOnDelete { get; set; }
    public bool ThrowOnDelete { get; set; }

    public PolicyInfoResult? CustomPolicyInfo { get; set; }

    public void DeployPolicy(string policyGuid, string policyBase64)
    {
        DeployCalls.Add(policyGuid);
        if (ThrowOnDeploy)
            throw new InvalidOperationException("Access denied");

        DeployedPolicies[policyGuid] = policyBase64;
    }

    public void DeletePolicy(string policyGuid)
    {
        DeleteCalls.Add(policyGuid);
        if (ThrowNotFoundOnDelete)
            throw new InvalidOperationException("Not found");
        if (ThrowOnDelete)
            throw new InvalidOperationException("Generic WMI error");

        if (!DeployedPolicies.Remove(policyGuid))
            throw new InvalidOperationException("Not found");
    }

    public List<PolicyInstance> GetAllPolicies()
    {
        GetAllPoliciesCalls++;
        return DeployedPolicies
            .Select(kv => new PolicyInstance(kv.Key, kv.Value))
            .ToList();
    }

    public PolicyInfoResult GetPolicyInfo(string policyGuid)
    {
        GetPolicyInfoCalls++;
        if (CustomPolicyInfo is not null)
            return CustomPolicyInfo;

        if (DeployedPolicies.ContainsKey(policyGuid))
        {
            return new PolicyInfoResult(
                IsAuthorized: "True",
                IsDeployed: "True",
                IsEffective: "True",
                IsBasePolicy: "True",
                IsSystemPolicy: "False",
                Status: "0",
                Version: "1.0.0.0",
                FriendlyName: "TestPolicy",
                BasePolicyId: policyGuid,
                PolicyOptions: "0");
        }

        return new PolicyInfoResult();
    }
}
