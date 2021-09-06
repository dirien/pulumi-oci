// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetProtectionRulesProtectionRuleResult
    {
        /// <summary>
        /// Filter rules using a list of actions.
        /// </summary>
        public readonly string Action;
        /// <summary>
        /// The description of the protection rule.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProtectionRulesProtectionRuleExclusionResult> Exclusions;
        /// <summary>
        /// The unique key of the protection rule.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// The list of labels for the protection rule.
        /// </summary>
        public readonly ImmutableArray<string> Labels;
        /// <summary>
        /// The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity's open source WAF rules, see [Mod Security's documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
        /// </summary>
        public readonly ImmutableArray<string> ModSecurityRuleIds;
        /// <summary>
        /// The name of the protection rule.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
        /// </summary>
        public readonly string WaasPolicyId;

        [OutputConstructor]
        private GetProtectionRulesProtectionRuleResult(
            string action,

            string description,

            ImmutableArray<Outputs.GetProtectionRulesProtectionRuleExclusionResult> exclusions,

            string key,

            ImmutableArray<string> labels,

            ImmutableArray<string> modSecurityRuleIds,

            string name,

            string waasPolicyId)
        {
            Action = action;
            Description = description;
            Exclusions = exclusions;
            Key = key;
            Labels = labels;
            ModSecurityRuleIds = modSecurityRuleIds;
            Name = name;
            WaasPolicyId = waasPolicyId;
        }
    }
}
