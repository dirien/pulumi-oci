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
    public sealed class WaasPolicyWafConfig
    {
        /// <summary>
        /// (Updatable) The access rules applied to the Web Application Firewall. Access rules allow custom content access policies to be defined and `ALLOW`, `DETECT`, or `BLOCK` actions to be taken on a request when specified criteria are met.
        /// </summary>
        public readonly ImmutableArray<Outputs.WaasPolicyWafConfigAccessRule> AccessRules;
        /// <summary>
        /// (Updatable) The settings used to limit the number of requests from an IP address.
        /// </summary>
        public readonly Outputs.WaasPolicyWafConfigAddressRateLimiting? AddressRateLimiting;
        /// <summary>
        /// (Updatable) A list of caching rules applied to the web application.
        /// </summary>
        public readonly ImmutableArray<Outputs.WaasPolicyWafConfigCachingRule> CachingRules;
        /// <summary>
        /// (Updatable) A list of CAPTCHA challenge settings. CAPTCHAs challenge requests to ensure a human is attempting to reach the specified URL and not a bot.
        /// </summary>
        public readonly ImmutableArray<Outputs.WaasPolicyWafConfigCaptcha> Captchas;
        /// <summary>
        /// (Updatable) A list of the custom protection rule OCIDs and their actions.
        /// </summary>
        public readonly ImmutableArray<Outputs.WaasPolicyWafConfigCustomProtectionRule> CustomProtectionRules;
        /// <summary>
        /// (Updatable) The device fingerprint challenge settings. Blocks bots based on unique device fingerprint information.
        /// </summary>
        public readonly Outputs.WaasPolicyWafConfigDeviceFingerprintChallenge? DeviceFingerprintChallenge;
        /// <summary>
        /// (Updatable) The human interaction challenge settings. Detects natural human interactions such as mouse movements, time on site, and page scrolling to identify bots.
        /// </summary>
        public readonly Outputs.WaasPolicyWafConfigHumanInteractionChallenge? HumanInteractionChallenge;
        /// <summary>
        /// (Updatable) The JavaScript challenge settings. Blocks bots by challenging requests from browsers that have no JavaScript support.
        /// </summary>
        public readonly Outputs.WaasPolicyWafConfigJsChallenge? JsChallenge;
        /// <summary>
        /// (Updatable) The key in the map of origins referencing the origin used for the Web Application Firewall. The origin must already be included in `Origins`. Required when creating the `WafConfig` resource, but is not required upon updating the configuration.
        /// </summary>
        public readonly string? Origin;
        /// <summary>
        /// (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
        /// </summary>
        public readonly ImmutableArray<string> OriginGroups;
        /// <summary>
        /// (Updatable) The settings applied to protection rules.
        /// </summary>
        public readonly Outputs.WaasPolicyWafConfigProtectionSettings? ProtectionSettings;
        /// <summary>
        /// (Updatable) A list of IP addresses that bypass the Web Application Firewall.
        /// </summary>
        public readonly ImmutableArray<Outputs.WaasPolicyWafConfigWhitelist> Whitelists;

        [OutputConstructor]
        private WaasPolicyWafConfig(
            ImmutableArray<Outputs.WaasPolicyWafConfigAccessRule> accessRules,

            Outputs.WaasPolicyWafConfigAddressRateLimiting? addressRateLimiting,

            ImmutableArray<Outputs.WaasPolicyWafConfigCachingRule> cachingRules,

            ImmutableArray<Outputs.WaasPolicyWafConfigCaptcha> captchas,

            ImmutableArray<Outputs.WaasPolicyWafConfigCustomProtectionRule> customProtectionRules,

            Outputs.WaasPolicyWafConfigDeviceFingerprintChallenge? deviceFingerprintChallenge,

            Outputs.WaasPolicyWafConfigHumanInteractionChallenge? humanInteractionChallenge,

            Outputs.WaasPolicyWafConfigJsChallenge? jsChallenge,

            string? origin,

            ImmutableArray<string> originGroups,

            Outputs.WaasPolicyWafConfigProtectionSettings? protectionSettings,

            ImmutableArray<Outputs.WaasPolicyWafConfigWhitelist> whitelists)
        {
            AccessRules = accessRules;
            AddressRateLimiting = addressRateLimiting;
            CachingRules = cachingRules;
            Captchas = captchas;
            CustomProtectionRules = customProtectionRules;
            DeviceFingerprintChallenge = deviceFingerprintChallenge;
            HumanInteractionChallenge = humanInteractionChallenge;
            JsChallenge = jsChallenge;
            Origin = origin;
            OriginGroups = originGroups;
            ProtectionSettings = protectionSettings;
            Whitelists = whitelists;
        }
    }
}
