// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class WaasPolicyWafConfigArgs : Pulumi.ResourceArgs
    {
        [Input("accessRules")]
        private InputList<Inputs.WaasPolicyWafConfigAccessRuleArgs>? _accessRules;

        /// <summary>
        /// (Updatable) The access rules applied to the Web Application Firewall. Access rules allow custom content access policies to be defined and `ALLOW`, `DETECT`, or `BLOCK` actions to be taken on a request when specified criteria are met.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigAccessRuleArgs> AccessRules
        {
            get => _accessRules ?? (_accessRules = new InputList<Inputs.WaasPolicyWafConfigAccessRuleArgs>());
            set => _accessRules = value;
        }

        /// <summary>
        /// (Updatable) The settings used to limit the number of requests from an IP address.
        /// </summary>
        [Input("addressRateLimiting")]
        public Input<Inputs.WaasPolicyWafConfigAddressRateLimitingArgs>? AddressRateLimiting { get; set; }

        [Input("cachingRules")]
        private InputList<Inputs.WaasPolicyWafConfigCachingRuleArgs>? _cachingRules;

        /// <summary>
        /// (Updatable) A list of caching rules applied to the web application.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigCachingRuleArgs> CachingRules
        {
            get => _cachingRules ?? (_cachingRules = new InputList<Inputs.WaasPolicyWafConfigCachingRuleArgs>());
            set => _cachingRules = value;
        }

        [Input("captchas")]
        private InputList<Inputs.WaasPolicyWafConfigCaptchaArgs>? _captchas;

        /// <summary>
        /// (Updatable) A list of CAPTCHA challenge settings. CAPTCHAs challenge requests to ensure a human is attempting to reach the specified URL and not a bot.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigCaptchaArgs> Captchas
        {
            get => _captchas ?? (_captchas = new InputList<Inputs.WaasPolicyWafConfigCaptchaArgs>());
            set => _captchas = value;
        }

        [Input("customProtectionRules")]
        private InputList<Inputs.WaasPolicyWafConfigCustomProtectionRuleArgs>? _customProtectionRules;

        /// <summary>
        /// (Updatable) A list of the custom protection rule OCIDs and their actions.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigCustomProtectionRuleArgs> CustomProtectionRules
        {
            get => _customProtectionRules ?? (_customProtectionRules = new InputList<Inputs.WaasPolicyWafConfigCustomProtectionRuleArgs>());
            set => _customProtectionRules = value;
        }

        /// <summary>
        /// (Updatable) The device fingerprint challenge settings. Blocks bots based on unique device fingerprint information.
        /// </summary>
        [Input("deviceFingerprintChallenge")]
        public Input<Inputs.WaasPolicyWafConfigDeviceFingerprintChallengeArgs>? DeviceFingerprintChallenge { get; set; }

        /// <summary>
        /// (Updatable) The human interaction challenge settings. Detects natural human interactions such as mouse movements, time on site, and page scrolling to identify bots.
        /// </summary>
        [Input("humanInteractionChallenge")]
        public Input<Inputs.WaasPolicyWafConfigHumanInteractionChallengeArgs>? HumanInteractionChallenge { get; set; }

        /// <summary>
        /// (Updatable) The JavaScript challenge settings. Blocks bots by challenging requests from browsers that have no JavaScript support.
        /// </summary>
        [Input("jsChallenge")]
        public Input<Inputs.WaasPolicyWafConfigJsChallengeArgs>? JsChallenge { get; set; }

        /// <summary>
        /// (Updatable) The key in the map of origins referencing the origin used for the Web Application Firewall. The origin must already be included in `Origins`. Required when creating the `WafConfig` resource, but is not required upon updating the configuration.
        /// </summary>
        [Input("origin")]
        public Input<string>? Origin { get; set; }

        [Input("originGroups")]
        private InputList<string>? _originGroups;

        /// <summary>
        /// (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
        /// </summary>
        public InputList<string> OriginGroups
        {
            get => _originGroups ?? (_originGroups = new InputList<string>());
            set => _originGroups = value;
        }

        /// <summary>
        /// (Updatable) The settings applied to protection rules.
        /// </summary>
        [Input("protectionSettings")]
        public Input<Inputs.WaasPolicyWafConfigProtectionSettingsArgs>? ProtectionSettings { get; set; }

        [Input("whitelists")]
        private InputList<Inputs.WaasPolicyWafConfigWhitelistArgs>? _whitelists;

        /// <summary>
        /// (Updatable) A list of IP addresses that bypass the Web Application Firewall.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigWhitelistArgs> Whitelists
        {
            get => _whitelists ?? (_whitelists = new InputList<Inputs.WaasPolicyWafConfigWhitelistArgs>());
            set => _whitelists = value;
        }

        public WaasPolicyWafConfigArgs()
        {
        }
    }
}
