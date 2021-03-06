// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class WaasPolicyWafConfigGetArgs : Pulumi.ResourceArgs
    {
        [Input("accessRules")]
        private InputList<Inputs.WaasPolicyWafConfigAccessRuleGetArgs>? _accessRules;

        /// <summary>
        /// (Updatable) The access rules applied to the Web Application Firewall. Access rules allow custom content access policies to be defined and `ALLOW`, `DETECT`, or `BLOCK` actions to be taken on a request when specified criteria are met.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigAccessRuleGetArgs> AccessRules
        {
            get => _accessRules ?? (_accessRules = new InputList<Inputs.WaasPolicyWafConfigAccessRuleGetArgs>());
            set => _accessRules = value;
        }

        /// <summary>
        /// (Updatable) The settings used to limit the number of requests from an IP address.
        /// </summary>
        [Input("addressRateLimiting")]
        public Input<Inputs.WaasPolicyWafConfigAddressRateLimitingGetArgs>? AddressRateLimiting { get; set; }

        [Input("cachingRules")]
        private InputList<Inputs.WaasPolicyWafConfigCachingRuleGetArgs>? _cachingRules;

        /// <summary>
        /// (Updatable) A list of caching rules applied to the web application.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigCachingRuleGetArgs> CachingRules
        {
            get => _cachingRules ?? (_cachingRules = new InputList<Inputs.WaasPolicyWafConfigCachingRuleGetArgs>());
            set => _cachingRules = value;
        }

        [Input("captchas")]
        private InputList<Inputs.WaasPolicyWafConfigCaptchaGetArgs>? _captchas;

        /// <summary>
        /// (Updatable) A list of CAPTCHA challenge settings. CAPTCHAs challenge requests to ensure a human is attempting to reach the specified URL and not a bot.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigCaptchaGetArgs> Captchas
        {
            get => _captchas ?? (_captchas = new InputList<Inputs.WaasPolicyWafConfigCaptchaGetArgs>());
            set => _captchas = value;
        }

        [Input("customProtectionRules")]
        private InputList<Inputs.WaasPolicyWafConfigCustomProtectionRuleGetArgs>? _customProtectionRules;

        /// <summary>
        /// (Updatable) A list of the custom protection rule OCIDs and their actions.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigCustomProtectionRuleGetArgs> CustomProtectionRules
        {
            get => _customProtectionRules ?? (_customProtectionRules = new InputList<Inputs.WaasPolicyWafConfigCustomProtectionRuleGetArgs>());
            set => _customProtectionRules = value;
        }

        /// <summary>
        /// (Updatable) The device fingerprint challenge settings. Blocks bots based on unique device fingerprint information.
        /// </summary>
        [Input("deviceFingerprintChallenge")]
        public Input<Inputs.WaasPolicyWafConfigDeviceFingerprintChallengeGetArgs>? DeviceFingerprintChallenge { get; set; }

        /// <summary>
        /// (Updatable) The human interaction challenge settings. Detects natural human interactions such as mouse movements, time on site, and page scrolling to identify bots.
        /// </summary>
        [Input("humanInteractionChallenge")]
        public Input<Inputs.WaasPolicyWafConfigHumanInteractionChallengeGetArgs>? HumanInteractionChallenge { get; set; }

        /// <summary>
        /// (Updatable) The JavaScript challenge settings. Blocks bots by challenging requests from browsers that have no JavaScript support.
        /// </summary>
        [Input("jsChallenge")]
        public Input<Inputs.WaasPolicyWafConfigJsChallengeGetArgs>? JsChallenge { get; set; }

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
        public Input<Inputs.WaasPolicyWafConfigProtectionSettingsGetArgs>? ProtectionSettings { get; set; }

        [Input("whitelists")]
        private InputList<Inputs.WaasPolicyWafConfigWhitelistGetArgs>? _whitelists;

        /// <summary>
        /// (Updatable) A list of IP addresses that bypass the Web Application Firewall.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigWhitelistGetArgs> Whitelists
        {
            get => _whitelists ?? (_whitelists = new InputList<Inputs.WaasPolicyWafConfigWhitelistGetArgs>());
            set => _whitelists = value;
        }

        public WaasPolicyWafConfigGetArgs()
        {
        }
    }
}
