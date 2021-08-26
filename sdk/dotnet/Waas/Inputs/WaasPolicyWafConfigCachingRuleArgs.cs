// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class WaasPolicyWafConfigCachingRuleArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
        /// </summary>
        [Input("action", required: true)]
        public Input<string> Action { get; set; } = null!;

        /// <summary>
        /// (Updatable) The duration to cache content for the caching rule, specified in ISO 8601 extended format. Supported units: seconds, minutes, hours, days, weeks, months. The maximum value that can be set for any unit is `99`. Mixing of multiple units is not supported. Only applies when the `action` is set to `CACHE`. Example: `PT1H`
        /// </summary>
        [Input("cachingDuration")]
        public Input<string>? CachingDuration { get; set; }

        /// <summary>
        /// (Updatable) The duration to cache content in the user's browser, specified in ISO 8601 extended format. Supported units: seconds, minutes, hours, days, weeks, months. The maximum value that can be set for any unit is `99`. Mixing of multiple units is not supported. Only applies when the `action` is set to `CACHE`. Example: `PT1H`
        /// </summary>
        [Input("clientCachingDuration")]
        public Input<string>? ClientCachingDuration { get; set; }

        [Input("criterias", required: true)]
        private InputList<Inputs.WaasPolicyWafConfigCachingRuleCriteriaArgs>? _criterias;

        /// <summary>
        /// (Updatable) When defined, the JavaScript Challenge would be applied only for the requests that matched all the listed conditions.
        /// </summary>
        public InputList<Inputs.WaasPolicyWafConfigCachingRuleCriteriaArgs> Criterias
        {
            get => _criterias ?? (_criterias = new InputList<Inputs.WaasPolicyWafConfigCachingRuleCriteriaArgs>());
            set => _criterias = value;
        }

        /// <summary>
        /// (Updatable) Enables or disables client caching. Browsers use the `Cache-Control` header value for caching content locally in the browser. This setting overrides the addition of a `Cache-Control` header in responses.
        /// </summary>
        [Input("isClientCachingEnabled")]
        public Input<bool>? IsClientCachingEnabled { get; set; }

        /// <summary>
        /// (Updatable) The unique key for the caching rule.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) The unique name of the whitelist.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        public WaasPolicyWafConfigCachingRuleArgs()
        {
        }
    }
}