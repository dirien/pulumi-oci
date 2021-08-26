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
    public sealed class GetWaasPolicyWafConfigJsChallengeResult
    {
        /// <summary>
        /// The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
        /// </summary>
        public readonly string Action;
        /// <summary>
        /// The number of seconds between challenges from the same IP address. If unspecified, defaults to `60`.
        /// </summary>
        public readonly int ActionExpirationInSeconds;
        /// <summary>
        /// When enabled, redirect responses from the origin will also be challenged. This will change HTTP 301/302 responses from origin to HTTP 200 with an HTML body containing JavaScript page redirection.
        /// </summary>
        public readonly bool AreRedirectsChallenged;
        /// <summary>
        /// The challenge settings if `action` is set to `BLOCK`.
        /// </summary>
        public readonly Outputs.GetWaasPolicyWafConfigJsChallengeChallengeSettingsResult ChallengeSettings;
        /// <summary>
        /// When defined, the JavaScript Challenge would be applied only for the requests that matched all the listed conditions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWaasPolicyWafConfigJsChallengeCriteriaResult> Criterias;
        /// <summary>
        /// The number of failed requests before taking action. If unspecified, defaults to `10`.
        /// </summary>
        public readonly int FailureThreshold;
        /// <summary>
        /// Enables or disables the JavaScript challenge Web Application Firewall feature.
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// When enabled, the user is identified not only by the IP address but also by an unique additional hash, which prevents blocking visitors with shared IP addresses.
        /// </summary>
        public readonly bool IsNatEnabled;
        /// <summary>
        /// Adds an additional HTTP header to requests that fail the challenge before being passed to the origin. Only applicable when the `action` is set to `DETECT`.
        /// </summary>
        public readonly Outputs.GetWaasPolicyWafConfigJsChallengeSetHttpHeaderResult SetHttpHeader;

        [OutputConstructor]
        private GetWaasPolicyWafConfigJsChallengeResult(
            string action,

            int actionExpirationInSeconds,

            bool areRedirectsChallenged,

            Outputs.GetWaasPolicyWafConfigJsChallengeChallengeSettingsResult challengeSettings,

            ImmutableArray<Outputs.GetWaasPolicyWafConfigJsChallengeCriteriaResult> criterias,

            int failureThreshold,

            bool isEnabled,

            bool isNatEnabled,

            Outputs.GetWaasPolicyWafConfigJsChallengeSetHttpHeaderResult setHttpHeader)
        {
            Action = action;
            ActionExpirationInSeconds = actionExpirationInSeconds;
            AreRedirectsChallenged = areRedirectsChallenged;
            ChallengeSettings = challengeSettings;
            Criterias = criterias;
            FailureThreshold = failureThreshold;
            IsEnabled = isEnabled;
            IsNatEnabled = isNatEnabled;
            SetHttpHeader = setHttpHeader;
        }
    }
}
