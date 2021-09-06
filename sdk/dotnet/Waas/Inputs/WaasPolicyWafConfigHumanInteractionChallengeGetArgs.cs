// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class WaasPolicyWafConfigHumanInteractionChallengeGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
        /// </summary>
        [Input("action")]
        public Input<string>? Action { get; set; }

        /// <summary>
        /// (Updatable) The number of seconds between challenges from the same IP address. If unspecified, defaults to `60`.
        /// </summary>
        [Input("actionExpirationInSeconds")]
        public Input<int>? ActionExpirationInSeconds { get; set; }

        /// <summary>
        /// (Updatable) The challenge settings if `action` is set to `BLOCK`.
        /// </summary>
        [Input("challengeSettings")]
        public Input<Inputs.WaasPolicyWafConfigHumanInteractionChallengeChallengeSettingsGetArgs>? ChallengeSettings { get; set; }

        /// <summary>
        /// (Updatable) The number of failed requests before taking action. If unspecified, defaults to `10`.
        /// </summary>
        [Input("failureThreshold")]
        public Input<int>? FailureThreshold { get; set; }

        /// <summary>
        /// (Updatable) The number of seconds before the failure threshold resets. If unspecified, defaults to  `60`.
        /// </summary>
        [Input("failureThresholdExpirationInSeconds")]
        public Input<int>? FailureThresholdExpirationInSeconds { get; set; }

        /// <summary>
        /// (Updatable) The number of interactions required to pass the challenge. If unspecified, defaults to `3`.
        /// </summary>
        [Input("interactionThreshold")]
        public Input<int>? InteractionThreshold { get; set; }

        /// <summary>
        /// (Updatable) Enables or disables the JavaScript challenge Web Application Firewall feature.
        /// </summary>
        [Input("isEnabled", required: true)]
        public Input<bool> IsEnabled { get; set; } = null!;

        /// <summary>
        /// (Updatable) When enabled, the user is identified not only by the IP address but also by an unique additional hash, which prevents blocking visitors with shared IP addresses.
        /// </summary>
        [Input("isNatEnabled")]
        public Input<bool>? IsNatEnabled { get; set; }

        /// <summary>
        /// (Updatable) The number of seconds to record the interactions from the user. If unspecified, defaults to `15`.
        /// </summary>
        [Input("recordingPeriodInSeconds")]
        public Input<int>? RecordingPeriodInSeconds { get; set; }

        /// <summary>
        /// (Updatable) Adds an additional HTTP header to requests that fail the challenge before being passed to the origin. Only applicable when the `action` is set to `DETECT`.
        /// </summary>
        [Input("setHttpHeader")]
        public Input<Inputs.WaasPolicyWafConfigHumanInteractionChallengeSetHttpHeaderGetArgs>? SetHttpHeader { get; set; }

        public WaasPolicyWafConfigHumanInteractionChallengeGetArgs()
        {
        }
    }
}
