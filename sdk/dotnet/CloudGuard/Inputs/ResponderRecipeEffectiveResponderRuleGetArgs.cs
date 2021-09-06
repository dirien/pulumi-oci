// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class ResponderRecipeEffectiveResponderRuleGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) ResponderRecipe Description
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Details of UpdateResponderRuleDetails.
        /// </summary>
        [Input("details")]
        public Input<Inputs.ResponderRecipeEffectiveResponderRuleDetailsGetArgs>? Details { get; set; }

        /// <summary>
        /// (Updatable) ResponderRecipe Display Name
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("policies")]
        private InputList<string>? _policies;

        /// <summary>
        /// List of Policy
        /// </summary>
        public InputList<string> Policies
        {
            get => _policies ?? (_policies = new InputList<string>());
            set => _policies = value;
        }

        /// <summary>
        /// (Updatable) ResponderRecipeRule Identifier
        /// </summary>
        [Input("responderRuleId")]
        public Input<string>? ResponderRuleId { get; set; }

        /// <summary>
        /// The current state of the Example.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("supportedModes")]
        private InputList<string>? _supportedModes;

        /// <summary>
        /// Supported Execution Modes
        /// </summary>
        public InputList<string> SupportedModes
        {
            get => _supportedModes ?? (_supportedModes = new InputList<string>());
            set => _supportedModes = value;
        }

        /// <summary>
        /// The date and time the responder recipe was created. Format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the responder recipe was updated. Format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// Type of Responder
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public ResponderRecipeEffectiveResponderRuleGetArgs()
        {
        }
    }
}
