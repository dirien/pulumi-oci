// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Inputs
{

    public sealed class SteeringPolicyRuleCaseAnswerDataGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// An expression that is used to select a set of answers that match a condition. For example, answers with matching pool properties.
        /// </summary>
        [Input("answerCondition")]
        public Input<string>? AnswerCondition { get; set; }

        /// <summary>
        /// Keeps the answer only if the value is `true`.
        /// </summary>
        [Input("shouldKeep")]
        public Input<bool>? ShouldKeep { get; set; }

        /// <summary>
        /// The rank assigned to the set of answers that match the expression in `answerCondition`. Answers with the lowest values move to the beginning of the list without changing the relative order of those with the same value. Answers can be given a value between `0` and `255`.
        /// </summary>
        [Input("value")]
        public Input<int>? Value { get; set; }

        public SteeringPolicyRuleCaseAnswerDataGetArgs()
        {
        }
    }
}
