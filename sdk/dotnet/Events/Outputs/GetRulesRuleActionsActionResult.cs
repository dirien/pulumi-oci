// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Events.Outputs
{

    [OutputType]
    public sealed class GetRulesRuleActionsActionResult
    {
        /// <summary>
        /// The action to perform if the condition in the rule matches an event.
        /// * **ONS:** Send to an Oracle Notification Service topic.
        /// * **OSS:** Send to a stream from Oracle Streaming Service.
        /// * **FAAS:** Send to an Oracle Functions Service endpoint.
        /// </summary>
        public readonly string ActionType;
        /// <summary>
        /// A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Function hosted by Oracle Functions Service.
        /// </summary>
        public readonly string FunctionId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Whether or not this rule is currently enabled.  Example: `true`
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// A message generated by the Events service about the current state of this rule.
        /// </summary>
        public readonly string LifecycleMessage;
        /// <summary>
        /// A filter to return only rules that match the lifecycle state in this parameter.  Example: `Creating`
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream to which messages are delivered.
        /// </summary>
        public readonly string StreamId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic to which messages are delivered.
        /// </summary>
        public readonly string TopicId;

        [OutputConstructor]
        private GetRulesRuleActionsActionResult(
            string actionType,

            string description,

            string functionId,

            string id,

            bool isEnabled,

            string lifecycleMessage,

            string state,

            string streamId,

            string topicId)
        {
            ActionType = actionType;
            Description = description;
            FunctionId = functionId;
            Id = id;
            IsEnabled = isEnabled;
            LifecycleMessage = lifecycleMessage;
            State = state;
            StreamId = streamId;
            TopicId = topicId;
        }
    }
}
