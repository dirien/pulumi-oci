// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage.Outputs
{

    [OutputType]
    public sealed class ObjectstorageBucketRetentionRule
    {
        /// <summary>
        /// A user-specified name for the retention rule. Names can be helpful in identifying retention rules. The name should be unique. This attribute is a forcenew attribute
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly Outputs.ObjectstorageBucketRetentionRuleDuration? Duration;
        /// <summary>
        /// Unique identifier for the retention rule.
        /// </summary>
        public readonly string? RetentionRuleId;
        /// <summary>
        /// The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// The date and time that the retention rule was modified as per [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string? TimeModified;
        /// <summary>
        /// (Updatable) The date and time as per [RFC 3339](https://tools.ietf.org/html/rfc3339) after which this rule is locked and can only be deleted by deleting the bucket. Once a rule is locked, only increases in the duration are allowed and no other properties can be changed. This property cannot be updated for rules that are in a locked state. Specifying it when a duration is not specified is considered an error.
        /// </summary>
        public readonly string? TimeRuleLocked;

        [OutputConstructor]
        private ObjectstorageBucketRetentionRule(
            string displayName,

            Outputs.ObjectstorageBucketRetentionRuleDuration? duration,

            string? retentionRuleId,

            string? timeCreated,

            string? timeModified,

            string? timeRuleLocked)
        {
            DisplayName = displayName;
            Duration = duration;
            RetentionRuleId = retentionRuleId;
            TimeCreated = timeCreated;
            TimeModified = timeModified;
            TimeRuleLocked = timeRuleLocked;
        }
    }
}