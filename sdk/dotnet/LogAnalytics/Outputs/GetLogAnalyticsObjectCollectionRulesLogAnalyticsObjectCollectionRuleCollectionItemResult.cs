// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Outputs
{

    [OutputType]
    public sealed class GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollectionItemResult
    {
        /// <summary>
        /// An optional character encoding to aid in detecting the character encoding of the contents of the objects while processing. It is recommended to set this value as ISO_8589_1 when configuring content of the objects having more numeric characters, and very few alphabets. For e.g. this applies when configuring VCN Flow Logs.
        /// </summary>
        public readonly string CharEncoding;
        /// <summary>
        /// The type of collection. Supported collection types: LIVE, HISTORIC, HISTORIC_LIVE
        /// </summary>
        public readonly string CollectionType;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A string that describes the details of the rule. It does not have to be unique, and can be changed. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Logging Analytics entity OCID to associate the processed logs with.
        /// </summary>
        public readonly string EntityId;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A detailed status of the life cycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Logging Analytics Log group OCID to associate the processed logs with.
        /// </summary>
        public readonly string LogGroupId;
        /// <summary>
        /// Name of the Logging Analytics Source to use for the processing.
        /// </summary>
        public readonly string LogSourceName;
        /// <summary>
        /// A filter to return rules only matching with this name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// Name of the Object Storage bucket.
        /// </summary>
        public readonly string OsBucketName;
        /// <summary>
        /// Object Storage namespace.
        /// </summary>
        public readonly string OsNamespace;
        /// <summary>
        /// Use this to override some property values which are defined at bucket level to the scope of object. Supported propeties for override are, logSourceName, charEncoding. Supported matchType for override are "contains".
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollectionItemOverrideResult> Overrides;
        /// <summary>
        /// The oldest time of the file in the bucket to consider for collection. Accepted values are: BEGINNING or CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollSince value other than CURRENT_TIME will result in error.
        /// </summary>
        public readonly string PollSince;
        /// <summary>
        /// The oldest time of the file in the bucket to consider for collection. Accepted values are: CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollTill will result in error.
        /// </summary>
        public readonly string PollTill;
        /// <summary>
        /// Lifecycle state filter.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time when this rule was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when this rule was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollectionItemResult(
            string charEncoding,

            string collectionType,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string entityId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string logGroupId,

            string logSourceName,

            string name,

            string @namespace,

            string osBucketName,

            string osNamespace,

            ImmutableArray<Outputs.GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollectionItemOverrideResult> overrides,

            string pollSince,

            string pollTill,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CharEncoding = charEncoding;
            CollectionType = collectionType;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            EntityId = entityId;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            LogGroupId = logGroupId;
            LogSourceName = logSourceName;
            Name = name;
            Namespace = @namespace;
            OsBucketName = osBucketName;
            OsNamespace = osNamespace;
            Overrides = overrides;
            PollSince = pollSince;
            PollTill = pollTill;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
