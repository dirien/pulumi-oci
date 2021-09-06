// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Vault.Outputs
{

    [OutputType]
    public sealed class GetSecretSecretRuleResult
    {
        /// <summary>
        /// A property indicating whether the rule is applied even if the secret version with the content you are trying to reuse was deleted.
        /// </summary>
        public readonly bool IsEnforcedOnDeletedSecretVersions;
        /// <summary>
        /// A property indicating whether to block retrieval of the secret content, on expiry. The default is false. If the secret has already expired and you would like to retrieve the secret contents, you need to edit the secret rule to disable this property, to allow reading the secret content.
        /// </summary>
        public readonly bool IsSecretContentRetrievalBlockedOnExpiry;
        /// <summary>
        /// The type of rule, which either controls when the secret contents expire or whether they can be reused.
        /// </summary>
        public readonly string RuleType;
        /// <summary>
        /// A property indicating how long the secret contents will be considered valid, expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format. The secret needs to be updated when the secret content expires. No enforcement mechanism exists at this time, but audit logs record the expiration on the appropriate date, according to the time interval specified in the rule. The timer resets after you update the secret contents. The minimum value is 1 day and the maximum value is 90 days for this property. Currently, only intervals expressed in days are supported. For example, pass `P3D` to have the secret version expire every 3 days.
        /// </summary>
        public readonly string SecretVersionExpiryInterval;
        /// <summary>
        /// An optional property indicating the absolute time when this secret will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. The minimum number of days from current time is 1 day and the maximum number of days from current time is 365 days. Example: `2019-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeOfAbsoluteExpiry;

        [OutputConstructor]
        private GetSecretSecretRuleResult(
            bool isEnforcedOnDeletedSecretVersions,

            bool isSecretContentRetrievalBlockedOnExpiry,

            string ruleType,

            string secretVersionExpiryInterval,

            string timeOfAbsoluteExpiry)
        {
            IsEnforcedOnDeletedSecretVersions = isEnforcedOnDeletedSecretVersions;
            IsSecretContentRetrievalBlockedOnExpiry = isSecretContentRetrievalBlockedOnExpiry;
            RuleType = ruleType;
            SecretVersionExpiryInterval = secretVersionExpiryInterval;
            TimeOfAbsoluteExpiry = timeOfAbsoluteExpiry;
        }
    }
}
