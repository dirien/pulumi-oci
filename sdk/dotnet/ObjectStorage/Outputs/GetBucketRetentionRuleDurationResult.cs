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
    public sealed class GetBucketRetentionRuleDurationResult
    {
        /// <summary>
        /// The timeAmount is interpreted in units defined by the timeUnit parameter, and is calculated in relation to each object's Last-Modified timestamp.
        /// </summary>
        public readonly string TimeAmount;
        /// <summary>
        /// The unit that should be used to interpret timeAmount.
        /// </summary>
        public readonly string TimeUnit;

        [OutputConstructor]
        private GetBucketRetentionRuleDurationResult(
            string timeAmount,

            string timeUnit)
        {
            TimeAmount = timeAmount;
            TimeUnit = timeUnit;
        }
    }
}
