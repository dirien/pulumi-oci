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
    public sealed class GetBucketSummariesBucketSummaryRetentionRuleDurationResult
    {
        public readonly string TimeAmount;
        public readonly string TimeUnit;

        [OutputConstructor]
        private GetBucketSummariesBucketSummaryRetentionRuleDurationResult(
            string timeAmount,

            string timeUnit)
        {
            TimeAmount = timeAmount;
            TimeUnit = timeUnit;
        }
    }
}
