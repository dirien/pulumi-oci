// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetDatabaseInsightsDatabaseInsightsCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetDatabaseInsightsDatabaseInsightsCollectionItemResult> Items;

        [OutputConstructor]
        private GetDatabaseInsightsDatabaseInsightsCollectionResult(ImmutableArray<Outputs.GetDatabaseInsightsDatabaseInsightsCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
