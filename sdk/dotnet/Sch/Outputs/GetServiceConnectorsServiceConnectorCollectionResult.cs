// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch.Outputs
{

    [OutputType]
    public sealed class GetServiceConnectorsServiceConnectorCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetServiceConnectorsServiceConnectorCollectionItemResult> Items;

        [OutputConstructor]
        private GetServiceConnectorsServiceConnectorCollectionResult(ImmutableArray<Outputs.GetServiceConnectorsServiceConnectorCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
