// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class GetFleetsFleetCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetFleetsFleetCollectionItemResult> Items;

        [OutputConstructor]
        private GetFleetsFleetCollectionResult(ImmutableArray<Outputs.GetFleetsFleetCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
