// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Artifacts.Outputs
{

    [OutputType]
    public sealed class GetGenericArtifactsGenericArtifactCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetGenericArtifactsGenericArtifactCollectionItemResult> Items;

        [OutputConstructor]
        private GetGenericArtifactsGenericArtifactCollectionResult(ImmutableArray<Outputs.GetGenericArtifactsGenericArtifactCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
