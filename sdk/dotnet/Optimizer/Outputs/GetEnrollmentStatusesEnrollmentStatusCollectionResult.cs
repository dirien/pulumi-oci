// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Outputs
{

    [OutputType]
    public sealed class GetEnrollmentStatusesEnrollmentStatusCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetEnrollmentStatusesEnrollmentStatusCollectionItemResult> Items;

        [OutputConstructor]
        private GetEnrollmentStatusesEnrollmentStatusCollectionResult(ImmutableArray<Outputs.GetEnrollmentStatusesEnrollmentStatusCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
