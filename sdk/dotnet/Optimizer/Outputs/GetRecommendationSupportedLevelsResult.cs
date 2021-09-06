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
    public sealed class GetRecommendationSupportedLevelsResult
    {
        /// <summary>
        /// The list of supported levels.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRecommendationSupportedLevelsItemResult> Items;

        [OutputConstructor]
        private GetRecommendationSupportedLevelsResult(ImmutableArray<Outputs.GetRecommendationSupportedLevelsItemResult> items)
        {
            Items = items;
        }
    }
}
