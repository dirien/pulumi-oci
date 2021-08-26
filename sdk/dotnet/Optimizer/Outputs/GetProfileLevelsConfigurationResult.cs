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
    public sealed class GetProfileLevelsConfigurationResult
    {
        /// <summary>
        /// The list of target tags attached to the current profile override.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProfileLevelsConfigurationItemResult> Items;

        [OutputConstructor]
        private GetProfileLevelsConfigurationResult(ImmutableArray<Outputs.GetProfileLevelsConfigurationItemResult> items)
        {
            Items = items;
        }
    }
}
