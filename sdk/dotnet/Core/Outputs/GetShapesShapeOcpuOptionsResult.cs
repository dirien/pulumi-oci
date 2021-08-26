// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetShapesShapeOcpuOptionsResult
    {
        /// <summary>
        /// The maximum number of OCPUs.
        /// </summary>
        public readonly double Max;
        /// <summary>
        /// The minimum number of OCPUs.
        /// </summary>
        public readonly double Min;

        [OutputConstructor]
        private GetShapesShapeOcpuOptionsResult(
            double max,

            double min)
        {
            Max = max;
            Min = min;
        }
    }
}
