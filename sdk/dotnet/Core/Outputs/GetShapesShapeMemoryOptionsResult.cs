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
    public sealed class GetShapesShapeMemoryOptionsResult
    {
        /// <summary>
        /// The default amount of memory per OCPU available for this shape, in gigabytes.
        /// </summary>
        public readonly double DefaultPerOcpuInGbs;
        /// <summary>
        /// The maximum amount of memory, in gigabytes.
        /// </summary>
        public readonly double MaxInGbs;
        /// <summary>
        /// The maximum amount of memory per OCPU available for this shape, in gigabytes.
        /// </summary>
        public readonly double MaxPerOcpuInGbs;
        /// <summary>
        /// The minimum amount of memory, in gigabytes.
        /// </summary>
        public readonly double MinInGbs;
        /// <summary>
        /// The minimum amount of memory per OCPU available for this shape, in gigabytes.
        /// </summary>
        public readonly double MinPerOcpuInGbs;

        [OutputConstructor]
        private GetShapesShapeMemoryOptionsResult(
            double defaultPerOcpuInGbs,

            double maxInGbs,

            double maxPerOcpuInGbs,

            double minInGbs,

            double minPerOcpuInGbs)
        {
            DefaultPerOcpuInGbs = defaultPerOcpuInGbs;
            MaxInGbs = maxInGbs;
            MaxPerOcpuInGbs = maxPerOcpuInGbs;
            MinInGbs = minInGbs;
            MinPerOcpuInGbs = minPerOcpuInGbs;
        }
    }
}
