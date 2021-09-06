// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfigGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The baseline OCPU utilization for a subcore burstable VM instance. Leave this attribute blank for a non-burstable instance, or explicitly specify non-burstable with `BASELINE_1_1`.
        /// </summary>
        [Input("baselineOcpuUtilization")]
        public Input<string>? BaselineOcpuUtilization { get; set; }

        /// <summary>
        /// The total amount of memory available to the instance, in gigabytes.
        /// </summary>
        [Input("memoryInGbs")]
        public Input<double>? MemoryInGbs { get; set; }

        /// <summary>
        /// The total number of OCPUs available to the instance.
        /// </summary>
        [Input("ocpus")]
        public Input<double>? Ocpus { get; set; }

        public InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfigGetArgs()
        {
        }
    }
}
