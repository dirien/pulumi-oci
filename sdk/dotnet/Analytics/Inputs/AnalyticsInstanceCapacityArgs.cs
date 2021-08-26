// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Analytics.Inputs
{

    public sealed class AnalyticsInstanceCapacityArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The capacity model to use.
        /// </summary>
        [Input("capacityType", required: true)]
        public Input<string> CapacityType { get; set; } = null!;

        /// <summary>
        /// (Updatable) The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        /// </summary>
        [Input("capacityValue", required: true)]
        public Input<int> CapacityValue { get; set; } = null!;

        public AnalyticsInstanceCapacityArgs()
        {
        }
    }
}