// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the volume backup.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The type of action to run when the instance is interrupted for eviction.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsArgs()
        {
        }
    }
}
