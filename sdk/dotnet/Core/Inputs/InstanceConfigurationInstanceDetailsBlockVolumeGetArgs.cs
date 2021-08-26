// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceConfigurationInstanceDetailsBlockVolumeGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Volume attachmentDetails. Please see [AttachVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/AttachVolumeDetails/)
        /// </summary>
        [Input("attachDetails")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeAttachDetailsGetArgs>? AttachDetails { get; set; }

        /// <summary>
        /// Creates a new block volume. Please see [CreateVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVolumeDetails/)
        /// </summary>
        [Input("createDetails")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsGetArgs>? CreateDetails { get; set; }

        /// <summary>
        /// The OCID of the volume.
        /// </summary>
        [Input("volumeId")]
        public Input<string>? VolumeId { get; set; }

        public InstanceConfigurationInstanceDetailsBlockVolumeGetArgs()
        {
        }
    }
}
