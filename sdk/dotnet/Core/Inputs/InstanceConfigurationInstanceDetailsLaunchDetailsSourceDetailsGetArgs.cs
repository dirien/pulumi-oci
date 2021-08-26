// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetailsGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the boot volume used to boot the instance.
        /// </summary>
        [Input("bootVolumeId")]
        public Input<string>? BootVolumeId { get; set; }

        /// <summary>
        /// The size of the boot volume in GBs. The minimum value is 50 GB and the maximum value is 32,768 GB (32 TB).
        /// </summary>
        [Input("bootVolumeSizeInGbs")]
        public Input<string>? BootVolumeSizeInGbs { get; set; }

        /// <summary>
        /// The OCID of the image used to boot the instance.
        /// </summary>
        [Input("imageId")]
        public Input<string>? ImageId { get; set; }

        /// <summary>
        /// The source type for the instance. Use `image` when specifying the image OCID. Use `bootVolume` when specifying the boot volume OCID.
        /// </summary>
        [Input("sourceType", required: true)]
        public Input<string> SourceType { get; set; } = null!;

        public InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetailsGetArgs()
        {
        }
    }
}
