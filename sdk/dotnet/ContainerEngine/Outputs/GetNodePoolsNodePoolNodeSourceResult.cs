// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetNodePoolsNodePoolNodeSourceResult
    {
        /// <summary>
        /// The OCID of the image used to boot the node.
        /// </summary>
        public readonly string ImageId;
        /// <summary>
        /// The user-friendly name of the entity corresponding to the OCID.
        /// </summary>
        public readonly string SourceName;
        /// <summary>
        /// The source type for the node. Use `IMAGE` when specifying an OCID of an image.
        /// </summary>
        public readonly string SourceType;

        [OutputConstructor]
        private GetNodePoolsNodePoolNodeSourceResult(
            string imageId,

            string sourceName,

            string sourceType)
        {
            ImageId = imageId;
            SourceName = sourceName;
            SourceType = sourceType;
        }
    }
}
