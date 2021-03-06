// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetBootVolumeAttachments
    {
        public static Task<GetBootVolumeAttachmentsResult> InvokeAsync(GetBootVolumeAttachmentsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetBootVolumeAttachmentsResult>("oci:core/getBootVolumeAttachments:getBootVolumeAttachments", args ?? new GetBootVolumeAttachmentsArgs(), options.WithVersion());
    }


    public sealed class GetBootVolumeAttachmentsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public string AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// The OCID of the boot volume.
        /// </summary>
        [Input("bootVolumeId")]
        public string? BootVolumeId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetBootVolumeAttachmentsFilterArgs>? _filters;
        public List<Inputs.GetBootVolumeAttachmentsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBootVolumeAttachmentsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        [Input("instanceId")]
        public string? InstanceId { get; set; }

        public GetBootVolumeAttachmentsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetBootVolumeAttachmentsResult
    {
        /// <summary>
        /// The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The list of boot_volume_attachments.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBootVolumeAttachmentsBootVolumeAttachmentResult> BootVolumeAttachments;
        /// <summary>
        /// The OCID of the boot volume.
        /// </summary>
        public readonly string? BootVolumeId;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetBootVolumeAttachmentsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the instance the boot volume is attached to.
        /// </summary>
        public readonly string? InstanceId;

        [OutputConstructor]
        private GetBootVolumeAttachmentsResult(
            string availabilityDomain,

            ImmutableArray<Outputs.GetBootVolumeAttachmentsBootVolumeAttachmentResult> bootVolumeAttachments,

            string? bootVolumeId,

            string compartmentId,

            ImmutableArray<Outputs.GetBootVolumeAttachmentsFilterResult> filters,

            string id,

            string? instanceId)
        {
            AvailabilityDomain = availabilityDomain;
            BootVolumeAttachments = bootVolumeAttachments;
            BootVolumeId = bootVolumeId;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            InstanceId = instanceId;
        }
    }
}
