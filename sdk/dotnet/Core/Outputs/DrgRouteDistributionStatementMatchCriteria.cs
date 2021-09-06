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
    public sealed class DrgRouteDistributionStatementMatchCriteria
    {
        /// <summary>
        /// The type of the network resource to be included in this match. A match for a network type implies that all DRG attachments of that type insert routes into the table.
        /// </summary>
        public readonly string? AttachmentType;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG attachment.
        /// </summary>
        public readonly string? DrgAttachmentId;
        /// <summary>
        /// (Updatable) The type of the match criteria for a route distribution statement.
        /// </summary>
        public readonly string? MatchType;

        [OutputConstructor]
        private DrgRouteDistributionStatementMatchCriteria(
            string? attachmentType,

            string? drgAttachmentId,

            string? matchType)
        {
            AttachmentType = attachmentType;
            DrgAttachmentId = drgAttachmentId;
            MatchType = matchType;
        }
    }
}
