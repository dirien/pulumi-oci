// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement.Outputs
{

    [OutputType]
    public sealed class SoftwareSourceAssociatedManagedInstance
    {
        /// <summary>
        /// (Updatable) User friendly name for the software source
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// OCID for the Software Source
        /// </summary>
        public readonly string? Id;

        [OutputConstructor]
        private SoftwareSourceAssociatedManagedInstance(
            string? displayName,

            string? id)
        {
            DisplayName = displayName;
            Id = id;
        }
    }
}
