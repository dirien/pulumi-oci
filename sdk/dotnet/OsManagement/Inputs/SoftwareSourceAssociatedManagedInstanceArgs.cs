// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement.Inputs
{

    public sealed class SoftwareSourceAssociatedManagedInstanceArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) User friendly name for the software source
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// OCID for the Software Source
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public SoftwareSourceAssociatedManagedInstanceArgs()
        {
        }
    }
}
