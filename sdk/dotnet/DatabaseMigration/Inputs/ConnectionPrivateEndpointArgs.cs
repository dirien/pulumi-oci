// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class ConnectionPrivateEndpointArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a previously created Private Endpoint.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the customer's subnet where the private endpoint VNIC will reside.  Required if the id was not specified.
        /// </summary>
        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN where the Private Endpoint will be bound to. Required if the id was not specified.
        /// </summary>
        [Input("vcnId", required: true)]
        public Input<string> VcnId { get; set; } = null!;

        public ConnectionPrivateEndpointArgs()
        {
        }
    }
}
