// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Inputs
{

    public sealed class ResolverEndpointArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the owning compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The type of resolver endpoint. VNIC is currently the only supported type.
        /// </summary>
        [Input("endpointType")]
        public Input<string>? EndpointType { get; set; }

        /// <summary>
        /// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
        /// </summary>
        [Input("forwardingAddress")]
        public Input<string>? ForwardingAddress { get; set; }

        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
        /// </summary>
        [Input("isForwarding")]
        public Input<bool>? IsForwarding { get; set; }

        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for listening.
        /// </summary>
        [Input("isListening")]
        public Input<bool>? IsListening { get; set; }

        /// <summary>
        /// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
        /// </summary>
        [Input("listeningAddress")]
        public Input<string>? ListeningAddress { get; set; }

        /// <summary>
        /// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        [Input("self")]
        public Input<string>? Self { get; set; }

        /// <summary>
        /// The current state of the resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        /// <summary>
        /// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public ResolverEndpointArgs()
        {
        }
    }
}
