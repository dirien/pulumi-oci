// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer
{
    /// <summary>
    /// This resource provides the Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.
    /// 
    /// Adds a listener to a network load balancer.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testListener = new Oci.NetworkLoadBalancer.Listener("testListener", new Oci.NetworkLoadBalancer.ListenerArgs
    ///         {
    ///             DefaultBackendSetName = oci_network_load_balancer_backend_set.Test_backend_set.Name,
    ///             NetworkLoadBalancerId = oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id,
    ///             Port = @var.Listener_port,
    ///             Protocol = @var.Listener_protocol,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Listeners can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:networkloadbalancer/listener:Listener test_listener "networkLoadBalancers/{networkLoadBalancerId}/listeners/{listenerName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:networkloadbalancer/listener:Listener")]
    public partial class Listener : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Output("defaultBackendSetName")]
        public Output<string> DefaultBackendSetName { get; private set; } = null!;

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Output("networkLoadBalancerId")]
        public Output<string> NetworkLoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Output("port")]
        public Output<int> Port { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
        /// </summary>
        [Output("protocol")]
        public Output<string> Protocol { get; private set; } = null!;


        /// <summary>
        /// Create a Listener resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Listener(string name, ListenerArgs args, CustomResourceOptions? options = null)
            : base("oci:networkloadbalancer/listener:Listener", name, args ?? new ListenerArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Listener(string name, Input<string> id, ListenerState? state = null, CustomResourceOptions? options = null)
            : base("oci:networkloadbalancer/listener:Listener", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Listener resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Listener Get(string name, Input<string> id, ListenerState? state = null, CustomResourceOptions? options = null)
        {
            return new Listener(name, id, state, options);
        }
    }

    public sealed class ListenerArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Input("defaultBackendSetName", required: true)]
        public Input<string> DefaultBackendSetName { get; set; } = null!;

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public Input<string> NetworkLoadBalancerId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Input("port", required: true)]
        public Input<int> Port { get; set; } = null!;

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
        /// </summary>
        [Input("protocol", required: true)]
        public Input<string> Protocol { get; set; } = null!;

        public ListenerArgs()
        {
        }
    }

    public sealed class ListenerState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Input("defaultBackendSetName")]
        public Input<string>? DefaultBackendSetName { get; set; }

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId")]
        public Input<string>? NetworkLoadBalancerId { get; set; }

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
        /// </summary>
        [Input("protocol")]
        public Input<string>? Protocol { get; set; }

        public ListenerState()
        {
        }
    }
}
