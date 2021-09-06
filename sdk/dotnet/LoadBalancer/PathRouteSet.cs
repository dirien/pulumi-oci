// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    /// <summary>
    /// This resource provides the Path Route Set resource in Oracle Cloud Infrastructure Load Balancer service.
    /// 
    /// Adds a path route set to a load balancer. For more information, see
    /// [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).
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
    ///         var testPathRouteSet = new Oci.LoadBalancer.PathRouteSet("testPathRouteSet", new Oci.LoadBalancer.PathRouteSetArgs
    ///         {
    ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
    ///             PathRoutes = 
    ///             {
    ///                 new Oci.LoadBalancer.Inputs.PathRouteSetPathRouteArgs
    ///                 {
    ///                     BackendSetName = oci_load_balancer_backend_set.Test_backend_set.Name,
    ///                     Path = @var.Path_route_set_path_routes_path,
    ///                     PathMatchType = new Oci.LoadBalancer.Inputs.PathRouteSetPathRoutePathMatchTypeArgs
    ///                     {
    ///                         MatchType = @var.Path_route_set_path_routes_path_match_type_match_type,
    ///                     },
    ///                 },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// PathRouteSets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:loadbalancer/pathRouteSet:PathRouteSet test_path_route_set "loadBalancers/{loadBalancerId}/pathRouteSets/{pathRouteSetName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:loadbalancer/pathRouteSet:PathRouteSet")]
    public partial class PathRouteSet : Pulumi.CustomResource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        /// </summary>
        [Output("loadBalancerId")]
        public Output<string> LoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The set of path route rules.
        /// </summary>
        [Output("pathRoutes")]
        public Output<ImmutableArray<Outputs.PathRouteSetPathRoute>> PathRoutes { get; private set; } = null!;

        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a PathRouteSet resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PathRouteSet(string name, PathRouteSetArgs args, CustomResourceOptions? options = null)
            : base("oci:loadbalancer/pathRouteSet:PathRouteSet", name, args ?? new PathRouteSetArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PathRouteSet(string name, Input<string> id, PathRouteSetState? state = null, CustomResourceOptions? options = null)
            : base("oci:loadbalancer/pathRouteSet:PathRouteSet", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PathRouteSet resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PathRouteSet Get(string name, Input<string> id, PathRouteSetState? state = null, CustomResourceOptions? options = null)
        {
            return new PathRouteSet(name, id, state, options);
        }
    }

    public sealed class PathRouteSetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("pathRoutes", required: true)]
        private InputList<Inputs.PathRouteSetPathRouteArgs>? _pathRoutes;

        /// <summary>
        /// (Updatable) The set of path route rules.
        /// </summary>
        public InputList<Inputs.PathRouteSetPathRouteArgs> PathRoutes
        {
            get => _pathRoutes ?? (_pathRoutes = new InputList<Inputs.PathRouteSetPathRouteArgs>());
            set => _pathRoutes = value;
        }

        public PathRouteSetArgs()
        {
        }
    }

    public sealed class PathRouteSetState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        /// <summary>
        /// The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("pathRoutes")]
        private InputList<Inputs.PathRouteSetPathRouteGetArgs>? _pathRoutes;

        /// <summary>
        /// (Updatable) The set of path route rules.
        /// </summary>
        public InputList<Inputs.PathRouteSetPathRouteGetArgs> PathRoutes
        {
            get => _pathRoutes ?? (_pathRoutes = new InputList<Inputs.PathRouteSetPathRouteGetArgs>());
            set => _pathRoutes = value;
        }

        [Input("state")]
        public Input<string>? State { get; set; }

        public PathRouteSetState()
        {
        }
    }
}
