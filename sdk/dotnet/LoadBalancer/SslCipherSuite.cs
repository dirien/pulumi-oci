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
    /// This resource provides the Ssl Cipher Suite resource in Oracle Cloud Infrastructure Load Balancer service.
    /// 
    /// Creates a custom SSL cipher suite.
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
    ///         var testSslCipherSuite = new Oci.LoadBalancer.SslCipherSuite("testSslCipherSuite", new Oci.LoadBalancer.SslCipherSuiteArgs
    ///         {
    ///             Ciphers = @var.Ssl_cipher_suite_ciphers,
    ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// SslCipherSuites can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:loadbalancer/sslCipherSuite:SslCipherSuite test_ssl_cipher_suite "loadBalancers/{loadBalancerId}/sslCipherSuites/{name}"
    /// ```
    /// </summary>
    [OciResourceType("oci:loadbalancer/sslCipherSuite:SslCipherSuite")]
    public partial class SslCipherSuite : Pulumi.CustomResource
    {
        /// <summary>
        /// A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        /// </summary>
        [Output("ciphers")]
        public Output<ImmutableArray<string>> Ciphers { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Output("loadBalancerId")]
        public Output<string> LoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a SslCipherSuite resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public SslCipherSuite(string name, SslCipherSuiteArgs args, CustomResourceOptions? options = null)
            : base("oci:loadbalancer/sslCipherSuite:SslCipherSuite", name, args ?? new SslCipherSuiteArgs(), MakeResourceOptions(options, ""))
        {
        }

        private SslCipherSuite(string name, Input<string> id, SslCipherSuiteState? state = null, CustomResourceOptions? options = null)
            : base("oci:loadbalancer/sslCipherSuite:SslCipherSuite", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing SslCipherSuite resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static SslCipherSuite Get(string name, Input<string> id, SslCipherSuiteState? state = null, CustomResourceOptions? options = null)
        {
            return new SslCipherSuite(name, id, state, options);
        }
    }

    public sealed class SslCipherSuiteArgs : Pulumi.ResourceArgs
    {
        [Input("ciphers", required: true)]
        private InputList<string>? _ciphers;

        /// <summary>
        /// A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        /// </summary>
        public InputList<string> Ciphers
        {
            get => _ciphers ?? (_ciphers = new InputList<string>());
            set => _ciphers = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        /// <summary>
        /// A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public SslCipherSuiteArgs()
        {
        }
    }

    public sealed class SslCipherSuiteState : Pulumi.ResourceArgs
    {
        [Input("ciphers")]
        private InputList<string>? _ciphers;

        /// <summary>
        /// A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        /// </summary>
        public InputList<string> Ciphers
        {
            get => _ciphers ?? (_ciphers = new InputList<string>());
            set => _ciphers = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        /// <summary>
        /// A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("state")]
        public Input<string>? State { get; set; }

        public SslCipherSuiteState()
        {
        }
    }
}
