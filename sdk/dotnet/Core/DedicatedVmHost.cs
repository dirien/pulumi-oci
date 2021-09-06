// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
    /// This resource provides the Dedicated Vm Host resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Creates a new dedicated virtual machine host in the specified compartment and the specified availability domain.
    /// Dedicated virtual machine hosts enable you to run your Compute virtual machine (VM) instances on dedicated servers
    /// that are a single tenant and not shared with other customers.
    /// For more information, see [Dedicated Virtual Machine Hosts](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/dedicatedvmhosts.htm).
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
    ///         var testDedicatedVmHost = new Oci.Core.DedicatedVmHost("testDedicatedVmHost", new Oci.Core.DedicatedVmHostArgs
    ///         {
    ///             AvailabilityDomain = @var.Dedicated_vm_host_availability_domain,
    ///             CompartmentId = @var.Compartment_id,
    ///             DedicatedVmHostShape = @var.Dedicated_vm_host_dedicated_vm_host_shape,
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             DisplayName = @var.Dedicated_vm_host_display_name,
    ///             FaultDomain = @var.Dedicated_vm_host_fault_domain,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// DedicatedVmHosts can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:core/dedicatedVmHost:DedicatedVmHost test_dedicated_vm_host "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:core/dedicatedVmHost:DedicatedVmHost")]
    public partial class DedicatedVmHost : Pulumi.CustomResource
    {
        /// <summary>
        /// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Output("availabilityDomain")]
        public Output<string> AvailabilityDomain { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
        /// </summary>
        [Output("dedicatedVmHostShape")]
        public Output<string> DedicatedVmHostShape { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My dedicated VM host`
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
        /// </summary>
        [Output("faultDomain")]
        public Output<string> FaultDomain { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The current available memory of the dedicated VM host, in GBs.
        /// </summary>
        [Output("remainingMemoryInGbs")]
        public Output<double> RemainingMemoryInGbs { get; private set; } = null!;

        /// <summary>
        /// The current available OCPUs of the dedicated VM host.
        /// </summary>
        [Output("remainingOcpus")]
        public Output<double> RemainingOcpus { get; private set; } = null!;

        /// <summary>
        /// The current state of the dedicated VM host.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The current total memory of the dedicated VM host, in GBs.
        /// </summary>
        [Output("totalMemoryInGbs")]
        public Output<double> TotalMemoryInGbs { get; private set; } = null!;

        /// <summary>
        /// The current total OCPUs of the dedicated VM host.
        /// </summary>
        [Output("totalOcpus")]
        public Output<double> TotalOcpus { get; private set; } = null!;


        /// <summary>
        /// Create a DedicatedVmHost resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DedicatedVmHost(string name, DedicatedVmHostArgs args, CustomResourceOptions? options = null)
            : base("oci:core/dedicatedVmHost:DedicatedVmHost", name, args ?? new DedicatedVmHostArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DedicatedVmHost(string name, Input<string> id, DedicatedVmHostState? state = null, CustomResourceOptions? options = null)
            : base("oci:core/dedicatedVmHost:DedicatedVmHost", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DedicatedVmHost resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DedicatedVmHost Get(string name, Input<string> id, DedicatedVmHostState? state = null, CustomResourceOptions? options = null)
        {
            return new DedicatedVmHost(name, id, state, options);
        }
    }

    public sealed class DedicatedVmHostArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
        /// </summary>
        [Input("dedicatedVmHostShape", required: true)]
        public Input<string> DedicatedVmHostShape { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My dedicated VM host`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
        /// </summary>
        [Input("faultDomain")]
        public Input<string>? FaultDomain { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        public DedicatedVmHostArgs()
        {
        }
    }

    public sealed class DedicatedVmHostState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
        /// </summary>
        [Input("dedicatedVmHostShape")]
        public Input<string>? DedicatedVmHostShape { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My dedicated VM host`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
        /// </summary>
        [Input("faultDomain")]
        public Input<string>? FaultDomain { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The current available memory of the dedicated VM host, in GBs.
        /// </summary>
        [Input("remainingMemoryInGbs")]
        public Input<double>? RemainingMemoryInGbs { get; set; }

        /// <summary>
        /// The current available OCPUs of the dedicated VM host.
        /// </summary>
        [Input("remainingOcpus")]
        public Input<double>? RemainingOcpus { get; set; }

        /// <summary>
        /// The current state of the dedicated VM host.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The current total memory of the dedicated VM host, in GBs.
        /// </summary>
        [Input("totalMemoryInGbs")]
        public Input<double>? TotalMemoryInGbs { get; set; }

        /// <summary>
        /// The current total OCPUs of the dedicated VM host.
        /// </summary>
        [Input("totalOcpus")]
        public Input<double>? TotalOcpus { get; set; }

        public DedicatedVmHostState()
        {
        }
    }
}
