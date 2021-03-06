// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement
{
    public static class GetManagedInstance
    {
        /// <summary>
        /// This data source provides details about a specific Managed Instance resource in Oracle Cloud Infrastructure OS Management service.
        /// 
        /// Returns a specific Managed Instance.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testManagedInstance = Output.Create(Oci.OsManagement.GetManagedInstance.InvokeAsync(new Oci.OsManagement.GetManagedInstanceArgs
        ///         {
        ///             ManagedInstanceId = oci_osmanagement_managed_instance.Test_managed_instance.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedInstanceResult> InvokeAsync(GetManagedInstanceArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedInstanceResult>("oci:osmanagement/getManagedInstance:getManagedInstance", args ?? new GetManagedInstanceArgs(), options.WithVersion());
    }


    public sealed class GetManagedInstanceArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// OCID for the managed instance
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public string ManagedInstanceId { get; set; } = null!;

        public GetManagedInstanceArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetManagedInstanceResult
    {
        /// <summary>
        /// Number of bug fix type updates available to be installed
        /// </summary>
        public readonly int BugUpdatesAvailable;
        /// <summary>
        /// list of child Software Sources attached to the Managed Instance
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstanceChildSoftwareSourceResult> ChildSoftwareSources;
        /// <summary>
        /// OCID for the Compartment
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Information specified by the user about the managed instance
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// User friendly name
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Number of enhancement type updates available to be installed
        /// </summary>
        public readonly int EnhancementUpdatesAvailable;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether a reboot is required to complete installation of updates.
        /// </summary>
        public readonly bool IsRebootRequired;
        /// <summary>
        /// Time at which the instance last booted
        /// </summary>
        public readonly string LastBoot;
        /// <summary>
        /// Time at which the instance last checked in
        /// </summary>
        public readonly string LastCheckin;
        /// <summary>
        /// The ids of the managed instance groups of which this instance is a member.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstanceManagedInstanceGroupResult> ManagedInstanceGroups;
        public readonly string ManagedInstanceId;
        /// <summary>
        /// The Operating System type of the managed instance.
        /// </summary>
        public readonly string OsFamily;
        /// <summary>
        /// Operating System Kernel Version
        /// </summary>
        public readonly string OsKernelVersion;
        /// <summary>
        /// Operating System Name
        /// </summary>
        public readonly string OsName;
        /// <summary>
        /// Operating System Version
        /// </summary>
        public readonly string OsVersion;
        /// <summary>
        /// Number of non-classified updates available to be installed
        /// </summary>
        public readonly int OtherUpdatesAvailable;
        /// <summary>
        /// the parent (base) Software Source attached to the Managed Instance
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstanceParentSoftwareSourceResult> ParentSoftwareSources;
        /// <summary>
        /// Number of scheduled jobs associated with this instance
        /// </summary>
        public readonly int ScheduledJobCount;
        /// <summary>
        /// Number of security type updates available to be installed
        /// </summary>
        public readonly int SecurityUpdatesAvailable;
        /// <summary>
        /// status of the managed instance.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Number of updates available to be installed
        /// </summary>
        public readonly int UpdatesAvailable;
        /// <summary>
        /// Number of work requests associated with this instance
        /// </summary>
        public readonly int WorkRequestCount;

        [OutputConstructor]
        private GetManagedInstanceResult(
            int bugUpdatesAvailable,

            ImmutableArray<Outputs.GetManagedInstanceChildSoftwareSourceResult> childSoftwareSources,

            string compartmentId,

            string description,

            string displayName,

            int enhancementUpdatesAvailable,

            string id,

            bool isRebootRequired,

            string lastBoot,

            string lastCheckin,

            ImmutableArray<Outputs.GetManagedInstanceManagedInstanceGroupResult> managedInstanceGroups,

            string managedInstanceId,

            string osFamily,

            string osKernelVersion,

            string osName,

            string osVersion,

            int otherUpdatesAvailable,

            ImmutableArray<Outputs.GetManagedInstanceParentSoftwareSourceResult> parentSoftwareSources,

            int scheduledJobCount,

            int securityUpdatesAvailable,

            string status,

            int updatesAvailable,

            int workRequestCount)
        {
            BugUpdatesAvailable = bugUpdatesAvailable;
            ChildSoftwareSources = childSoftwareSources;
            CompartmentId = compartmentId;
            Description = description;
            DisplayName = displayName;
            EnhancementUpdatesAvailable = enhancementUpdatesAvailable;
            Id = id;
            IsRebootRequired = isRebootRequired;
            LastBoot = lastBoot;
            LastCheckin = lastCheckin;
            ManagedInstanceGroups = managedInstanceGroups;
            ManagedInstanceId = managedInstanceId;
            OsFamily = osFamily;
            OsKernelVersion = osKernelVersion;
            OsName = osName;
            OsVersion = osVersion;
            OtherUpdatesAvailable = otherUpdatesAvailable;
            ParentSoftwareSources = parentSoftwareSources;
            ScheduledJobCount = scheduledJobCount;
            SecurityUpdatesAvailable = securityUpdatesAvailable;
            Status = status;
            UpdatesAvailable = updatesAvailable;
            WorkRequestCount = workRequestCount;
        }
    }
}
