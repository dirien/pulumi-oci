// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type DatabaseExadataInfrastructureStorage struct {
	pulumi.CustomResourceState

	ActivatedStorageCount    pulumi.IntOutput                                            `pulumi:"activatedStorageCount"`
	ActivationFile           pulumi.StringPtrOutput                                      `pulumi:"activationFile"`
	AdditionalStorageCount   pulumi.IntOutput                                            `pulumi:"additionalStorageCount"`
	AdminNetworkCidr         pulumi.StringOutput                                         `pulumi:"adminNetworkCidr"`
	CloudControlPlaneServer1 pulumi.StringOutput                                         `pulumi:"cloudControlPlaneServer1"`
	CloudControlPlaneServer2 pulumi.StringOutput                                         `pulumi:"cloudControlPlaneServer2"`
	CompartmentId            pulumi.StringOutput                                         `pulumi:"compartmentId"`
	ComputeCount             pulumi.IntOutput                                            `pulumi:"computeCount"`
	Contacts                 DatabaseExadataInfrastructureStorageContactArrayOutput      `pulumi:"contacts"`
	CorporateProxy           pulumi.StringOutput                                         `pulumi:"corporateProxy"`
	CpusEnabled              pulumi.IntOutput                                            `pulumi:"cpusEnabled"`
	CsiNumber                pulumi.StringOutput                                         `pulumi:"csiNumber"`
	DataStorageSizeInTbs     pulumi.Float64Output                                        `pulumi:"dataStorageSizeInTbs"`
	DbNodeStorageSizeInGbs   pulumi.IntOutput                                            `pulumi:"dbNodeStorageSizeInGbs"`
	DefinedTags              pulumi.MapOutput                                            `pulumi:"definedTags"`
	DisplayName              pulumi.StringOutput                                         `pulumi:"displayName"`
	DnsServers               pulumi.StringArrayOutput                                    `pulumi:"dnsServers"`
	ExadataInfrastructureId  pulumi.StringPtrOutput                                      `pulumi:"exadataInfrastructureId"`
	FreeformTags             pulumi.MapOutput                                            `pulumi:"freeformTags"`
	Gateway                  pulumi.StringOutput                                         `pulumi:"gateway"`
	InfiniBandNetworkCidr    pulumi.StringOutput                                         `pulumi:"infiniBandNetworkCidr"`
	LifecycleDetails         pulumi.StringOutput                                         `pulumi:"lifecycleDetails"`
	MaintenanceSloStatus     pulumi.StringOutput                                         `pulumi:"maintenanceSloStatus"`
	MaintenanceWindow        DatabaseExadataInfrastructureStorageMaintenanceWindowOutput `pulumi:"maintenanceWindow"`
	MaxCpuCount              pulumi.IntOutput                                            `pulumi:"maxCpuCount"`
	MaxDataStorageInTbs      pulumi.Float64Output                                        `pulumi:"maxDataStorageInTbs"`
	MaxDbNodeStorageInGbs    pulumi.IntOutput                                            `pulumi:"maxDbNodeStorageInGbs"`
	MaxMemoryInGbs           pulumi.IntOutput                                            `pulumi:"maxMemoryInGbs"`
	MemorySizeInGbs          pulumi.IntOutput                                            `pulumi:"memorySizeInGbs"`
	Netmask                  pulumi.StringOutput                                         `pulumi:"netmask"`
	NtpServers               pulumi.StringArrayOutput                                    `pulumi:"ntpServers"`
	Shape                    pulumi.StringOutput                                         `pulumi:"shape"`
	State                    pulumi.StringOutput                                         `pulumi:"state"`
	StorageCount             pulumi.IntOutput                                            `pulumi:"storageCount"`
	TimeCreated              pulumi.StringOutput                                         `pulumi:"timeCreated"`
	TimeZone                 pulumi.StringOutput                                         `pulumi:"timeZone"`
}

// NewDatabaseExadataInfrastructureStorage registers a new resource with the given unique name, arguments, and options.
func NewDatabaseExadataInfrastructureStorage(ctx *pulumi.Context,
	name string, args *DatabaseExadataInfrastructureStorageArgs, opts ...pulumi.ResourceOption) (*DatabaseExadataInfrastructureStorage, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AdminNetworkCidr == nil {
		return nil, errors.New("invalid value for required argument 'AdminNetworkCidr'")
	}
	if args.CloudControlPlaneServer1 == nil {
		return nil, errors.New("invalid value for required argument 'CloudControlPlaneServer1'")
	}
	if args.CloudControlPlaneServer2 == nil {
		return nil, errors.New("invalid value for required argument 'CloudControlPlaneServer2'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.DnsServers == nil {
		return nil, errors.New("invalid value for required argument 'DnsServers'")
	}
	if args.Gateway == nil {
		return nil, errors.New("invalid value for required argument 'Gateway'")
	}
	if args.InfiniBandNetworkCidr == nil {
		return nil, errors.New("invalid value for required argument 'InfiniBandNetworkCidr'")
	}
	if args.Netmask == nil {
		return nil, errors.New("invalid value for required argument 'Netmask'")
	}
	if args.NtpServers == nil {
		return nil, errors.New("invalid value for required argument 'NtpServers'")
	}
	if args.Shape == nil {
		return nil, errors.New("invalid value for required argument 'Shape'")
	}
	if args.TimeZone == nil {
		return nil, errors.New("invalid value for required argument 'TimeZone'")
	}
	var resource DatabaseExadataInfrastructureStorage
	err := ctx.RegisterResource("oci:index/databaseExadataInfrastructureStorage:DatabaseExadataInfrastructureStorage", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDatabaseExadataInfrastructureStorage gets an existing DatabaseExadataInfrastructureStorage resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDatabaseExadataInfrastructureStorage(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DatabaseExadataInfrastructureStorageState, opts ...pulumi.ResourceOption) (*DatabaseExadataInfrastructureStorage, error) {
	var resource DatabaseExadataInfrastructureStorage
	err := ctx.ReadResource("oci:index/databaseExadataInfrastructureStorage:DatabaseExadataInfrastructureStorage", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DatabaseExadataInfrastructureStorage resources.
type databaseExadataInfrastructureStorageState struct {
	ActivatedStorageCount    *int                                                   `pulumi:"activatedStorageCount"`
	ActivationFile           *string                                                `pulumi:"activationFile"`
	AdditionalStorageCount   *int                                                   `pulumi:"additionalStorageCount"`
	AdminNetworkCidr         *string                                                `pulumi:"adminNetworkCidr"`
	CloudControlPlaneServer1 *string                                                `pulumi:"cloudControlPlaneServer1"`
	CloudControlPlaneServer2 *string                                                `pulumi:"cloudControlPlaneServer2"`
	CompartmentId            *string                                                `pulumi:"compartmentId"`
	ComputeCount             *int                                                   `pulumi:"computeCount"`
	Contacts                 []DatabaseExadataInfrastructureStorageContact          `pulumi:"contacts"`
	CorporateProxy           *string                                                `pulumi:"corporateProxy"`
	CpusEnabled              *int                                                   `pulumi:"cpusEnabled"`
	CsiNumber                *string                                                `pulumi:"csiNumber"`
	DataStorageSizeInTbs     *float64                                               `pulumi:"dataStorageSizeInTbs"`
	DbNodeStorageSizeInGbs   *int                                                   `pulumi:"dbNodeStorageSizeInGbs"`
	DefinedTags              map[string]interface{}                                 `pulumi:"definedTags"`
	DisplayName              *string                                                `pulumi:"displayName"`
	DnsServers               []string                                               `pulumi:"dnsServers"`
	ExadataInfrastructureId  *string                                                `pulumi:"exadataInfrastructureId"`
	FreeformTags             map[string]interface{}                                 `pulumi:"freeformTags"`
	Gateway                  *string                                                `pulumi:"gateway"`
	InfiniBandNetworkCidr    *string                                                `pulumi:"infiniBandNetworkCidr"`
	LifecycleDetails         *string                                                `pulumi:"lifecycleDetails"`
	MaintenanceSloStatus     *string                                                `pulumi:"maintenanceSloStatus"`
	MaintenanceWindow        *DatabaseExadataInfrastructureStorageMaintenanceWindow `pulumi:"maintenanceWindow"`
	MaxCpuCount              *int                                                   `pulumi:"maxCpuCount"`
	MaxDataStorageInTbs      *float64                                               `pulumi:"maxDataStorageInTbs"`
	MaxDbNodeStorageInGbs    *int                                                   `pulumi:"maxDbNodeStorageInGbs"`
	MaxMemoryInGbs           *int                                                   `pulumi:"maxMemoryInGbs"`
	MemorySizeInGbs          *int                                                   `pulumi:"memorySizeInGbs"`
	Netmask                  *string                                                `pulumi:"netmask"`
	NtpServers               []string                                               `pulumi:"ntpServers"`
	Shape                    *string                                                `pulumi:"shape"`
	State                    *string                                                `pulumi:"state"`
	StorageCount             *int                                                   `pulumi:"storageCount"`
	TimeCreated              *string                                                `pulumi:"timeCreated"`
	TimeZone                 *string                                                `pulumi:"timeZone"`
}

type DatabaseExadataInfrastructureStorageState struct {
	ActivatedStorageCount    pulumi.IntPtrInput
	ActivationFile           pulumi.StringPtrInput
	AdditionalStorageCount   pulumi.IntPtrInput
	AdminNetworkCidr         pulumi.StringPtrInput
	CloudControlPlaneServer1 pulumi.StringPtrInput
	CloudControlPlaneServer2 pulumi.StringPtrInput
	CompartmentId            pulumi.StringPtrInput
	ComputeCount             pulumi.IntPtrInput
	Contacts                 DatabaseExadataInfrastructureStorageContactArrayInput
	CorporateProxy           pulumi.StringPtrInput
	CpusEnabled              pulumi.IntPtrInput
	CsiNumber                pulumi.StringPtrInput
	DataStorageSizeInTbs     pulumi.Float64PtrInput
	DbNodeStorageSizeInGbs   pulumi.IntPtrInput
	DefinedTags              pulumi.MapInput
	DisplayName              pulumi.StringPtrInput
	DnsServers               pulumi.StringArrayInput
	ExadataInfrastructureId  pulumi.StringPtrInput
	FreeformTags             pulumi.MapInput
	Gateway                  pulumi.StringPtrInput
	InfiniBandNetworkCidr    pulumi.StringPtrInput
	LifecycleDetails         pulumi.StringPtrInput
	MaintenanceSloStatus     pulumi.StringPtrInput
	MaintenanceWindow        DatabaseExadataInfrastructureStorageMaintenanceWindowPtrInput
	MaxCpuCount              pulumi.IntPtrInput
	MaxDataStorageInTbs      pulumi.Float64PtrInput
	MaxDbNodeStorageInGbs    pulumi.IntPtrInput
	MaxMemoryInGbs           pulumi.IntPtrInput
	MemorySizeInGbs          pulumi.IntPtrInput
	Netmask                  pulumi.StringPtrInput
	NtpServers               pulumi.StringArrayInput
	Shape                    pulumi.StringPtrInput
	State                    pulumi.StringPtrInput
	StorageCount             pulumi.IntPtrInput
	TimeCreated              pulumi.StringPtrInput
	TimeZone                 pulumi.StringPtrInput
}

func (DatabaseExadataInfrastructureStorageState) ElementType() reflect.Type {
	return reflect.TypeOf((*databaseExadataInfrastructureStorageState)(nil)).Elem()
}

type databaseExadataInfrastructureStorageArgs struct {
	ActivationFile           *string                                                `pulumi:"activationFile"`
	AdminNetworkCidr         string                                                 `pulumi:"adminNetworkCidr"`
	CloudControlPlaneServer1 string                                                 `pulumi:"cloudControlPlaneServer1"`
	CloudControlPlaneServer2 string                                                 `pulumi:"cloudControlPlaneServer2"`
	CompartmentId            string                                                 `pulumi:"compartmentId"`
	ComputeCount             *int                                                   `pulumi:"computeCount"`
	Contacts                 []DatabaseExadataInfrastructureStorageContact          `pulumi:"contacts"`
	CorporateProxy           *string                                                `pulumi:"corporateProxy"`
	DefinedTags              map[string]interface{}                                 `pulumi:"definedTags"`
	DisplayName              string                                                 `pulumi:"displayName"`
	DnsServers               []string                                               `pulumi:"dnsServers"`
	ExadataInfrastructureId  *string                                                `pulumi:"exadataInfrastructureId"`
	FreeformTags             map[string]interface{}                                 `pulumi:"freeformTags"`
	Gateway                  string                                                 `pulumi:"gateway"`
	InfiniBandNetworkCidr    string                                                 `pulumi:"infiniBandNetworkCidr"`
	MaintenanceWindow        *DatabaseExadataInfrastructureStorageMaintenanceWindow `pulumi:"maintenanceWindow"`
	Netmask                  string                                                 `pulumi:"netmask"`
	NtpServers               []string                                               `pulumi:"ntpServers"`
	Shape                    string                                                 `pulumi:"shape"`
	StorageCount             *int                                                   `pulumi:"storageCount"`
	TimeZone                 string                                                 `pulumi:"timeZone"`
}

// The set of arguments for constructing a DatabaseExadataInfrastructureStorage resource.
type DatabaseExadataInfrastructureStorageArgs struct {
	ActivationFile           pulumi.StringPtrInput
	AdminNetworkCidr         pulumi.StringInput
	CloudControlPlaneServer1 pulumi.StringInput
	CloudControlPlaneServer2 pulumi.StringInput
	CompartmentId            pulumi.StringInput
	ComputeCount             pulumi.IntPtrInput
	Contacts                 DatabaseExadataInfrastructureStorageContactArrayInput
	CorporateProxy           pulumi.StringPtrInput
	DefinedTags              pulumi.MapInput
	DisplayName              pulumi.StringInput
	DnsServers               pulumi.StringArrayInput
	ExadataInfrastructureId  pulumi.StringPtrInput
	FreeformTags             pulumi.MapInput
	Gateway                  pulumi.StringInput
	InfiniBandNetworkCidr    pulumi.StringInput
	MaintenanceWindow        DatabaseExadataInfrastructureStorageMaintenanceWindowPtrInput
	Netmask                  pulumi.StringInput
	NtpServers               pulumi.StringArrayInput
	Shape                    pulumi.StringInput
	StorageCount             pulumi.IntPtrInput
	TimeZone                 pulumi.StringInput
}

func (DatabaseExadataInfrastructureStorageArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*databaseExadataInfrastructureStorageArgs)(nil)).Elem()
}

type DatabaseExadataInfrastructureStorageInput interface {
	pulumi.Input

	ToDatabaseExadataInfrastructureStorageOutput() DatabaseExadataInfrastructureStorageOutput
	ToDatabaseExadataInfrastructureStorageOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStorageOutput
}

func (*DatabaseExadataInfrastructureStorage) ElementType() reflect.Type {
	return reflect.TypeOf((*DatabaseExadataInfrastructureStorage)(nil))
}

func (i *DatabaseExadataInfrastructureStorage) ToDatabaseExadataInfrastructureStorageOutput() DatabaseExadataInfrastructureStorageOutput {
	return i.ToDatabaseExadataInfrastructureStorageOutputWithContext(context.Background())
}

func (i *DatabaseExadataInfrastructureStorage) ToDatabaseExadataInfrastructureStorageOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStorageOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseExadataInfrastructureStorageOutput)
}

func (i *DatabaseExadataInfrastructureStorage) ToDatabaseExadataInfrastructureStoragePtrOutput() DatabaseExadataInfrastructureStoragePtrOutput {
	return i.ToDatabaseExadataInfrastructureStoragePtrOutputWithContext(context.Background())
}

func (i *DatabaseExadataInfrastructureStorage) ToDatabaseExadataInfrastructureStoragePtrOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStoragePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseExadataInfrastructureStoragePtrOutput)
}

type DatabaseExadataInfrastructureStoragePtrInput interface {
	pulumi.Input

	ToDatabaseExadataInfrastructureStoragePtrOutput() DatabaseExadataInfrastructureStoragePtrOutput
	ToDatabaseExadataInfrastructureStoragePtrOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStoragePtrOutput
}

type databaseExadataInfrastructureStoragePtrType DatabaseExadataInfrastructureStorageArgs

func (*databaseExadataInfrastructureStoragePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabaseExadataInfrastructureStorage)(nil))
}

func (i *databaseExadataInfrastructureStoragePtrType) ToDatabaseExadataInfrastructureStoragePtrOutput() DatabaseExadataInfrastructureStoragePtrOutput {
	return i.ToDatabaseExadataInfrastructureStoragePtrOutputWithContext(context.Background())
}

func (i *databaseExadataInfrastructureStoragePtrType) ToDatabaseExadataInfrastructureStoragePtrOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStoragePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseExadataInfrastructureStoragePtrOutput)
}

// DatabaseExadataInfrastructureStorageArrayInput is an input type that accepts DatabaseExadataInfrastructureStorageArray and DatabaseExadataInfrastructureStorageArrayOutput values.
// You can construct a concrete instance of `DatabaseExadataInfrastructureStorageArrayInput` via:
//
//          DatabaseExadataInfrastructureStorageArray{ DatabaseExadataInfrastructureStorageArgs{...} }
type DatabaseExadataInfrastructureStorageArrayInput interface {
	pulumi.Input

	ToDatabaseExadataInfrastructureStorageArrayOutput() DatabaseExadataInfrastructureStorageArrayOutput
	ToDatabaseExadataInfrastructureStorageArrayOutputWithContext(context.Context) DatabaseExadataInfrastructureStorageArrayOutput
}

type DatabaseExadataInfrastructureStorageArray []DatabaseExadataInfrastructureStorageInput

func (DatabaseExadataInfrastructureStorageArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DatabaseExadataInfrastructureStorage)(nil)).Elem()
}

func (i DatabaseExadataInfrastructureStorageArray) ToDatabaseExadataInfrastructureStorageArrayOutput() DatabaseExadataInfrastructureStorageArrayOutput {
	return i.ToDatabaseExadataInfrastructureStorageArrayOutputWithContext(context.Background())
}

func (i DatabaseExadataInfrastructureStorageArray) ToDatabaseExadataInfrastructureStorageArrayOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStorageArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseExadataInfrastructureStorageArrayOutput)
}

// DatabaseExadataInfrastructureStorageMapInput is an input type that accepts DatabaseExadataInfrastructureStorageMap and DatabaseExadataInfrastructureStorageMapOutput values.
// You can construct a concrete instance of `DatabaseExadataInfrastructureStorageMapInput` via:
//
//          DatabaseExadataInfrastructureStorageMap{ "key": DatabaseExadataInfrastructureStorageArgs{...} }
type DatabaseExadataInfrastructureStorageMapInput interface {
	pulumi.Input

	ToDatabaseExadataInfrastructureStorageMapOutput() DatabaseExadataInfrastructureStorageMapOutput
	ToDatabaseExadataInfrastructureStorageMapOutputWithContext(context.Context) DatabaseExadataInfrastructureStorageMapOutput
}

type DatabaseExadataInfrastructureStorageMap map[string]DatabaseExadataInfrastructureStorageInput

func (DatabaseExadataInfrastructureStorageMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DatabaseExadataInfrastructureStorage)(nil)).Elem()
}

func (i DatabaseExadataInfrastructureStorageMap) ToDatabaseExadataInfrastructureStorageMapOutput() DatabaseExadataInfrastructureStorageMapOutput {
	return i.ToDatabaseExadataInfrastructureStorageMapOutputWithContext(context.Background())
}

func (i DatabaseExadataInfrastructureStorageMap) ToDatabaseExadataInfrastructureStorageMapOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStorageMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseExadataInfrastructureStorageMapOutput)
}

type DatabaseExadataInfrastructureStorageOutput struct {
	*pulumi.OutputState
}

func (DatabaseExadataInfrastructureStorageOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DatabaseExadataInfrastructureStorage)(nil))
}

func (o DatabaseExadataInfrastructureStorageOutput) ToDatabaseExadataInfrastructureStorageOutput() DatabaseExadataInfrastructureStorageOutput {
	return o
}

func (o DatabaseExadataInfrastructureStorageOutput) ToDatabaseExadataInfrastructureStorageOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStorageOutput {
	return o
}

func (o DatabaseExadataInfrastructureStorageOutput) ToDatabaseExadataInfrastructureStoragePtrOutput() DatabaseExadataInfrastructureStoragePtrOutput {
	return o.ToDatabaseExadataInfrastructureStoragePtrOutputWithContext(context.Background())
}

func (o DatabaseExadataInfrastructureStorageOutput) ToDatabaseExadataInfrastructureStoragePtrOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStoragePtrOutput {
	return o.ApplyT(func(v DatabaseExadataInfrastructureStorage) *DatabaseExadataInfrastructureStorage {
		return &v
	}).(DatabaseExadataInfrastructureStoragePtrOutput)
}

type DatabaseExadataInfrastructureStoragePtrOutput struct {
	*pulumi.OutputState
}

func (DatabaseExadataInfrastructureStoragePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabaseExadataInfrastructureStorage)(nil))
}

func (o DatabaseExadataInfrastructureStoragePtrOutput) ToDatabaseExadataInfrastructureStoragePtrOutput() DatabaseExadataInfrastructureStoragePtrOutput {
	return o
}

func (o DatabaseExadataInfrastructureStoragePtrOutput) ToDatabaseExadataInfrastructureStoragePtrOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStoragePtrOutput {
	return o
}

type DatabaseExadataInfrastructureStorageArrayOutput struct{ *pulumi.OutputState }

func (DatabaseExadataInfrastructureStorageArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DatabaseExadataInfrastructureStorage)(nil))
}

func (o DatabaseExadataInfrastructureStorageArrayOutput) ToDatabaseExadataInfrastructureStorageArrayOutput() DatabaseExadataInfrastructureStorageArrayOutput {
	return o
}

func (o DatabaseExadataInfrastructureStorageArrayOutput) ToDatabaseExadataInfrastructureStorageArrayOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStorageArrayOutput {
	return o
}

func (o DatabaseExadataInfrastructureStorageArrayOutput) Index(i pulumi.IntInput) DatabaseExadataInfrastructureStorageOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DatabaseExadataInfrastructureStorage {
		return vs[0].([]DatabaseExadataInfrastructureStorage)[vs[1].(int)]
	}).(DatabaseExadataInfrastructureStorageOutput)
}

type DatabaseExadataInfrastructureStorageMapOutput struct{ *pulumi.OutputState }

func (DatabaseExadataInfrastructureStorageMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DatabaseExadataInfrastructureStorage)(nil))
}

func (o DatabaseExadataInfrastructureStorageMapOutput) ToDatabaseExadataInfrastructureStorageMapOutput() DatabaseExadataInfrastructureStorageMapOutput {
	return o
}

func (o DatabaseExadataInfrastructureStorageMapOutput) ToDatabaseExadataInfrastructureStorageMapOutputWithContext(ctx context.Context) DatabaseExadataInfrastructureStorageMapOutput {
	return o
}

func (o DatabaseExadataInfrastructureStorageMapOutput) MapIndex(k pulumi.StringInput) DatabaseExadataInfrastructureStorageOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DatabaseExadataInfrastructureStorage {
		return vs[0].(map[string]DatabaseExadataInfrastructureStorage)[vs[1].(string)]
	}).(DatabaseExadataInfrastructureStorageOutput)
}

func init() {
	pulumi.RegisterOutputType(DatabaseExadataInfrastructureStorageOutput{})
	pulumi.RegisterOutputType(DatabaseExadataInfrastructureStoragePtrOutput{})
	pulumi.RegisterOutputType(DatabaseExadataInfrastructureStorageArrayOutput{})
	pulumi.RegisterOutputType(DatabaseExadataInfrastructureStorageMapOutput{})
}
