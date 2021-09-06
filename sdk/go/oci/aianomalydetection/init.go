// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package aianomalydetection

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi-oci/sdk/go/oci"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type module struct {
	version semver.Version
}

func (m *module) Version() semver.Version {
	return m.version
}

func (m *module) Construct(ctx *pulumi.Context, name, typ, urn string) (r pulumi.Resource, err error) {
	switch typ {
	case "oci:aianomalydetection/aiPrivateEndpoint:AiPrivateEndpoint":
		r = &AiPrivateEndpoint{}
	case "oci:aianomalydetection/dataAsset:DataAsset":
		r = &DataAsset{}
	case "oci:aianomalydetection/model:Model":
		r = &Model{}
	case "oci:aianomalydetection/project:Project":
		r = &Project{}
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	err = ctx.RegisterResource(typ, name, nil, r, pulumi.URN_(urn))
	return
}

func init() {
	version, err := oci.PkgVersion()
	if err != nil {
		fmt.Printf("failed to determine package version. defaulting to v1: %v\n", err)
	}
	pulumi.RegisterResourceModule(
		"oci",
		"aianomalydetection/aiPrivateEndpoint",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"aianomalydetection/dataAsset",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"aianomalydetection/model",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"aianomalydetection/project",
		&module{version},
	)
}
