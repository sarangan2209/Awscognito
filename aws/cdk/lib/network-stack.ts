import { Construct } from 'constructs';
import { Vpc, SubnetType, IpAddresses, IIpAddresses } from 'aws-cdk-lib/aws-ec2';
import { CustomStack, CustomStackProps } from './stack';
export class NetworkStack extends CustomStack {
    constructor(scope: Construct, props: CustomStackProps, stackName: string) {
        super(scope, props, stackName);
        new VPC(this, props, stackName);
    }
}
export class VPC extends Construct {
    constructor(
        scope: CustomStack, props: CustomStackProps, stackName: string
    ) {
        super(scope, stackName);
        /**
         * properties for VPC
        */
        const ipAddresses: IIpAddresses = IpAddresses.cidr('10.0.0.0/21')
        const maxAzs = 2
        const cidrMask = 24
        /**
         * Creating a new VPC
        */
        new Vpc(this, `${props.projectName}`, {
            vpcName: 'ftp-test',
            ipAddresses: ipAddresses,
            maxAzs: maxAzs,
            enableDnsHostnames: true,
            enableDnsSupport: true,
            natGateways: 1,
            subnetConfiguration: [
                {
                    name: `${props.projectName}-private-`,
                    subnetType: SubnetType.PRIVATE_WITH_EGRESS,
                    cidrMask: cidrMask,
                },
                {
                    name: `${props.projectName}-public-`,
                    subnetType: SubnetType.PUBLIC,
                    cidrMask: cidrMask,
                    mapPublicIpOnLaunch: true
                },
            ],
        });
    }
}