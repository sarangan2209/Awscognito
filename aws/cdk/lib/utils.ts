import { IVpc, Vpc } from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

export class Utils {
    static getVpc(vpcName: string, scope: Construct): IVpc {
        const vpc = Vpc.fromLookup(scope, 'ImportedVPC', {
            vpcName: vpcName,
        });
        return vpc;
    }
}
