import * as cdk from 'aws-cdk-lib';
import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as transfer from 'aws-cdk-lib/aws-transfer';
import * as fs from 'fs';
import * as path from 'path';

interface SftpTransferStackProps extends StackProps {
  userName: string;
  publicKeyPath: string;
}

export class SftpTransferStack extends Stack {
  constructor(scope: Construct, id: string, props: SftpTransferStackProps) {
    super(scope, id, props);

    const { userName, publicKeyPath } = props;

    // 1. S3 bucket for SFTP storage
    const bucket = new s3.Bucket(this, 'SftpBucket', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // 2. IAM role for SFTP to access S3
    const transferRole = new iam.Role(this, 'TransferAccessRole', {
      assumedBy: new iam.ServicePrincipal('transfer.amazonaws.com'),
    });

    transferRole.addToPolicy(new iam.PolicyStatement({
      actions: ['s3:ListBucket', 's3:GetBucketLocation'],
      resources: [bucket.bucketArn],
    }));

    transferRole.addToPolicy(new iam.PolicyStatement({
      actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
      resources: [`${bucket.bucketArn}/*`],
    }));

    // 3. Create Transfer Family SFTP server
    const sftpServer = new transfer.CfnServer(this, 'SftpServer', {
      endpointType: 'PUBLIC',
      identityProviderType: 'SERVICE_MANAGED',
      protocols: ['SFTP'],
    });

    // 4. Read SSH public key
    const fullPath = path.resolve(publicKeyPath);
    const publicKey = fs.readFileSync(fullPath, 'utf8');

    // 5. Create SFTP user
    new transfer.CfnUser(this, 'SftpUser', {
      serverId: sftpServer.attrServerId,
      userName,
      role: transferRole.roleArn,
      homeDirectory: `/${bucket.bucketName}`,
      sshPublicKeys: [publicKey],
    });

    // 6. Output SFTP endpoint
    new cdk.CfnOutput(this, 'SftpEndpoint', {
        value: cdk.Fn.join('', [
          's-', sftpServer.ref,
          `.server.transfer.${cdk.Stack.of(this).region}.amazonaws.com`
        ]),
      });
  }
}
