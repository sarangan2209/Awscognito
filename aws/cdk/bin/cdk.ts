#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { NetworkStack } from '../lib/network-stack';
import { FtpEc2Stack } from '../lib/ftp-ec2-stack';




const app = new cdk.App();

// new NetworkStack(app, {
//   projectName: 'ftp-server',
//   env: {
//     region: 'us-east-1',
//   },
// }, 'NetworkStack');


const AWS_ACCOUNT_ID = ''; 
const AWS_REGION = 'us-east-1';

new FtpEc2Stack(app, 'FtpEc2Stack', {
  env: {
    account: AWS_ACCOUNT_ID,
    region: AWS_REGION,
  },
});