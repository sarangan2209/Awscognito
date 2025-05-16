import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import {
  Instance,
  InstanceType,
  InstanceClass,
  InstanceSize,
  MachineImage,
  SecurityGroup,
  Peer,
  Port,
  Vpc,
} from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

export class FtpEc2Stack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const vpc = Vpc.fromLookup(this, 'ExistingVPC', {
      vpcName: 'ftp-test',  
    });

    const sg = new SecurityGroup(this, 'FtpSg', {
      vpc,
      description: 'Allow FTP and SSH',
      allowAllOutbound: true,
    });

    sg.addIngressRule(Peer.anyIpv4(), Port.tcp(22), 'Allow SSH');
    sg.addIngressRule(Peer.anyIpv4(), Port.tcp(20), 'FTP Data');
    sg.addIngressRule(Peer.anyIpv4(), Port.tcp(21), 'FTP Control');
    sg.addIngressRule(Peer.anyIpv4(), Port.tcpRange(1024, 1048), 'FTP Passive Ports');

    const ami = MachineImage.genericLinux({
      'us-east-1': 'ami-084568db4383264d4', 
    });

    const publicSubnets = vpc.selectSubnets({ subnetType: ec2.SubnetType.PUBLIC });


    const instance = new Instance(this, 'FtpInstance', {
    vpc,
    vpcSubnets: publicSubnets,
    instanceType: InstanceType.of(InstanceClass.T3, InstanceSize.MICRO),
    machineImage: ami,
    securityGroup: sg,
    keyName: 'key-pair-test',
    });

    instance.addUserData(
      `#!/bin/bash
      apt update -y
      apt install vsftpd -y
      useradd -m ftpuser
      echo 'ftpuser:YourPassword123' | chpasswd
      mkdir -p /home/ftpuser/uploads
      chown ftpuser:ftpuser /home/ftpuser/uploads
      chmod 755 /home/ftpuser
      echo "listen=YES" >> /etc/vsftpd.conf
      echo "listen_ipv6=NO" >> /etc/vsftpd.conf
      echo "anonymous_enable=NO" >> /etc/vsftpd.conf
      echo "local_enable=YES" >> /etc/vsftpd.conf
      echo "write_enable=YES" >> /etc/vsftpd.conf
      echo "chroot_local_user=YES" >> /etc/vsftpd.conf
      echo "allow_writeable_chroot=YES" >> /etc/vsftpd.conf
      echo "pasv_enable=YES" >> /etc/vsftpd.conf
      echo "pasv_min_port=1024" >> /etc/vsftpd.conf
      echo "pasv_max_port=1048" >> /etc/vsftpd.conf
      echo "pasv_address=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)" >> /etc/vsftpd.conf
      systemctl restart vsftpd
      `
    );

    new cdk.CfnOutput(this, 'PublicIP', {
        value: instance.instancePublicIp ?? 'Public IP not assigned',
      });
  }
}
