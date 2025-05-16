// import { Construct } from 'constructs';
// import {
//     StackProps,
//     Stack,
//     DefaultStackSynthesizer,
// } from 'aws-cdk-lib';


// export interface CustomStackProps extends StackProps {
//     readonly projectName: string;
//     readonly gitRevision: string;
//     readonly baseDomain: string;
//     readonly appName: string;
//     readonly projectEnvironment?: string;
// }

// export class CustomStack extends Stack {
//     public readonly projectName: string;
//     public readonly gitRevision: string;
//     public readonly baseDomain: string;
//     public readonly appName: string;
//     public readonly projectEnvironment?: string;
//     public constructor(
//         scope: Construct,
//         props: CustomStackProps,
//         stackName: string,
//     ) {
//         const overriddenProps = Object.assign(
//             {
//                 synthesizer: new DefaultStackSynthesizer({
//                     generateBootstrapVersionRule: false,
//                 }),
//             },
//             props
//         );

//         super(scope, stackName, overriddenProps);

//         if (props.gitRevision === undefined) {
//             throw new Error('Git Revision must be provided');
//         }

//         this.gitRevision = props.gitRevision;
//         this.projectName = props.projectName;
//         this.projectEnvironment = props.projectEnvironment;
//         this.baseDomain = props.baseDomain;
//         this.appName = props.appName;

//         if (props.projectEnvironment) {
//             this.tags.setTag('Environment', props.projectEnvironment);
//         }

//         this.tags.setTag('Project', props.projectName);
//         this.tags.setTag('GitRevision', props.gitRevision);
//         this.tags.setTag('StackName', stackName);
//         this.tags.setTag('AppName', props.appName);

//     }
// }

// lib/stack.ts
import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface CustomStackProps extends StackProps {
  projectName: string;
}

export class CustomStack extends Stack {
  constructor(scope: Construct, props: CustomStackProps, id: string) {
    super(scope, id, props);
  }
}

