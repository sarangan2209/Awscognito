<?php

namespace App\Services;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Support\Facades\Log;

class CognitoAuthService
{
    protected $client;

    public function __construct()
    {

        $this->clientId = env('AWS_COGNITO_CLIENT_ID');

        $this->client = new CognitoIdentityProviderClient([
            'region' => env('AWS_COGNITO_REGION', 'ap-south-1'),
            'version' => 'latest',
            'credentials' => [
                'key' => env('AWS_ACCESS_KEY_ID'),
                'secret' => env('AWS_SECRET_ACCESS_KEY'),
            ],
        ]);
    }

    public function register($name, $email, $password)
    {
        try {
            $clientId = env('AWS_COGNITO_CLIENT_ID');
            $clientSecret = env('AWS_COGNITO_CLIENT_SECRET');

            $response = $this->client->signUp([
                'ClientId' => $clientId,
                'SecretHash' => $this->calculateSecretHash($email, $clientId, $clientSecret),
                'Username' => $email,
                'Password' => $password,
                'UserAttributes' => [
                    ['Name' => 'name', 'Value' => $name],
                    ['Name' => 'email', 'Value' => $email],
                ],
            ]);

            return $response;
        } catch (\Exception $e) {
            Log::error('Cognito Registration Error: '.$e->getMessage());

            return ['error' => $e->getMessage()];
        }
    }

    private function calculateSecretHash($username, $clientId, $clientSecret)
    {
        return base64_encode(
            hash_hmac('sha256', $username.$clientId, $clientSecret, true)
        );
    }

    public function confirmSignUp($email, $confirmationCode)
    {
        try {
            $clientId = $this->clientId;
            $clientSecret = env('AWS_COGNITO_CLIENT_SECRET');
            $secretHash = $this->calculateSecretHash($email, $clientId, $clientSecret);

            $response = $this->client->confirmSignUp([
                'ClientId' => $clientId,
                'Username' => $email,
                'ConfirmationCode' => $confirmationCode,
                'SecretHash' => $secretHash,
            ]);

            return ['success' => true, 'message' => 'User confirmed successfully.'];
        } catch (\Exception $e) {
            Log::error('Cognito Confirm SignUp Error: '.$e->getMessage());

            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    public function loginUser(string $email, string $password): array
    {
        try {
            $clientId = $this->clientId;
            $clientSecret = env('AWS_COGNITO_CLIENT_SECRET');
            $secretHash = $this->calculateSecretHash($email, $clientId, $clientSecret);
            $result = $this->client->initiateAuth([
                'AuthFlow' => 'USER_PASSWORD_AUTH',
                'ClientId' => $clientId,
                'AuthParameters' => [
                    'USERNAME' => $email,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $secretHash,
                ],
            ]);

            return [
                'success' => true,
                'message' => 'Login successful',
                'token' => $result['AuthenticationResult'],
            ];
        } catch (\Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    public function getUserProfile($token)
    {
        try {
            $clientId = $this->clientId;
            $clientSecret = env('AWS_COGNITO_CLIENT_SECRET');
            $response = $this->client->getUser([
                'AccessToken' => $token,
            ]);

            $userData = [];
            foreach ($response['UserAttributes'] as $attribute) {
                $userData[$attribute['Name']] = $attribute['Value'];
            }

            return ['success' => true, 'data' => $userData];
        } catch (\Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    public function logoutUser($token)
    {
        try {
            $clientId = $this->clientId;
            $clientSecret = env('AWS_COGNITO_CLIENT_SECRET');
            $this->client->globalSignOut([
                'AccessToken' => $token,
            ]);

            return ['success' => true, 'message' => 'User logged out successfully.'];
        } catch (\Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    public function forgotPassword($email)
    {
        try {
            $clientId = $this->clientId;
            $clientSecret = env('AWS_COGNITO_CLIENT_SECRET');
            $secretHash = $this->calculateSecretHash($email, $clientId, $clientSecret);

            $response = $this->client->forgotPassword([
                'ClientId' => $clientId,
                'Username' => $email,
                'SecretHash' => $secretHash,
            ]);

            return ['success' => true, 'message' => 'Password reset code sent to email.'];
        } catch (\Exception $e) {
            Log::error('Cognito Forgot Password Error: '.$e->getMessage());

            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    public function resetPassword($email, $confirmationCode, $newPassword)
    {
        try {
            $clientId = $this->clientId;
            $clientSecret = env('AWS_COGNITO_CLIENT_SECRET');
            $secretHash = $this->calculateSecretHash($email, $clientId, $clientSecret);

            $response = $this->client->confirmForgotPassword([
                'ClientId' => $clientId,
                'Username' => $email,
                'ConfirmationCode' => $confirmationCode,
                'Password' => $newPassword,
                'SecretHash' => $secretHash,
            ]);

            return ['success' => true, 'message' => 'Password reset successfully.'];
        } catch (\Exception $e) {
            Log::error('Cognito Reset Password Error: '.$e->getMessage());

            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
}
