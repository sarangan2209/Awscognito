<?php

namespace App\Services;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Support\Facades\Log;
use Aws\Credentials\Credentials;



class CognitoAuthService
{
    protected $client;    

    public function __construct()
    {

        $this->clientId = env('AWS_COGNITO_CLIENT_ID'); 
        
        $this->client = new CognitoIdentityProviderClient([
            'region' => env('AWS_COGNITO_REGION','ap-south-1'),
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
            Log::error('Cognito Registration Error: ' . $e->getMessage());
            return ['error' => $e->getMessage()];
            }
    }

    private function calculateSecretHash($username, $clientId, $clientSecret)
    {
        return base64_encode(
            hash_hmac('sha256', $username .$clientId, $clientSecret, true)
        );
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
                'SECRET_HASH' => $secretHash, // 🔹 Add this line
            ],
        ]);
        return [
            'success' => true,
            'message' => 'Login successful',
            'token' => $result['AuthenticationResult']
        ];
    } catch (\Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

}
