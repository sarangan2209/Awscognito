<?php

namespace App\Http\Controllers;

use App\Models\User;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

class LoginUserViaSocialiteController extends Controller
{
    public function create($provider)
    {
        return Socialite::driver($provider)->stateless()->redirect();
    }

    // public function store($provider)
    // {
    //     $socialiteUser = Socialite::driver($provider)->stateless()->user();

    //     $user = User::where('email', $socialiteUser->getEmail())->first();

    //     if (!$user) {
    //         $user = User::create([
    //             'name' => $socialiteUser->getName(),
    //             'email' => $socialiteUser->getEmail(),
    //             'socialite_id' => $socialiteUser->getId(),
    //             'socialite_token' => $socialiteUser->token,
    //             'socialite_provider' => $provider,
    //         ]);
    //     }

    //     Auth::login($user);

    //     return response()->json([
    //         'message' => 'Login successful',
    //         'user' => $user,
    //     ]);
    // }
    private function calculateSecretHash($username, $clientId, $clientSecret)
    {
        return base64_encode(
            hash_hmac('sha256', $username.$clientId, $clientSecret, true)
        );
    }

    public function store($provider)
    {
        $socialiteUser = Socialite::driver($provider)->stateless()->user();

        $user = User::where('email', $socialiteUser->getEmail())->first();

        if (! $user) {
            $user = User::create([
                'name' => $socialiteUser->getName(),
                'email' => $socialiteUser->getEmail(),
                'socialite_id' => $socialiteUser->getId(),
                'socialite_token' => $socialiteUser->token,
                'socialite_provider' => $provider,
            ]);
        }

        $cognitoClient = new CognitoIdentityProviderClient([
            'region' => env('AWS_REGION'),
            'version' => 'latest',
            'credentials' => [
                'key' => env('AWS_ACCESS_KEY_ID'),
                'secret' => env('AWS_SECRET_ACCESS_KEY'),
            ],
        ]);

        $userPoolId = env('AWS_COGNITO_USER_POOL_ID');
        $clientId = env('AWS_COGNITO_CLIENT_ID');
        $clientSecret = env('AWS_COGNITO_CLIENT_SECRET');
        $email = $socialiteUser->getEmail();
        $temporaryPassword = 'Temp@1234';
        $permanentPassword = 'StrongP@ssword123';

        if (! $clientId || ! $clientSecret) {
            return response()->json(['error' => 'Cognito Client ID or Secret is missing. Check .env file.'], 500);
        }

        try {
            $cognitoClient->adminGetUser([
                'UserPoolId' => $userPoolId,
                'Username' => $email,
            ]);
        } catch (\Exception $e) {
            $cognitoClient->adminCreateUser([
                'UserPoolId' => $userPoolId,
                'Username' => $email,
                'UserAttributes' => [
                    ['Name' => 'email', 'Value' => $email],
                    ['Name' => 'name', 'Value' => $socialiteUser->getName()],
                    ['Name' => 'email_verified', 'Value' => 'true'],
                ],
                'TemporaryPassword' => $temporaryPassword,
                'MessageAction' => 'SUPPRESS',
            ]);

            $cognitoClient->adminSetUserPassword([
                'UserPoolId' => $userPoolId,
                'Username' => $email,
                'Password' => $permanentPassword,
                'Permanent' => true,
            ]);
        }

        $secretHash = $this->calculateSecretHash($email, $clientId, $clientSecret);

        try {
            $response = $cognitoClient->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'UserPoolId' => $userPoolId,
                'ClientId' => $clientId,
                'AuthParameters' => [
                    'USERNAME' => $email,
                    'PASSWORD' => $permanentPassword,
                    'SECRET_HASH' => $secretHash,
                ],
            ]);

            $tokens = $response->get('AuthenticationResult');

            Auth::login($user);

            return response()->json([
                'message' => 'Login successful',
                'user' => $user,
                'id_token' => $tokens['IdToken'],
                'access_token' => $tokens['AccessToken'],
                'refresh_token' => $tokens['RefreshToken'],
            ]);

        } catch (\Exception $e) {
            return response()->json(['error' => 'Authentication failed', 'message' => $e->getMessage()], 400);
        }
    }
}
