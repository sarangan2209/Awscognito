<?php

namespace App\Http\Controllers;

use App\Http\Requests\ConfirmSignUpRequest;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Models\User;
use App\Services\CognitoAuthService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    protected $cognitoAuthService;

    public function __construct(CognitoAuthService $cognitoAuthService)
    {
        $this->cognitoAuthService = $cognitoAuthService;
    }

    public function register(RegisterRequest $request)
    {

        $result = $this->cognitoAuthService->register(
            $request->name,
            $request->email,
            $request->password
        );

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        if (isset($result['error'])) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json(['message' => 'User registered successfully. Check your email for verification.'], 201);
    }

    public function confirmSignUp(ConfirmSignUpRequest $request)
    {

        $result = $this->cognitoAuthService->confirmSignUp(
            $request->email,
            $request->confirmation_code
        );

        if (! $result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json(['message' => 'User confirmed successfully.'], 200);
    }

    public function login(LoginRequest $request)
    {

        $result = $this->cognitoAuthService->loginUser(
            $request->email,
            $request->password
        );

        return response()->json($result);
    }

    public function profile(Request $request)
    {
        $token = $request->bearerToken();

        if (! $token) {
            return response()->json(['error' => 'Token not provided'], 401);
        }

        $result = $this->cognitoAuthService->getUserProfile($token);

        if (! $result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json($result);
    }

    public function logout(Request $request)
    {
        $token = $request->bearerToken();

        if (! $token) {
            return response()->json(['error' => 'Token not provided'], 401);
        }

        $result = $this->cognitoAuthService->logoutUser($token);

        if (! $result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json($result);
    }

    public function forgotPassword(ForgotPasswordRequest $request)
    {

        $result = $this->cognitoAuthService->forgotPassword($request->email);

        if (! $result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json(['message' => $result['message']]);
    }

    public function resetPassword(ResetPasswordRequest $request)
    {

        $result = $this->cognitoAuthService->resetPassword(
            $request->email,
            $request->confirmation_code,
            $request->new_password
        );

        if (! $result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        $user = User::where('email', $request->email)->first();
        if ($user) {
            $user->password = Hash::make($request->new_password);
            $user->save();
        }

        return response()->json(['message' => $result['message']]);
    }
}
