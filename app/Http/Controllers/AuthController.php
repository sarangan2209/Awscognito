<?php

namespace App\Http\Controllers;

use App\Services\CognitoAuthService;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    protected $cognitoAuthService;

    public function __construct(CognitoAuthService $cognitoAuthService)
    {
        $this->cognitoAuthService = $cognitoAuthService;
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]);

        $result = $this->cognitoAuthService->register(
            $request->name,
            $request->email,
            $request->password
        );


        if (isset($result['error'])) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json(['message' => 'User registered successfully. Check your email for verification.'], 201);
    }

    public function confirmSignUp(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'confirmation_code' => 'required|string',
        ]);

        $result = $this->cognitoAuthService->confirmSignUp(
            $request->email,
            $request->confirmation_code
        );

        if (!$result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json(['message' => 'User confirmed successfully.'], 200);
    }



    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);
        $result = $this->cognitoAuthService->loginUser($validated['email'], $validated['password']);
        return response()->json($result);
    }

    public function profile(Request $request)
    {
    $token = $request->bearerToken();

    if (!$token) {
        return response()->json(['error' => 'Token not provided'], 401);
    }

    $result = $this->cognitoAuthService->getUserProfile($token);

    if (!$result['success']) {
        return response()->json(['error' => $result['error']], 400);
    }

    return response()->json($result);
    }

    public function logout(Request $request)
    {
        $token = $request->bearerToken(); 

        if (!$token) {
            return response()->json(['error' => 'Token not provided'], 401);
        }

        $result = $this->cognitoAuthService->logoutUser($token);

        if (!$result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json($result);
    }

    public function forgotPassword(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        $result = $this->cognitoAuthService->forgotPassword($request->email);

        if (!$result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json(['message' => $result['message']]);
    }


    public function resetPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'confirmation_code' => 'required|string',
            'new_password' => 'required|min:8',
        ]);

        $result = $this->cognitoAuthService->resetPassword(
            $request->email,
            $request->confirmation_code,
            $request->new_password
        );

        if (!$result['success']) {
            return response()->json(['error' => $result['error']], 400);
        }

        return response()->json(['message' => $result['message']]);
    }



}
