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


public function login(Request $request)
{
    $validated = $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);
    $result = $this->cognitoAuthService->loginUser($validated['email'], $validated['password']);
    return response()->json($result);
}

}
