<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
// use App\Http\Controllers\CognitoAuthController;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::post('/register', [AuthController::class, 'register']);

Route::post('/confirmsignup', [AuthController::class, 'confirmSignUp']);

Route::post('/login', [AuthController::class, 'login']);

Route::get('/profile', [AuthController::class, 'profile']);

Route::post('/logout', [AuthController::class, 'logout']);

Route::post('/forgotpassword', [AuthController::class, 'forgotPassword']);

Route::post('/resetpassword', [AuthController::class, 'resetPassword']);
