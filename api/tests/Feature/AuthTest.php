<?php

use App\Models\User;
use App\Services\CognitoAuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);

beforeEach(function () {

    $this->cognitoAuthService = Mockery::mock(CognitoAuthService::class);
    $this->app->instance(CognitoAuthService::class, $this->cognitoAuthService);

    $this->user = User::factory()->create([
        'name' => fake()->name(),
        'email' => fake()->unique()->safeEmail(),
        'password' => Hash::make('test@123'),
    ]);

});

it('should register a user successfully', function () {
    $this->cognitoAuthService
        ->shouldReceive('register')
        ->once()
        ->with('John Doe', 'johndoe@example.com', 'Password@123')
        ->andReturn(['success' => true]);

    $response = $this->postJson('/api/register', [
        'name' => 'John Doe',
        'email' => 'johndoe@example.com',
        'password' => 'Password@123',
        'password_confirmation' => 'Password@123',
    ]);

    $response->assertStatus(201)
        ->assertJson([
            'message' => 'User registered successfully. Check your email for verification.',
        ]);

});

it('should return 400 if registration fails', function () {

    $this->cognitoAuthService
        ->shouldReceive('register')
        ->once()
        ->with('John Doe', 'johndoe@example.com', 'Password@123')
        ->andReturn(['error' => 'Cognito registration failed']);

    $response = $this->postJson('/api/register', [
        'name' => 'John Doe',
        'email' => 'johndoe@example.com',
        'password' => 'Password@123',
        'password_confirmation' => 'Password@123',
    ]);

    $response->assertStatus(400)
        ->assertJson([
            'error' => 'Cognito registration failed',
        ]);
});

it('should succeed login with valid credentials', function () {
    $this->cognitoAuthService
        ->shouldReceive('loginUser')
        ->once()
        ->with('johndoe@example.com', 'Password123@')
        ->andReturn([
            'success' => true,
            'access_token' => 'sample_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);

    $response = $this->postJson('/api/login', [
        'email' => 'johndoe@example.com',
        'password' => 'Password123@',
    ]);

    $response->assertStatus(200)
        ->assertJsonStructure(['success', 'access_token', 'token_type', 'expires_in']);
});

it('should confirm user signup with a valid confirmation code', function () {

    $this->cognitoAuthService
        ->shouldReceive('confirmSignUp')
        ->once()
        ->with('johndoe@example.com', '123456')
        ->andReturn(['success' => true]);

    $response = $this->postJson('/api/confirmsignup', [
        'email' => 'johndoe@example.com',
        'confirmation_code' => '123456',
    ]);

    $response->assertStatus(200)
        ->assertJson([
            'message' => 'User confirmed successfully.',
        ]);
});

it('should return 400 if confirmation fails', function () {

    $this->cognitoAuthService
        ->shouldReceive('confirmSignUp')
        ->once()
        ->with('johndoe@example.com', 'wrongcode')
        ->andReturn([
            'success' => false,
            'error' => 'Invalid confirmation code.',
        ]);

    $response = $this->postJson('/api/confirmsignup', [
        'email' => 'johndoe@example.com',
        'confirmation_code' => 'wrongcode',
    ]);

    $response->assertStatus(400)
        ->assertJson([
            'error' => 'Invalid confirmation code.',
        ]);
});

it('should return user profile with a valid token', function () {

    $this->accessToken = 'valid_test_token';
    $this->cognitoAuthService
        ->shouldReceive('getUserProfile')
        ->once()
        ->with('valid_test_token')
        ->andReturn([
            'success' => true,
            'data' => [
                'name' => 'John Doe',
                'email' => 'johndoe@example.com',
            ],
        ]);

    $response = $this->getJson('/api/profile', [
        'Authorization' => "Bearer {$this->accessToken}",
    ]);

    $response->assertStatus(200)
        ->assertJson([
            'success' => true,
            'data' => [
                'name' => 'John Doe',
                'email' => 'johndoe@example.com',
            ],
        ]);
});

it('should return 401 if no token is provided for profile', function () {

    $response = $this->getJson('/api/profile');

    $response->assertStatus(401)
        ->assertJson([
            'error' => 'Token not provided',
        ]);
});

it('should return 400 if token is invalid for profile', function () {

    $this->cognitoAuthService
        ->shouldReceive('getUserProfile')
        ->once()
        ->with('invalid_token')
        ->andReturn([
            'success' => false,
            'error' => 'Invalid token',
        ]);

    $response = $this->getJson('/api/profile', [
        'Authorization' => 'Bearer invalid_token',
    ]);

    $response->assertStatus(400)
        ->assertJson([
            'error' => 'Invalid token',
        ]);
});

it('should logout user with a valid token', function () {

    $this->accessToken = 'valid_test_token';
    $this->cognitoAuthService
        ->shouldReceive('logoutUser')
        ->once()
        ->with('valid_test_token')
        ->andReturn([
            'success' => true,
            'message' => 'User logged out successfully.',
        ]);

    $response = $this->postJson('/api/logout', [], [
        'Authorization' => "Bearer {$this->accessToken}",
    ]);

    $response->assertStatus(200)
        ->assertJson([
            'success' => true,
            'message' => 'User logged out successfully.',
        ]);
});

it('should return 401 if no token is provided for logout', function () {

    $response = $this->postJson('/api/logout');

    $response->assertStatus(401)
        ->assertJson([
            'error' => 'Token not provided',
        ]);
});

it('should return 400 if token is invalid for logout', function () {

    $this->cognitoAuthService
        ->shouldReceive('logoutUser')
        ->once()
        ->with('invalid_token')
        ->andReturn([
            'success' => false,
            'error' => 'Invalid token',
        ]);

    $response = $this->postJson('/api/logout', [], [
        'Authorization' => 'Bearer invalid_token',
    ]);

    $response->assertStatus(400)
        ->assertJson([
            'error' => 'Invalid token',
        ]);
});

it('should send forgot password email successfully', function () {

    $this->cognitoAuthService
        ->shouldReceive('forgotPassword')
        ->once()
        ->with('johndoe@example.com')
        ->andReturn([
            'success' => true,
            'message' => 'Password reset code sent to email.',
        ]);

    $response = $this->postJson('/api/forgotpassword', [
        'email' => 'johndoe@example.com',
    ]);

    $response->assertStatus(200)
        ->assertJson([
            'message' => 'Password reset code sent to email.',
        ]);
});

it('should return 400 if email is invalid or not found', function () {

    $this->cognitoAuthService
        ->shouldReceive('forgotPassword')
        ->once()
        ->with('invalid@example.com')
        ->andReturn([
            'success' => false,
            'error' => 'User not found',
        ]);

    $response = $this->postJson('/api/forgotpassword', [
        'email' => 'invalid@example.com',
    ]);

    $response->assertStatus(400)
        ->assertJson([
            'error' => 'User not found',
        ]);
});

it('should reset password successfully with valid confirmation code', function () {

    $this->cognitoAuthService
        ->shouldReceive('resetPassword')
        ->once()
        ->with('johndoe@example.com', '123456', 'NewPassword@123')
        ->andReturn([
            'success' => true,
            'message' => 'Password reset successfully.',
        ]);

    $response = $this->postJson('/api/resetpassword', [
        'email' => 'johndoe@example.com',
        'confirmation_code' => '123456',
        'new_password' => 'NewPassword@123',
    ]);

    $response->assertStatus(200)
        ->assertJson([
            'message' => 'Password reset successfully.',
        ]);

});

it('should return 400 if confirmation code is invalid', function () {

    $this->cognitoAuthService
        ->shouldReceive('resetPassword')
        ->once()
        ->with('johndoe@example.com', 'wrong_code', 'NewPassword@123')
        ->andReturn([
            'success' => false,
            'error' => 'Invalid confirmation code.',
        ]);

    $response = $this->postJson('/api/resetpassword', [
        'email' => 'johndoe@example.com',
        'confirmation_code' => 'wrong_code',
        'new_password' => 'NewPassword@123',
    ]);

    $response->assertStatus(400)
        ->assertJson([
            'error' => 'Invalid confirmation code.',
        ]);
});

it('should update the user password in the database after reset', function () {

    $user = User::factory()->create([
        'email' => 'johndoe@example.com',
        'password' => Hash::make('OldPassword@123'),
    ]);

    $this->assertFalse(Hash::check('NewPassword@123', $user->password));

    $this->cognitoAuthService
        ->shouldReceive('resetPassword')
        ->once()
        ->with('johndoe@example.com', '123456', 'NewPassword@123')
        ->andReturn([
            'success' => true,
            'message' => 'Password reset successfully.',
        ]);

    $response = $this->postJson('/api/resetpassword', [
        'email' => 'johndoe@example.com',
        'confirmation_code' => '123456',
        'new_password' => 'NewPassword@123',
    ]);

    $response->assertStatus(200)
        ->assertJson([
            'message' => 'Password reset successfully.',
        ]);

    $user->refresh();

    $this->assertTrue(Hash::check('NewPassword@123', $user->password));
});
