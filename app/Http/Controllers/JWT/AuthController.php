<?php

namespace App\Http\Controllers\JWT;

use App\Http\Controllers\Controller;
use Illuminate\Auth\AuthenticationException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class AuthController extends Controller
{
    public function __construct ()
    {
        $this->middleware('auth:jwt', ['except' => ['login', 'refresh']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->guard('jwt')->attempt($credentials)) {
            return response()->json('Invalid email or password', 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function user()
    {
        return response()->json(auth()->guard('jwt')->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->guard('jwt')->logout();

        return response()->json('Successfully logged out');
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        try {
            return $this->respondWithToken(auth()->guard('jwt')->refresh());
        } catch (TokenExpiredException $tokenExpiredException) {
            return response()->json('The token has expired.', 401);
        } catch (TokenInvalidException $tokenInvalidException) {
            return response()->json('The token is invalid.', 401);
        } catch (JWTException $JWTException) {
            return response()->json('The token couldn\'t be refreshed.', 401);
        } catch (AuthenticationException $authenticationException) {
            return response()->json('Unauthenticated.', 401);
        }

    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->guard('jwt')->factory()->getTTL() * 60
        ]);
    }
}
