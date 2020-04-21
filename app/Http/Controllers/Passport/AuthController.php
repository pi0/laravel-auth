<?php

namespace App\Http\Controllers\Passport;

use App\Http\Controllers\Controller;

class AuthController extends Controller
{
    public function __construct ()
    {
        $this->middleware('auth:passport');
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function user()
    {
        return response()->json(auth()->guard('passport')->user());
    }
}
