package com.ciscowebex.androidsdk.auth.model;

import android.support.annotation.Nullable;
import android.text.TextUtils;

import com.google.gson.annotations.SerializedName;

public class WebexToken {
    @SerializedName("access_token")
    private String token;

    @SerializedName("expires_in")
    private Long expiresIn;

    public WebexToken(String token, Long expiresIn) {
        this.token = token;
        this.expiresIn = expiresIn;
    }

    public @Nullable
    String getToken() {
        return token;
    }

    public @Nullable Long getExpiresIn() {
        return expiresIn;
    }

    public boolean isWebexAccessTokenNonEmpty() {
        return !TextUtils.isEmpty(token) && expiresIn!=null && expiresIn != Long.MIN_VALUE;
    }
}
