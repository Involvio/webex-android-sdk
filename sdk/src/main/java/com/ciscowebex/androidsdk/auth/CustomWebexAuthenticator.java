package com.ciscowebex.androidsdk.auth;

import android.support.annotation.NonNull;

import com.cisco.spark.android.authenticator.ApiTokenProvider;
import com.cisco.spark.android.authenticator.OAuth2Tokens;
import com.cisco.spark.android.core.ApplicationController;
import com.cisco.spark.android.core.Injector;
import com.cisco.spark.android.model.AuthenticatedUser;
import com.cisco.spark.android.model.conversation.ActorRecord;
import com.ciscowebex.androidsdk.CompletionHandler;
import com.ciscowebex.androidsdk.auth.model.WebexToken;
import com.ciscowebex.androidsdk.internal.ResultImpl;
import com.ciscowebex.androidsdk.utils.http.ServiceBuilder;
import com.ciscowebex.androidsdk_commlib.AfterInjected;

import org.greenrobot.eventbus.EventBus;

import javax.inject.Inject;
import javax.inject.Named;

import me.helloworld.utils.Checker;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import retrofit2.http.GET;
import retrofit2.http.Url;

public class CustomWebexAuthenticator implements Authenticator {
    @Inject
    ApiTokenProvider _provider;
    @Inject
    ApplicationController _applicationController;
    private OAuth2Tokens _token = null;

    @Inject
    @Named("SDK")
    Injector _injector;

    private @NonNull String refreshTokenUrl;
    private CustomWebexAuthenticator.AuthService _authService;
    private static final String DEPARTMENT_UNKNOWN = "Unknown";

    public CustomWebexAuthenticator(@NonNull String refreshTokenUrl) {
        _authService = new ServiceBuilder().build(AuthService.class);
        this.refreshTokenUrl = refreshTokenUrl;
    }

    public void authorize(@NonNull String token, long expire) {
        this.deauthorize();
        this._token = new OAuth2Tokens();
        this._token.setAccessToken(token);
        this._token.setExpiresIn(expire + System.currentTimeMillis() / 1000L);
        this._token.setRefreshToken(token);
        if (this._provider != null) {
            AuthenticatedUser authenticatedUser = new AuthenticatedUser("", new ActorRecord.ActorKey(""), "", this._token, "Unknown", (String)null, 0L, (String)null);
            this._provider.setAuthenticatedUser(authenticatedUser);
        }
    }

    public boolean isAuthorized() {
        return this._token != null && this._token.getAccessToken() != null && System.currentTimeMillis() < this._token.getExpiresIn() * 1000L;
    }

    public void deauthorize() {
        this._token = null;
        if (this._applicationController != null) {
            this._applicationController.clear();
        }

    }

    public void getToken(CompletionHandler<String> handler) {
        if (_token == null) {
            handler.onComplete(ResultImpl.error("Not authorized"));
            return;
        }
        if (!Checker.isEmpty(_token.getAccessToken()) && _token.getExpiresIn() > (System.currentTimeMillis() / 1000) + (15 * 60)) {
            handler.onComplete(ResultImpl.success(_token.getAccessToken()));
            return;
        }
        refreshToken(handler);
    }

    public void refreshToken(@NonNull CompletionHandler<String> handler) {

        if (_token == null) {
            handler.onComplete(ResultImpl.error("Not authorized"));
        } else {
            _authService.getRefreshedAccessTokenFrom(refreshTokenUrl).enqueue(
                    new Callback<WebexToken>() {
                        @Override
                        public void onResponse(Call<WebexToken> call, Response<WebexToken> response) {
                            if(response!=null && response.isSuccessful()) {
                                WebexToken webexToken = response.body();
                                if(webexToken !=null && webexToken.isWebexAccessTokenNonEmpty()) {
                                    String token = response.body().getToken();
                                    Long expiresIn = response.body().getExpiresIn();

                                    if (_token == null || Checker.isEmpty(_token.getAccessToken())) {
                                        handler.onComplete(ResultImpl.error(response));
                                    } else {
                                        _token.setAccessToken(token);
                                        _token.setExpiresIn(expiresIn + System.currentTimeMillis() / 1000);
                                        if (_provider != null) {
                                            AuthenticatedUser authenticatedUser = new AuthenticatedUser("", new ActorRecord.ActorKey(""), "", _token, DEPARTMENT_UNKNOWN, null, 0, null);
                                            _provider.setAuthenticatedUser(authenticatedUser);
                                        }
                                        EventBus.getDefault().post(webexToken);
                                        handler.onComplete(ResultImpl.success(_token.getAccessToken()));
                                    }
                                } else {
                                    handler.onComplete(ResultImpl.error(response));
                                }
                            } else {
                                handler.onComplete(ResultImpl.error(response));
                            }
                        }

                        @Override
                        public void onFailure(Call<WebexToken> call, Throwable t) {
                            handler.onComplete(ResultImpl.error(t));
                        }
                    }
            );
        }
    }
    @AfterInjected
    private void afterInjected() {
        if (this._provider != null && this._token != null) {
            AuthenticatedUser authenticatedUser = new AuthenticatedUser("", new ActorRecord.ActorKey(""), "", this._token, "Unknown", (String)null, 0L, (String)null);
            this._provider.setAuthenticatedUser(authenticatedUser);
        }
    }

    interface AuthService {
        @GET
        Call<WebexToken> getRefreshedAccessTokenFrom(@Url String url);
    }
}