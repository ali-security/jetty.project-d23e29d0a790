//
// ========================================================================
// Copyright (c) 1995 Mort Bay Consulting Pty Ltd and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
// ========================================================================
//

package org.eclipse.jetty.client;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpScheme;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.ConnectHandler;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.component.LifeCycle;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class HttpClientProxyTest extends AbstractHttpClientServerTest
{
    private Server proxy;

    @AfterEach
    public void disposeProxy()
    {
        LifeCycle.stop(proxy);
    }

    private int startProxy(Handler handler) throws Exception
    {
        QueuedThreadPool proxyThreads = new QueuedThreadPool();
        proxyThreads.setName("proxy");
        proxy = new Server(proxyThreads);
        ServerConnector proxyConnector = new ServerConnector(proxy);
        proxy.addConnector(proxyConnector);
        proxy.setHandler(handler);
        proxy.start();
        return proxyConnector.getLocalPort();
    }

    @ParameterizedTest
    @ArgumentsSource(NonSslScenarioProvider.class) // Avoid TLS otherwise CONNECT requests are sent instead of proxied requests
    public void testProxiedRequest(Scenario scenario) throws Exception
    {
        final String serverHost = "server";
        final int status = HttpStatus.NO_CONTENT_204;
        start(scenario, new EmptyServerHandler()
        {
            @Override
            protected void service(org.eclipse.jetty.server.Request request, Response response)
            {
                if (!URI.create(request.getHttpURI().toString()).isAbsolute())
                    response.setStatus(HttpStatus.USE_PROXY_305);
                else if (serverHost.equals(org.eclipse.jetty.server.Request.getServerName(request)))
                    response.setStatus(status);
                else
                    response.setStatus(HttpStatus.NOT_ACCEPTABLE_406);
            }
        });

        int proxyPort = connector.getLocalPort();
        int serverPort = proxyPort + 1; // Any port will do for these tests - just not the same as the proxy
        client.getProxyConfiguration().addProxy(new HttpProxy("localhost", proxyPort));

        ContentResponse response = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response.getStatus());
    }

    @ParameterizedTest
    @ArgumentsSource(NonSslScenarioProvider.class) // Avoid TLS otherwise CONNECT requests are sent instead of proxied requests
    public void testProxyAuthentication(Scenario scenario) throws Exception
    {
        final String user = "foo";
        final String password = "bar";
        final String credentials = Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.ISO_8859_1));
        final String serverHost = "server";
        final String realm = "test_realm";
        final int status = HttpStatus.NO_CONTENT_204;
        start(scenario, new EmptyServerHandler()
        {
            @Override
            protected void service(org.eclipse.jetty.server.Request request, Response response)
            {
                String authorization = request.getHeaders().get(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization == null)
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.getHeaders().put(HttpHeader.PROXY_AUTHENTICATE, "Basic realm=\"" + realm + "\"");
                }
                else
                {
                    String prefix = "Basic ";
                    if (authorization.startsWith(prefix))
                    {
                        String attempt = authorization.substring(prefix.length());
                        if (credentials.equals(attempt))
                            response.setStatus(status);
                    }
                }
            }
        });

        String proxyHost = "localhost";
        int proxyPort = connector.getLocalPort();
        int serverPort = proxyPort + 1; // Any port will do for these tests - just not the same as the proxy
        client.getProxyConfiguration().addProxy(new HttpProxy(proxyHost, proxyPort));

        ContentResponse response1 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        // No Authentication available => 407
        assertEquals(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407, response1.getStatus());

        // Add authentication...
        URI uri = URI.create(scenario.getScheme() + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(uri, realm, user, password));
        final AtomicInteger requests = new AtomicInteger();
        client.getRequestListeners().addSuccessListener(request -> requests.incrementAndGet());
        // ...and perform the request again => 407 + 204
        ContentResponse response2 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response2.getStatus());
        assertEquals(2, requests.get());

        // Now the authentication result is cached => 204
        requests.set(0);
        ContentResponse response3 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response3.getStatus());
        assertEquals(1, requests.get());
    }

    @ParameterizedTest
    @ArgumentsSource(NonSslScenarioProvider.class) // Avoid TLS otherwise CONNECT requests are sent instead of proxied requests
    public void testProxyAuthenticationWithRedirect(Scenario scenario) throws Exception
    {
        String user = "foo";
        String password = "bar";
        String credentials = Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.ISO_8859_1));
        String proxyHost = "localhost";
        String serverHost = "server";
        int serverPort = HttpScheme.HTTP.is(scenario.getScheme()) ? 80 : 443;
        String realm = "test_realm";
        int status = HttpStatus.NO_CONTENT_204;
        start(scenario, new Handler.Abstract()
        {
            @Override
            public boolean handle(org.eclipse.jetty.server.Request request, Response response, Callback callback)
            {
                String target = org.eclipse.jetty.server.Request.getPathInContext(request);
                if (target.startsWith("/proxy"))
                {
                    String authorization = request.getHeaders().get(HttpHeader.PROXY_AUTHORIZATION.asString());
                    if (authorization == null)
                    {
                        response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                        response.getHeaders().put(HttpHeader.PROXY_AUTHENTICATE, "Basic realm=\"" + realm + "\"");
                        callback.succeeded();
                    }
                    else
                    {
                        String prefix = "Basic ";
                        if (authorization.startsWith(prefix))
                        {
                            String attempt = authorization.substring(prefix.length());
                            if (credentials.equals(attempt))
                            {
                                // Change also the host, to verify that proxy authentication works in this case too.
                                Response.sendRedirect(request, response, callback, scenario.getScheme() + "://127.0.0.1:" + serverPort + "/server");
                                return true;
                            }
                        }
                        callback.succeeded();
                    }
                }
                else if (target.startsWith("/server"))
                {
                    response.setStatus(status);
                    callback.succeeded();
                }
                else
                {
                    Response.writeError(request, response, callback, HttpStatus.INTERNAL_SERVER_ERROR_500);
                }

                return true;
            }
        });

        int proxyPort = connector.getLocalPort();
        client.getProxyConfiguration().addProxy(new HttpProxy(proxyHost, proxyPort));

        ContentResponse response1 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .path("/proxy")
            .timeout(5, TimeUnit.SECONDS)
            .send();

        // No Authentication available => 407.
        assertEquals(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407, response1.getStatus());

        // Add authentication...
        URI uri = URI.create(scenario.getScheme() + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(uri, realm, user, password));
        final AtomicInteger requests = new AtomicInteger();
        client.getRequestListeners().addSuccessListener(request -> requests.incrementAndGet());
        // ...and perform the request again => 407 + 302 + 204.
        ContentResponse response2 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .path("/proxy")
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response2.getStatus());
        assertEquals(3, requests.get());

        // Now the authentication result is cached => 204.
        requests.set(0);
        ContentResponse response3 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .path("/server")
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response3.getStatus());
        assertEquals(1, requests.get());
    }

    @ParameterizedTest
    @ArgumentsSource(NonSslScenarioProvider.class) // Avoid TLS otherwise CONNECT requests are sent instead of proxied requests
    public void testProxyAuthenticationWithServerAuthentication(Scenario scenario) throws Exception
    {
        String proxyRealm = "proxyRealm";
        String serverRealm = "serverRealm";
        int status = HttpStatus.NO_CONTENT_204;
        start(scenario, new EmptyServerHandler()
        {
            @Override
            protected void service(org.eclipse.jetty.server.Request request, Response response)
            {
                String authorization = request.getHeaders().get(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization == null)
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.getHeaders().put(HttpHeader.PROXY_AUTHENTICATE, "Basic realm=\"" + proxyRealm + "\"");
                }
                else
                {
                    authorization = request.getHeaders().get(HttpHeader.AUTHORIZATION.asString());
                    if (authorization == null)
                    {
                        response.setStatus(HttpStatus.UNAUTHORIZED_401);
                        response.getHeaders().put(HttpHeader.WWW_AUTHENTICATE, "Basic realm=\"" + serverRealm + "\"");
                    }
                    else
                    {
                        response.setStatus(status);
                    }
                }
            }
        });

        String proxyHost = "localhost";
        int proxyPort = connector.getLocalPort();
        String serverHost = "server";
        int serverPort = proxyPort + 1;
        URI proxyURI = URI.create(scenario.getScheme() + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, proxyRealm, "proxyUser", "proxyPassword"));
        URI serverURI = URI.create(scenario.getScheme() + "://" + serverHost + ":" + serverPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(serverURI, serverRealm, "serverUser", "serverPassword"));
        client.getProxyConfiguration().addProxy(new HttpProxy(proxyHost, proxyPort));
        final AtomicInteger requests = new AtomicInteger();
        client.getRequestListeners().addSuccessListener(request -> requests.incrementAndGet());
        // Make a request, expect 407 + 401 + 204.
        ContentResponse response1 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response1.getStatus());
        assertEquals(3, requests.get());

        // Make again the request, only the server authentication is cached, expect 407 + 204.
        requests.set(0);
        ContentResponse response2 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response2.getStatus());
        assertEquals(2, requests.get());
    }

    @ParameterizedTest
    @ArgumentsSource(NonSslScenarioProvider.class) // Avoid TLS otherwise CONNECT requests are sent instead of proxied requests
    public void testProxyAuthenticationWithExplicitAuthorizationHeader(Scenario scenario) throws Exception
    {
        String proxyRealm = "proxyRealm";
        String serverRealm = "serverRealm";
        int status = HttpStatus.NO_CONTENT_204;
        start(scenario, new EmptyServerHandler()
        {
            @Override
            protected void service(org.eclipse.jetty.server.Request request, Response response)
            {
                String authorization = request.getHeaders().get(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization == null)
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.getHeaders().put(HttpHeader.PROXY_AUTHENTICATE, "Basic realm=\"" + proxyRealm + "\"");
                }
                else
                {
                    authorization = request.getHeaders().get(HttpHeader.AUTHORIZATION.asString());
                    if (authorization == null)
                    {
                        response.setStatus(HttpStatus.UNAUTHORIZED_401);
                        response.getHeaders().put(HttpHeader.WWW_AUTHENTICATE, "Basic realm=\"" + serverRealm + "\"");
                    }
                    else
                    {
                        response.setStatus(status);
                    }
                }
            }
        });

        String proxyHost = "localhost";
        int proxyPort = connector.getLocalPort();
        String serverHost = "server";
        int serverPort = proxyPort + 1;
        URI proxyURI = URI.create(scenario.getScheme() + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, proxyRealm, "proxyUser", "proxyPassword"));
        client.getProxyConfiguration().addProxy(new HttpProxy(proxyHost, proxyPort));
        final AtomicInteger requests = new AtomicInteger();
        client.getRequestListeners().addSuccessListener(request -> requests.incrementAndGet());
        // Make a request, expect 407 + 204.
        ContentResponse response1 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .headers(headers -> headers.put(HttpHeader.AUTHORIZATION, "Basic foobar"))
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response1.getStatus());
        assertEquals(2, requests.get());

        // Make again the request, authentication is cached, expect 204.
        requests.set(0);
        ContentResponse response2 = client.newRequest(serverHost, serverPort)
            .scheme(scenario.getScheme())
            .headers(headers -> headers.put(HttpHeader.AUTHORIZATION, "Basic foobar"))
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(status, response2.getStatus());
        assertEquals(1, requests.get());
    }

    @Test
    public void testProxyAuthenticationRequiredFromServerNotSentToProxyIsNotHandled() throws Exception
    {
        String realm = "proxyRealm";
        AtomicInteger serverRequests = new AtomicInteger();
        AtomicReference<String> proxyAuthorization = new AtomicReference<>();
        Scenario scenario = new NormalScenario();
        start(scenario, new EmptyServerHandler()
        {
            @Override
            protected void service(org.eclipse.jetty.server.Request request, Response response)
            {
                serverRequests.incrementAndGet();
                String authorization = request.getHeaders().get(HttpHeader.PROXY_AUTHORIZATION);
                if (authorization != null)
                {
                    proxyAuthorization.set(authorization);
                    response.setStatus(HttpStatus.NO_CONTENT_204);
                }
                else
                {
                    // A server that is not a proxy replies with a proxy authentication challenge.
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.getHeaders().put(HttpHeader.PROXY_AUTHENTICATE, "Basic realm=\"" + realm + "\"");
                }
            }
        });

        // No proxy is configured, so the request is sent directly to the server.
        URI serverURI = URI.create(scenario.getScheme() + "://localhost:" + connector.getLocalPort());
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(serverURI, realm, "user", "password"));

        ContentResponse response = client.newRequest("localhost", connector.getLocalPort())
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        // The 407 must not be handled, since the request was not sent to a proxy.
        assertEquals(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407, response.getStatus());
        assertEquals(1, serverRequests.get());
        assertNull(proxyAuthorization.get());
    }

    @Test
    public void testProxyAuthenticationRequiredFromServerThroughTunnelDoesNotLeakProxyCredentials() throws Exception
    {
        String proxyRealm = "proxyRealm";
        AtomicInteger serverRequests = new AtomicInteger();
        AtomicReference<String> leakedProxyAuthorization = new AtomicReference<>();
        // A secure server, reached through a tunnel, replies with a proxy authentication challenge.
        Scenario scenario = new SslScenario();
        startServer(scenario, new EmptyServerHandler()
        {
            @Override
            protected void service(org.eclipse.jetty.server.Request request, Response response)
            {
                serverRequests.incrementAndGet();
                String authorization = request.getHeaders().get(HttpHeader.PROXY_AUTHORIZATION);
                if (authorization != null)
                {
                    leakedProxyAuthorization.set(authorization);
                    response.setStatus(HttpStatus.NO_CONTENT_204);
                }
                else
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.getHeaders().put(HttpHeader.PROXY_AUTHENTICATE, "Basic realm=\"" + proxyRealm + "\"");
                }
            }
        });
        int proxyPort = startProxy(new ConnectHandler());
        startClient(scenario);

        String proxyHost = "localhost";
        URI proxyURI = URI.create(HttpScheme.HTTP.asString() + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, proxyRealm, "proxyUser", "proxyPassword"));
        client.getProxyConfiguration().addProxy(new HttpProxy(proxyHost, proxyPort));

        ContentResponse response = client.newRequest("localhost", connector.getLocalPort())
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        // The 407 comes from the server through the tunnel, not from the proxy,
        // so it must not be handled and the proxy credentials must not reach the server.
        assertEquals(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407, response.getStatus());
        assertEquals(1, serverRequests.get());
        assertNull(leakedProxyAuthorization.get());
    }

    @Test
    public void testUnauthorizedFromProxyForTunnelRequestIsNotHandled() throws Exception
    {
        String realm = "proxyRealm";
        AtomicInteger connectRequests = new AtomicInteger();
        AtomicInteger authorizedConnectRequests = new AtomicInteger();
        int proxyPort = startProxy(new Handler.Abstract()
        {
            @Override
            public boolean handle(org.eclipse.jetty.server.Request request, Response response, Callback callback)
            {
                if (HttpMethod.CONNECT.is(request.getMethod()))
                {
                    connectRequests.incrementAndGet();
                    if (request.getHeaders().contains(HttpHeader.AUTHORIZATION))
                        authorizedConnectRequests.incrementAndGet();
                }
                // Reply to the CONNECT request with a server authentication challenge.
                response.setStatus(HttpStatus.UNAUTHORIZED_401);
                response.getHeaders().put(HttpHeader.WWW_AUTHENTICATE, "Basic realm=\"" + realm + "\"");
                response.getHeaders().put(HttpFields.CONTENT_LENGTH_0);
                callback.succeeded();
                return true;
            }
        });
        Scenario scenario = new SslScenario();
        startClient(scenario);

        String proxyHost = "localhost";
        URI proxyURI = URI.create(HttpScheme.HTTP.asString() + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, realm, "user", "password"));
        client.getProxyConfiguration().addProxy(new HttpProxy(proxyHost, proxyPort));

        // Any port will do, the tunnel to the server is never established.
        int serverPort = proxyPort + 1;
        assertThrows(ExecutionException.class, () -> client.newRequest("localhost", serverPort)
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send());

        // The 401 response to the CONNECT request must not be handled,
        // so no credentials must be sent in a new CONNECT request.
        assertThat(connectRequests.get(), greaterThan(0));
        assertEquals(0, authorizedConnectRequests.get());
    }

    @Test
    public void testProxyAuthenticationForTunnelRequest() throws Exception
    {
        String proxyRealm = "proxyRealm";
        String user = "proxyUser";
        String password = "proxyPassword";
        String credentials = "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.ISO_8859_1));
        AtomicInteger connectRequests = new AtomicInteger();
        AtomicReference<String> leakedProxyAuthorization = new AtomicReference<>();
        Scenario scenario = new SslScenario();
        startServer(scenario, new EmptyServerHandler()
        {
            @Override
            protected void service(org.eclipse.jetty.server.Request request, Response response)
            {
                String authorization = request.getHeaders().get(HttpHeader.PROXY_AUTHORIZATION);
                if (authorization != null)
                    leakedProxyAuthorization.set(authorization);
                response.setStatus(HttpStatus.NO_CONTENT_204);
            }
        });
        int proxyPort = startProxy(new ConnectHandler()
        {
            @Override
            public boolean handle(org.eclipse.jetty.server.Request request, Response response, Callback callback) throws Exception
            {
                if (HttpMethod.CONNECT.is(request.getMethod()))
                {
                    connectRequests.incrementAndGet();
                    if (!credentials.equals(request.getHeaders().get(HttpHeader.PROXY_AUTHORIZATION)))
                    {
                        response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                        response.getHeaders().put(HttpHeader.PROXY_AUTHENTICATE, "Basic realm=\"" + proxyRealm + "\"");
                        response.getHeaders().put(HttpFields.CONTENT_LENGTH_0);
                        callback.succeeded();
                        return true;
                    }
                }
                return super.handle(request, response, callback);
            }
        });
        startClient(scenario);

        String proxyHost = "localhost";
        URI proxyURI = URI.create(HttpScheme.HTTP.asString() + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, proxyRealm, user, password));
        client.getProxyConfiguration().addProxy(new HttpProxy(proxyHost, proxyPort));

        // The 407 response to the CONNECT request comes from the proxy, so it must be handled.
        ContentResponse response = client.newRequest("localhost", connector.getLocalPort())
            .scheme(scenario.getScheme())
            .timeout(5, TimeUnit.SECONDS)
            .send();

        assertEquals(HttpStatus.NO_CONTENT_204, response.getStatus());
        assertEquals(2, connectRequests.get());
        // The proxy credentials are sent to the proxy only, never to the server.
        assertNull(leakedProxyAuthorization.get());
    }
}
