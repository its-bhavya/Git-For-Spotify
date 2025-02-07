package com.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.awt.Desktop;

import org.json.JSONObject;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import io.github.cdimascio.dotenv.Dotenv;
import se.michaelthelin.spotify.SpotifyApi;
import se.michaelthelin.spotify.SpotifyHttpManager;
import se.michaelthelin.spotify.model_objects.credentials.AuthorizationCodeCredentials;
import se.michaelthelin.spotify.requests.authorization.authorization_code.AuthorizationCodeRequest;

public class SpotifyAuth {
    private static final Dotenv dotenv = Dotenv.load();

    //imported the app credentials from .env file in the directory 
    private static final String CLIENT_ID = dotenv.get("CLIENT_ID");
    private static final String CLIENT_SECRET = dotenv.get("CLIENT_SECRET");
    private static final String REDIRECT_URI = dotenv.get("REDIRECT_URI");

    private static final String AUTH_URL = "https://accounts.spotify.com/authorize";
    private static final String TOKEN_URL = "https://accounts.spotify.com/api/token";
    protected static String authCode = "";
    protected static String access_tok = "";

    protected static final SpotifyApi spotifyApi = new SpotifyApi.Builder()
        .setClientId(CLIENT_ID)
        .setClientSecret(CLIENT_SECRET)
        .setRedirectUri(SpotifyHttpManager.makeUri(REDIRECT_URI))
        .build();

    public static void main(String[] args) throws Exception {
        String state = UUID.randomUUID().toString();

        //defining the scope of our app
        String scope = "playlist-read-private playlist-read-collaborative playlist-modify-private playlist-modify-public user-read-private";

        String authRequestURL = AUTH_URL + "?client_id=" + CLIENT_ID +
                "&response_type=code" +
                "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8) +
                "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8) +
                "&state=" + state;

        // Open browser for authentication
        Desktop.getDesktop().browse(new URI(authRequestURL));

        // Start a local server to listen for the callback
        startServer();
    }

    private static void startServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/", new SpotifyCallbackHandler());
        server.setExecutor(null);
        System.out.println("Waiting for Spotify authorization...");
        server.start();
    }

    static class SpotifyCallbackHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            Map<String, String> params = getQueryParams(query);
        
            try {
                if (params.containsKey("code")) {
                    authCode = params.get("code");
                    String response = "Authorization successful! You can close this window.";
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                    
                    // Now fetch the access token and set it
                    fetchAccessToken(authCode);
                    
                    System.exit(0); // Stop server after authentication
                } else {
                    String response = "Authorization failed!";
                    exchange.sendResponseHeaders(400, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } catch (Exception e) {
                System.out.println("Error occurred: " + e.getMessage());
            }
        }        
    }

    private static void fetchAccessToken(String code) throws IOException {
        try {
            URL url = new URI(TOKEN_URL).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Authorization", "Basic " + 
                Base64.getEncoder().encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8)));
    
            String postData = "grant_type=authorization_code" +
                    "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8) +
                    "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8);
    
            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData.getBytes(StandardCharsets.UTF_8));
            }
    
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("Failed to retrieve access token: " + conn.getResponseCode());
            }
    
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String response = br.readLine();
                JSONObject jsonResponse = new JSONObject(response);
                String accessToken = jsonResponse.getString("access_token");
                access_tok = accessToken; // Set the global variable
                System.out.println("\nAccess Token: " + accessToken);

                // Now set the access token in the SpotifyApi instance
                spotifyApi.setAccessToken(accessToken);
            }
        } catch (IOException | URISyntaxException e) {
            System.out.println("Error occurred: " + e.getMessage());
        }
    }

    private static Map<String, String> getQueryParams(String query) {
        Map<String, String> params = new HashMap<>();
        if (query != null) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=");
                if (pair.length > 1) {
                    params.put(pair[0], pair[1]);
                }
            }
        }
        return params;
    }
}
