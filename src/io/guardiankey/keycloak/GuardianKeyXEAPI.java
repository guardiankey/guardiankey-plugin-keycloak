package io.guardiankey.keycloak;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class GuardianKeyXEAPI {

    private boolean enabled = true;
    private boolean verbose = false;
    private String apiUrl = "https://api.guardiankey.io/";
    private String orgId = "";
    private String authGroupId = "";
    private String apiKey = "";
    private String keyB64 = "";
    private String ivB64 = "";
    private String salt = "";
    private String agentId = "KeyCloakServer";
    private String service = "KeyCloak";
    private boolean reverse = true;
    private byte[] anonKey;
    private byte[] anonIv;

    public void setConfig(Map<String, String> config) {
        if (config == null) return;
        if (config.get("guardiankey.xe.enable") != null)
            this.enabled = "true".equals(config.get("guardiankey.xe.enable"));
        if (config.get("guardiankey.xe.verbose") != null)
            this.verbose = "true".equals(config.get("guardiankey.xe.verbose"));
        if (config.get("guardiankey.xe.apiurl") != null && !config.get("guardiankey.xe.apiurl").isEmpty())
            this.apiUrl = config.get("guardiankey.xe.apiurl").replaceAll("/$", "") + "/";
        if (config.get("guardiankey.xe.orgid") != null)
            this.orgId = config.get("guardiankey.xe.orgid");
        if (config.get("guardiankey.xe.authgroupid") != null)
            this.authGroupId = config.get("guardiankey.xe.authgroupid");
        if (config.get("guardiankey.xe.apikey") != null)
            this.apiKey = config.get("guardiankey.xe.apikey");
        if (config.get("guardiankey.xe.key") != null)
            this.keyB64 = config.get("guardiankey.xe.key");
        if (config.get("guardiankey.xe.iv") != null)
            this.ivB64 = config.get("guardiankey.xe.iv");
        if (config.get("guardiankey.xe.salt") != null)
            this.salt = config.get("guardiankey.xe.salt");
        if (config.get("guardiankey.xe.agentid") != null && !config.get("guardiankey.xe.agentid").isEmpty())
            this.agentId = config.get("guardiankey.xe.agentid");
        if (config.get("guardiankey.xe.service") != null && !config.get("guardiankey.xe.service").isEmpty())
            this.service = config.get("guardiankey.xe.service");
        if (config.get("guardiankey.xe.reverse") != null)
            this.reverse = "true".equals(config.get("guardiankey.xe.reverse"));

        String ak = config.get("guardiankey.xe.anonkey");
        String aiv = config.get("guardiankey.xe.anoniv");
        this.anonKey = (ak != null && !ak.isEmpty()) ? Base64.getDecoder().decode(ak) : null;
        this.anonIv  = (aiv != null && !aiv.isEmpty()) ? Base64.getDecoder().decode(aiv) : null;

        if ((this.apiKey == null || this.apiKey.isEmpty()) && !this.keyB64.isEmpty() && !this.ivB64.isEmpty()) {
            this.apiKey = sha256Hex(this.keyB64 + this.ivB64);
        }
    }

    public boolean isEnabled() { return enabled; }
    public boolean isVerbose() { return verbose; }
    public String getAuthGroupId() { return authGroupId; }

    public String getSalt() {
        if (salt != null && !salt.isEmpty()) return salt;
        return sha1Hex(apiKey + authGroupId);
    }

    public String anonymizeUsername(String username) {
        if (anonKey == null || anonIv == null || username == null) return username;
        try {
            IvParameterSpec iv = new IvParameterSpec(anonIv);
            SecretKeySpec sk = new SecretKeySpec(anonKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, sk, iv);
            return Base64.getEncoder().encodeToString(cipher.doFinal(username.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return username;
        }
    }

    private Map<String, Object> buildBackendData(String username, String email, boolean loginFailed,
                                                  String eventType, String clientIP, String userAgent,
                                                  String secChUa, String secChUaMobile, String secChUaPlatform) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("generatedTime", System.currentTimeMillis() / 1000);
        b.put("agentId", agentId);
        b.put("organizationId", orgId);
        b.put("authGroupId", authGroupId);
        b.put("service", service);
        b.put("clientIP", clientIP != null ? clientIP : "");
        String clientReverse = "";
        if (reverse && clientIP != null && !clientIP.isEmpty()) {
            try {
                clientReverse = InetAddress.getByName(clientIP).getCanonicalHostName();
            } catch (Exception e) {
                clientReverse = "";
            }
        }
        b.put("clientReverse", clientReverse);
        b.put("userName", anonymizeUsername(username != null ? username : ""));
        b.put("authMethod", "");
        b.put("loginFailed", loginFailed ? "1" : "0");
        b.put("userAgent", userAgent != null ? userAgent : "");
        b.put("psychometricTyped", "");
        b.put("psychometricImage", "");
        b.put("event_type", eventType != null ? eventType : "Authentication");
        b.put("userEmail", (email != null && (anonKey == null)) ? email : "");
        b.put("sec_ch_ua", secChUa != null ? secChUa : "");
        b.put("sec_ch_ua_mobile", secChUaMobile != null ? secChUaMobile : "");
        b.put("sec_ch_ua_platform", secChUaPlatform != null ? secChUaPlatform : "");
        return b;
    }

    private Map<String, Object> buildFrontendData(String gkasSolution, String url, String saltVal,
                                                   String once, String timeVal) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("gkas_solution", gkasSolution != null ? gkasSolution : "");
        f.put("url", url != null ? url : "");
        f.put("salt", saltVal != null ? saltVal : "");
        f.put("once", once != null ? once : "");
        f.put("time", timeVal != null ? timeVal : String.valueOf(System.currentTimeMillis() / 1000));
        return f;
    }

    public Map<String, Object> checkAccessXE(KeycloakSession session,
                                              String username, String email, boolean loginFailed,
                                              String eventType, String clientIP, String userAgent,
                                              String secChUa, String secChUaMobile, String secChUaPlatform,
                                              String gkasSolution, String url, String saltVal,
                                              String once, String timeVal) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", authGroupId);
        body.put("backend_data", buildBackendData(username, email, loginFailed, eventType, clientIP,
                userAgent, secChUa, secChUaMobile, secChUaPlatform));
        body.put("frontend_data", buildFrontendData(gkasSolution, url, saltVal, once, timeVal));

        Gson gson = new GsonBuilder().create();
        final String json = gson.toJson(body);
        final String endpoint = apiUrl + "v3/gkas/" + authGroupId + "/checkaccessxe";
        if (verbose) {
            System.out.println("GuardianKeyXEAPI POST " + endpoint);
            System.out.println("GuardianKeyXEAPI body: " + json);
        }

        final HttpClientProvider provider = session.getProvider(HttpClientProvider.class);
        final CloseableHttpClient client = provider.getHttpClient();

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Map<String, Object>> future = executor.submit(new Callable<Map<String, Object>>() {
            @Override
            public Map<String, Object> call() {
                return doPost(client, endpoint, json);
            }
        });
        executor.shutdown();

        Map<String, Object> result = null;
        try {
            result = future.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            if (verbose) System.out.println("GuardianKeyXEAPI timeout/error: " + e.getMessage());
        }
        if (!executor.isTerminated()) executor.shutdownNow();

        if (result == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("response", "ERROR");
            return err;
        }
        if (!result.containsKey("response")) {
            result.put("response", "ERROR");
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> doPost(CloseableHttpClient client, String url, String body) {
        try {
            HttpPost post = new HttpPost(url);
            post.setHeader("Content-Type", "application/json");
            post.setHeader("X-Api-Key", apiKey);
            post.setEntity(new StringEntity(body, StandardCharsets.UTF_8));
            HttpResponse response = client.execute(post);
            int sc = response.getStatusLine().getStatusCode();
            if (sc != 200) {
                if (verbose) System.out.println("GuardianKeyXEAPI POST error: " + response.getStatusLine());
                return null;
            }
            HttpEntity entity = response.getEntity();
            String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
            if (verbose) System.out.println("GuardianKeyXEAPI POST response: " + json);
            Gson gson = new GsonBuilder().create();
            return gson.fromJson(json, Map.class);
        } catch (Exception e) {
            if (verbose) e.printStackTrace();
            return null;
        }
    }

    private static String sha1Hex(String input) {
        return hashHex("SHA-1", input);
    }

    private static String sha256Hex(String input) {
        return hashHex("SHA-256", input);
    }

    private static String hashHex(String algorithm, String input) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
