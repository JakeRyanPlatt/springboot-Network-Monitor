package com.example.demo;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
public class DiagnosticsController {

    @GetMapping("/ping")
    public ResponseEntity<Map<String, Object>> ping(
            @RequestParam("host") String host
    ) {
        Map<String, Object> result = new HashMap<>();
        result.put("host", host);
        result.put("timestamp", Instant.now().toString());

        if (host == null || host.isBlank()) {
            result.put("error", "Host is required");
            return ResponseEntity.badRequest().body(result);
        }

        // Very basic validation: avoid spaces to reduce injection risk
        if (host.chars().anyMatch(Character::isWhitespace)) {
            result.put("error", "Invalid host");
            return ResponseEntity.badRequest().body(result);
        }

        try {
            // Linux-style ping: 1 packet
            Process process = new ProcessBuilder("ping", "-c", "1", host)
                    .redirectErrorStream(true)
                    .start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            result.put("exitCode", exitCode);
            result.put("rawOutput", output.toString());

            boolean reachable = (exitCode == 0);
            result.put("reachable", reachable);

            // crude latency extraction (optional, can refine later)
            String out = output.toString();
            String latencyMs = null;
            // look for "time=XX.x ms"
            int idx = out.indexOf("time=");
            if (idx != -1) {
                int end = out.indexOf(" ms", idx);
                if (end != -1) {
                    latencyMs = out.substring(idx + 5, end).trim();
                }
            }
            result.put("latencyMs", latencyMs);

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            result.put("error", "Exception: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

    @GetMapping("/dns-lookup")
    public ResponseEntity<Map<String, Object>> dnsLookup(
            @RequestParam("host") String host
    ) {
        Map<String, Object> result = new HashMap<>();
        result.put("host", host);
        result.put("timestamp", Instant.now().toString());

        if (host == null || host.isBlank()) {
            result.put("error", "Host is required");
            return ResponseEntity.badRequest().body(result);
        }

        try {
            var addr = java.net.InetAddress.getByName(host);
            result.put("hostAddress", addr.getHostAddress());
            result.put("canonicalHostName", addr.getCanonicalHostName());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            result.put("error", "DNS lookup failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(result);
        }
    } 
    @GetMapping("/traceroute")
    public ResponseEntity<Map<String, Object>> traceroute(
            @RequestParam("host") String host
    ) {
        Map<String, Object> result = new HashMap<>();
        result.put("host", host);
        result.put("timestamp", Instant.now().toString());

        if (host == null || host.isBlank()) {
            result.put("error", "Host is required");
            return ResponseEntity.badRequest().body(result);
        }

        if (host.chars().anyMatch(Character::isWhitespace)) {
            result.put("error", "Invalid host");
            return ResponseEntity.badRequest().body(result);
        }

        try {
            Process process = new ProcessBuilder("traceroute", host)
                    .redirectErrorStream(true)
                    .start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            result.put("exitCode", exitCode);
            result.put("rawOutput", output.toString());

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            result.put("error", "Exception: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }
    @GetMapping("/port-scan")
    public ResponseEntity<Map<String, Object>> portScan(
            @RequestParam("host") String host,
            @RequestParam("fromPort") int fromPort,
            @RequestParam("toPort") int toPort
    ) {
        Map<String, Object> result = new HashMap<>();
        result.put("host", host);
        result.put("fromPort", fromPort);
        result.put("toPort", toPort);
        result.put("timestamp", Instant.now().toString());

        // Basic validation
        if (host == null || host.isBlank()) {
            result.put("error", "Host is required");
            return ResponseEntity.badRequest().body(result);
        }
        if (host.chars().anyMatch(Character::isWhitespace)) {
            result.put("error", "Invalid host");
            return ResponseEntity.badRequest().body(result);
        }
        if (fromPort < 1 || toPort > 65535 || fromPort > toPort) {
            result.put("error", "Invalid port range");
            return ResponseEntity.badRequest().body(result);
        }
        // Prevent crazy-wide scans for now
        if (toPort - fromPort > 2000) {
            result.put("error", "Port range too large (max 2000 ports for this endpoint)");
            return ResponseEntity.badRequest().body(result);
        }

        try {
            java.net.InetAddress address = java.net.InetAddress.getByName(host);
            result.put("resolvedAddress", address.getHostAddress());

            java.util.List<Integer> openPorts = new java.util.ArrayList<>();
            java.util.List<Integer> closedPorts = new java.util.ArrayList<>();

            int timeoutMs = 200; // 0.2s per port, tune as needed

            for (int port = fromPort; port <= toPort; port++) {
                try (java.net.Socket socket = new java.net.Socket()) {
                    java.net.SocketAddress sockAddr =
                            new java.net.InetSocketAddress(address, port);
                    socket.connect(sockAddr, timeoutMs);
                    openPorts.add(port);
                } catch (Exception e) {
                    // Could not connect (timeout / refused)
                    closedPorts.add(port);
                }
            }

            result.put("openPorts", openPorts);
            result.put("closedPorts", closedPorts);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            result.put("error", "Exception: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }
}
