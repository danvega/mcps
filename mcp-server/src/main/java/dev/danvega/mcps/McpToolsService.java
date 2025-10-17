package dev.danvega.mcps;

import org.springaicommunity.mcp.annotation.McpTool;
import org.springaicommunity.mcp.annotation.McpToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@Service
public class McpToolsService {

    @McpTool(name = "echo", description = "Echo back a message with timestamp")
    public String echo(@McpToolParam(description = "Message to echo", required = true) String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        return String.format("[%s] Echo: %s", timestamp, message);
    }

    @McpTool(name = "getCurrentUser", description = "Get information about the currently authenticated user")
    public Map<String, Object> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("name", authentication.getName());
        userInfo.put("authenticated", authentication.isAuthenticated());
        userInfo.put("authorities", authentication.getAuthorities().stream()
                .map(Object::toString)
                .toList());

        return userInfo;
    }

    @McpTool(name = "getServerStatus", description = "Get server status (admin only)")
    @PreAuthorize("hasAuthority('SCOPE_admin') or hasRole('ADMIN')")
    public Map<String, Object> getServerStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "healthy");
        status.put("uptime", "running");
        status.put("timestamp", LocalDateTime.now().toString());
        status.put("javaVersion", System.getProperty("java.version"));
        status.put("memoryUsage", getMemoryInfo());

        return status;
    }

    private Map<String, Long> getMemoryInfo() {
        Runtime runtime = Runtime.getRuntime();
        Map<String, Long> memInfo = new HashMap<>();
        memInfo.put("totalMemory", runtime.totalMemory());
        memInfo.put("freeMemory", runtime.freeMemory());
        memInfo.put("maxMemory", runtime.maxMemory());
        memInfo.put("usedMemory", runtime.totalMemory() - runtime.freeMemory());
        return memInfo;
    }
}
