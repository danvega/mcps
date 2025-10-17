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
}
