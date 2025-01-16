package com.example.security.authorization.security;

import com.example.security.authorization.model.RequiresPermission;
import com.example.security.authorization.services.RbacService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.lang.reflect.Method;

@Component
public class RbacFilter implements HandlerInterceptor {
    @Autowired
    private RbacService rbacService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            Method method = handlerMethod.getMethod();

            if (method.isAnnotationPresent(RequiresPermission.class)) {
                RequiresPermission requiresPermission = method.getAnnotation(RequiresPermission.class);
                String permission = requiresPermission.permission();

                if (!rbacService.hasPermission(permission)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
                    return false;
                }
            }
        }

        return true;
    }
}
