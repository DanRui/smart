package com.smart.sso.client;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import com.alibaba.fastjson.JSON;
import com.smart.mvc.config.ConfigUtils;
import com.smart.mvc.exception.ServiceException;
import com.smart.mvc.model.Result;
import com.smart.mvc.util.SpringUtils;
import com.smart.mvc.util.StringUtils;
import com.smart.sso.rpc.AuthenticationRpcService;

/**
 * 单点登录权限系统Filter基类
 * 
 * @author Joe
 */
public abstract class ClientFilter implements Filter {

	// 单点登录服务端URL
	protected String ssoServerUrl;
	// 当前应用关联权限系统的应用编码
	protected String ssoAppCode;
	// 单点登录服务端提供的RPC服务，由Spring容器注入
	protected AuthenticationRpcService authenticationRpcService;

	// appId
	protected String appId;

	// appKey
	protected String appKey;

	// homeUrl
	protected String homeUrl;

	// unitInfo
	protected String unitInfo;

	// publicKeyFile
	protected String publicKeyFile;

	// privateKeyFile
	protected String privateKeyFile;

	// 排除拦截
	protected List<String> excludeList = null;
	
	private PathMatcher pathMatcher = null;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		if (StringUtils.isBlank(ssoServerUrl = ConfigUtils.getProperty("sso.server.url"))) {
			throw new IllegalArgumentException("ssoServerUrl不能为空");
		}
		if (StringUtils.isBlank(ssoAppCode = ConfigUtils.getProperty("sso.app.code"))) {
			throw new IllegalArgumentException("ssoAppCode不能为空");
		}
//		if ((authenticationRpcService = SpringUtils.getBean(AuthenticationRpcService.class)) == null) {
//			throw new IllegalArgumentException("authenticationRpcService注入失败");
//		}

		if (StringUtils.isBlank(appId = ConfigUtils.getProperty("appId"))) {
			throw new IllegalArgumentException("appId不能为空");
		}

		if (StringUtils.isBlank(appKey = ConfigUtils.getProperty("appKey"))) {
			throw new IllegalArgumentException("appKey不能为空");
		}

		if (StringUtils.isBlank(homeUrl = ConfigUtils.getProperty("homeUrl"))) {
			throw new IllegalArgumentException("homeUrl不能为空");
		}

		if (StringUtils.isBlank(unitInfo = ConfigUtils.getProperty("unitInfo"))) {
			throw new IllegalArgumentException("unitInfo不能为空");
		}

		if (StringUtils.isBlank(publicKeyFile = ConfigUtils.getProperty("publicKeyFile"))) {
			throw new IllegalArgumentException("publicKeyFile不能为空");
		}

		if (StringUtils.isBlank(privateKeyFile = ConfigUtils.getProperty("privateKeyFile"))) {
			throw new IllegalArgumentException("privateKeyFile不能为空");
		}
		
		String excludes = filterConfig.getInitParameter("excludes");
		if (StringUtils.isNotBlank(excludes)) {
			excludeList = Arrays.asList(excludes.split(","));
			pathMatcher = new AntPathMatcher();
		}
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		if (matchExcludePath(httpRequest.getServletPath()))
			chain.doFilter(request, response);
		else {
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			try {
				doFilter(httpRequest, httpResponse, chain);
			}
			catch (ServiceException e) {
				httpResponse.setContentType("application/json;charset=UTF-8");
				httpResponse.setStatus(HttpStatus.OK.value());
				PrintWriter writer = httpResponse.getWriter();
				writer.write(JSON.toJSONString(Result.create(e.getCode()).setMessage(e.getMessage())));
				writer.flush();
				writer.close();
			}
		}
	}
	
	private boolean matchExcludePath(String path) {
		if (excludeList != null) {
			for (String ignore : excludeList) {
				if (pathMatcher.match(ignore, path)) {
					return true;
				}
			}
		}
		return false;
	}

	public abstract void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException, ServiceException;

	@Override
	public void destroy() {
	}
}