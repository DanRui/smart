package com.smart.sso.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URLEncoder;
import java.security.PublicKey;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.smart.mvc.exception.ServiceException;
import com.smart.mvc.util.MD5Utils;
import com.smart.mvc.util.RSAUtils;
import com.smart.mvc.util.StringUtils;
import com.smart.sso.rpc.RpcUser;
import org.apache.commons.codec.binary.Base64;
import org.apache.poi.util.StringUtil;

/**
 * 单点登录及Token验证Filter
 * 
 * @author Joe
 */
public class SsoFilter extends ClientFilter {

	// sso授权回调参数token名称
	//public static final String SSO_TOKEN_NAME = "__vt_param__";
	public static final String SSO_TOKEN_NAME = "JSSOSESSIONID";

	@Override
	public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String localToken = getLocalToken(request);
		System.out.println("localToken is: " + localToken);
		System.out.println("过滤的请求路径为：" + request.getRequestURL());
		String token = request.getParameter("JSSOSESSIONID");
		System.out.println("JSSOSESSIONID is: " + token);
		if (StringUtils.isBlank(token) && StringUtils.isBlank(localToken)) {
			if (getParameterToken(request) != null) {
				// 再跳转一次当前URL，以便去掉URL中token参数
				response.sendRedirect(request.getRequestURL().toString());
			}
			else
				redirectLogin(request, response);
		}
//		else if (isLogined(token))
		else if (getLocalToken(request) == null) {
			// token 不为空，则将token放到session中
			invokeAuthenticationInfoInSession(request, token, "admin");
			chain.doFilter(request, response);
		}else if (getLocalToken(request) != null) {
			chain.doFilter(request, response);
		}
		else
			redirectLogin(request, response);
	}

	/**
	 * 获取Session中token
	 * 
	 * @param request
	 * @return
	 */
	private String getLocalToken(HttpServletRequest request) {
		SessionUser sessionUser = SessionUtils.getSessionUser(request);
		return sessionUser == null ? null : sessionUser.getToken();
	}

	/**
	 * 获取服务端回传token参数且验证
	 * 
	 * @param request
	 * @return
	 * @throws IOException
	 */
	private String getParameterToken(HttpServletRequest request) throws IOException {
		String token = request.getParameter(SSO_TOKEN_NAME);
		if (token != null) {
//			RpcUser rpcUser = authenticationRpcService.findAuthInfo(token);
//			if (rpcUser != null) {
//				invokeAuthenticationInfoInSession(request, token, rpcUser.getAccount());
				return token;
//			}
		}
		return null;
	}

	/**
	 * 跳转登录
	 * 
	 * @param request
	 * @param response
	 * @throws IOException
	 */
	private void redirectLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
		if (isAjaxRequest(request)) {
			throw new ServiceException(SsoResultCode.SSO_TOKEN_ERROR, "未登录或已超时");
		}
		else {
			SessionUtils.invalidate(request);
			// 1.判断unitInfo是否合法(不做判断，由SSO校验)
			// 随机生成6位数
			long randomNum = (long)(Math.random() * 9 + 1) * 100000;

			String rdStr = String.valueOf(randomNum);

			// 获得当前时间戳
			long timestamp = new Date().getTime();

			String sign = "";
			sign = MD5Utils.getMD5Code(rdStr + timestamp + appId + appKey);

			//String basePath = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath() + "/";
			String backUrl = "";
			String retUrl = StringUtils.isBlank(request.getRequestURL()) ? request.getHeader("Referer") : request.getRequestURL().toString();
			if (StringUtils.isBlank(retUrl)) {
				backUrl = homeUrl;
			} else {
				backUrl = retUrl;
			}

			// 2.拼接字符串重定向到SSO登录页面
			StringBuilder sb = new StringBuilder(ssoServerUrl).append("/ssoLogin?");

			StringBuilder retUrlSb = new StringBuilder();
			retUrlSb.append("rd").append("=").append(rdStr)
					.append("&systemCode=").append(ssoAppCode)
					.append("&appId=").append(appId)
					.append("&sign=").append(sign)
					.append("&timestamp=").append(timestamp)
					.append("&unitInfo=").append(unitInfo)
					.append("&backUrl=").append(backUrl)
					.append("&reLogin=").append(true)
					.append("&token=").append(getParameterToken(request))
			;

			// 调用RSA加密算法将url后的参数进行加密，再传输到SSO解密处理
			try {

				// Check if the pair of keys are present else generate those.
				if (!RSAUtils.areKeysPresent(publicKeyFile, privateKeyFile)) {
					// Method generates a pair of keys using the RSA algorithm and
					// stores it
					// in their respective files
					RSAUtils.generateKey(publicKeyFile, privateKeyFile);
				}

				//final String originalText = "12345678901234567890123456789012";
				//final String originalText = "http://api.fsafx.cn/jsso/sso/user/ssoLogin?rd=800000&appCode=10001&appId=101001&sign=7fe2225c2dd3bc16f31f5b59afa49b3d&timestamp=1505475770803&unitInfo=QUIyRjNCNzdDREY4MzQ1Mw&backUrl=http://abk.fsafx.cn/&reLogin=true&token=null";
				System.out.println(retUrlSb.toString().getBytes().length);
				ObjectInputStream inputStream = null;

				// Encrypt the string using the public key
				inputStream = new ObjectInputStream(new FileInputStream(
						publicKeyFile));
				final PublicKey publicKey = (PublicKey) inputStream.readObject();
				final byte[] cipherText = RSAUtils.encrypt(retUrlSb.toString(), publicKey);

				// use String to hold cipher binary data
				Base64 base64 = new Base64();
				String cipherTextBase64 = base64.encodeToString(cipherText);

				// 2.拼接字符串重定向到SSO登录页面
				sb.append("retUrl=").append(URLEncoder.encode(cipherTextBase64,"UTF-8"));
			} catch (Exception e) {
				throw new RuntimeException("加密错误！");
			}

			response.sendRedirect(sb.toString());
		}
	}

	/**
	 * 保存认证信息到Session
	 * 
	 * @param token
	 * @param account
	 * @param request
	 */
	private void invokeAuthenticationInfoInSession(HttpServletRequest request, String token, String account) {
		SessionUtils.setSessionUser(request, new SessionUser(token, account));
	}

	/**
	 * 是否已登录
	 * 
	 * @param token
	 * @return
	 */
	private boolean isLogined(String token) {
		return authenticationRpcService.validate(token);
	}

	/**
	 * 是否Ajax请求
	 * 
	 * @param request
	 * @return
	 */
	private boolean isAjaxRequest(HttpServletRequest request) {
		String requestedWith = request.getHeader("X-Requested-With");
		return requestedWith != null ? "XMLHttpRequest".equals(requestedWith) : false;
	}
}