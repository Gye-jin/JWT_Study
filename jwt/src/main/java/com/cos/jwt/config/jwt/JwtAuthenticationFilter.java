package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.JwtProperties;
import com.cos.jwt.config.AUTH.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// login 요청해서 username, password 전송하면(post)
// usernamepasswordAuthenticationFilter 동작을 함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;

	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("로그인 시도");

		// 1. username,password 받아서
		try {
//			BufferedReader br = request.getReader();
//			String input = null;
//			while((input=br.readLine()) !=null) {
//				System.out.println(input);
//			}

			ObjectMapper om = new ObjectMapper();
			User user;
			user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);

			UsernamePasswordAuthenticationToken tuthenticationToken = new UsernamePasswordAuthenticationToken(
					user.getUsername(), user.getPassword());

			// PrincipalDetailsService의 loaduserbyusername() 함수가 실행된 후 정상이면 authentication이 리턴됨.
			// db에 있는 username과 password가 일치한다.
			Authentication authentication = authenticationManager.authenticate(tuthenticationToken);

			// authentication 객체가 session 영역에 저장됨 => 로그인이 되었다는 뜻임.
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인완료"+principalDetails.getUser().getUsername());
			// authentication 객체가 세션 영역에 저장을 해야하고 그방법이 reeturn 해주면 됨.
			// 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임.
			// 굳이 jwt토큰을 사용하면서 세션을 만들 이유가 없음, 근데 단지 권한 처리 때문에 session영역에 넣어줌.
			return authentication;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		;
		// 2. 정상인지 로그인 시도를 해봄AuthenticationManager로 로그인 시도를 하면 principledetailsservice가
		// 호출되며 loaduserbyusername 호출.
		// 3. princiapldetails를 세션에 담고(권한 관리를 위해서 )
		// 4. jwt 토큰을 만들어서 응답함.
		return null;
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 succssfulAuthentication 함수가 피룡
	// jwt 토큰을 만들어서  request요청한 사용자에게 jwt 토큰을 response해줌.
	// RSA 방식이 아닌 Hash암호방식 HMAC512
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX);
	}

}
