package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthrizationFilter;
import com.cos.jwt.filter.Myfilter1;
import com.cos.jwt.filter.Myfilter3;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final CorsFilter corsfilter;
	private final UserRepository userrepository;
	
	// 해당 메소드의 리턴되는 오브젝트를 ioc로 등록해줌.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
			http.addFilterBefore(new Myfilter3(), SecurityContextPersistenceFilter.class);
			http.csrf().disable();	// csrf토큰이 있어야 post, put 등의 방식으로 보호가능하지만, restfulapi는 이미 보호가 됨.
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(corsfilter)	// 기존의 crossorigin(인증 x), 시큐리티 필터에 등록 인증(o)
			.formLogin().disable()
			.httpBasic().disable()	// 유저의 아이디와 패스워드를 통해 인증을 진행함(기본 인증방식).
			.addFilter(new JwtAuthenticationFilter(authenticationManager()))	//authenticationManager
			.addFilter(new JwtAuthrizationFilter(authenticationManager(),userrepository))	//authenticationManager
			.authorizeRequests()
			.antMatchers("/api/v1/user/**")
			.access("hasRole('ROLE_USER')or hasRole('ROLE_MANAGER')or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER')or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/admin/**")
			.access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll();
			
			
	}

}
