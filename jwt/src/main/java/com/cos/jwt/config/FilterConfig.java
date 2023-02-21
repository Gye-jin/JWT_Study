package com.cos.jwt.config;

import com.cos.jwt.filter.Myfilter1;
import com.cos.jwt.filter.Myfilter2;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

	@Bean
	public FilterRegistrationBean<Myfilter1> filter1(){
		FilterRegistrationBean<Myfilter1> bean = new FilterRegistrationBean<>(new Myfilter1());
		bean.addUrlPatterns("/*");
		bean.setOrder(1); // 낮은 번호가 필터 중에서 가장 먼저 실행됨.
		return bean;
	}
	@Bean
	public FilterRegistrationBean<Myfilter2> filter2(){
		FilterRegistrationBean<Myfilter2> bean = new FilterRegistrationBean<>(new Myfilter2());
		bean.addUrlPatterns("/*");
		bean.setOrder(0); // 낮은 번호가 필터 중에서 가장 먼저 실행됨.
		return bean;
	}
}
