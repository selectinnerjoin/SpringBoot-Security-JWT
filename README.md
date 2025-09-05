# Spring Boot JWT

![](https://img.shields.io/badge/build-success-brightgreen.svg)

# Stack

![](https://img.shields.io/badge/java_11-✓-blue.svg)
![](https://img.shields.io/badge/spring_boot-✓-blue.svg)
![](https://img.shields.io/badge/postsq-✓-blue.svg)
![](https://img.shields.io/badge/jwt-✓-blue.svg)

***

<h3 align="center">Please help this repo with a :star: if you find it useful! :blush:</h3>

***

# File structure

```
spring-boot-jwt/
 │
 ├── src/main/java/com/web/
 │   └── backend
 │       ├── controller
 │       │   └── AuthRestAPIs.java
 │       │   └── TestRestAPIs.java
 │       │
 │       ├── exception
 │       │   └──  EmailAlreadyExistsException.java
 │       │   └── GroupAlreadyExistsException.java
 │       │   ├── RoleNotFoundException.java
 │       │   └── UsernameAlreadyExistsException.java
 │       │
 │       ├── payload
 │ 		 │       ├── request
 │		 │       │   └── LoginRequest.java
 │		 │       │   └── SignupRequest.java
 │		 │		 │
 │ 		 │       └── response
 │       │   	 	 └── JwtResponse.java
 │       │           └── MessageResponse.java
 │       │
 │       ├── model
 │       │   └──  Role.java
 │       │   └── RoleName.java
 │       │   └── User.java
 │       │
 │       ├── repository
 │       │   └── RoleRepository.java
 │       │   └── UserRepository.java
 │       │
 │       ├── security
 │ 		 │       ├── service
 │		 │       │   └── UserDetailsServiceImpl.java
 │		 │       │   └── UserPrinciple.java
 │		 │		 │
 │ 		 │       ├── jwt
 │       │   	 │	 └── JwtAuthenticationSuccessHandler.java
 │       │       │   └── JwtAuthEntryPoint.java
 │       │       │   └── JwtAuthTokenFilter.java
 │       │       │   └── JwtProvider.java
 │       │       │
 │       │ 		 └── WebSecurityConfig.java
 │       │
 │       └──BackendApplication.java
 │
 ├── src/main/resources/
 │   └── application.properties
 │
 ├── .gitignore
 ├── LICENSE
 ├── mvnw/mvnw.cmd
 ├── README.md
 └── pom.xml
```

# Introduction (https://jwt.io)

Just to throw some background in, we have a wonderful introduction, courtesy of **jwt.io**! Let’s take a look:

## What is JSON Web Token?

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA.

Let's explain some concepts of this definition further.

**Compact**: Because of their smaller size, JWTs can be sent through a URL, POST parameter, or inside an HTTP header. Additionally, the smaller size means transmission is fast.

**Self-contained**: The payload contains all the required information about the user, avoiding the need to query the database more than once.

## When should you use JSON Web Tokens?

Here are some scenarios where JSON Web Tokens are useful:

**Authentication**: This is the most common scenario for using JWT. Once the user is logged in, each subsequent request will include the JWT, allowing the user to access routes, services, and resources that are permitted with that token. Single Sign On is a feature that widely uses JWT nowadays, because of its small overhead and its ability to be easily used across different domains.

**Information Exchange**: JSON Web Tokens are a good way of securely transmitting information between parties. Because JWTs can be signed—for example, using public/private key pairs—you can be sure the senders are who they say they are. Additionally, as the signature is calculated using the header and the payload, you can also verify that the content hasn't been tampered with.

## What is the JSON Web Token structure?

JSON Web Tokens consist of three parts separated by dots **(.)**, which are:

1. Header
2. Payload
3. Signature

Therefore, a JWT typically looks like the following.

`xxxxx`.`yyyyy`.`zzzzz`

Let's break down the different parts.

**Header**

The header typically consists of two parts: the type of the token, which is JWT, and the hashing algorithm being used, such as HMAC SHA256 or RSA.

For example:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Then, this JSON is Base64Url encoded to form the first part of the JWT.

**Payload**

The second part of the token is the payload, which contains the claims. Claims are statements about an entity (typically, the user) and additional metadata. There are three types of claims: reserved, public, and private claims.

- **Reserved claims**: These are a set of predefined claims which are not mandatory but recommended, to provide a set of useful, interoperable claims. Some of them are: iss (issuer), exp (expiration time), sub (subject), aud (audience), and others.

> Notice that the claim names are only three characters long as JWT is meant to be compact.

- **Public claims**: These can be defined at will by those using JWTs. But to avoid collisions they should be defined in the IANA JSON Web Token Registry or be defined as a URI that contains a collision resistant namespace.

- **Private claims**: These are the custom claims created to share information between parties that agree on using them.

An example of payload could be:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

The payload is then Base64Url encoded to form the second part of the JSON Web Token.

**Signature**

To create the signature part you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.

For example if you want to use the HMAC SHA256 algorithm, the signature will be created in the following way:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

The signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.
Putting all together

The output is three Base64 strings separated by dots that can be easily passed in HTML and HTTP environments, while being more compact when compared to XML-based standards such as SAML.

The following shows a JWT that has the previous header and payload encoded, and it is signed with a secret. Encoded JWT

![](https://camo.githubusercontent.com/a56953523c443d6a97204adc5e39b4b8c195b453/68747470733a2f2f63646e2e61757468302e636f6d2f636f6e74656e742f6a77742f656e636f6465642d6a7774332e706e67)

## How do JSON Web Tokens work?

In authentication, when the user successfully logs in using their credentials, a JSON Web Token will be returned and must be saved locally (typically in local storage, but cookies can be also used), instead of the traditional approach of creating a session in the server and returning a cookie.

Whenever the user wants to access a protected route or resource, the user agent should send the JWT, typically in the Authorization header using the Bearer schema. The content of the header should look like the following:

`Authorization: Bearer <token>`

This is a stateless authentication mechanism as the user state is never saved in server memory. The server's protected routes will check for a valid JWT in the Authorization header, and if it's present, the user will be allowed to access protected resources. As JWTs are self-contained, all the necessary information is there, reducing the need to query the database multiple times.

This allows you to fully rely on data APIs that are stateless and even make requests to downstream services. It doesn't matter which domains are serving your APIs, so Cross-Origin Resource Sharing (CORS) won't be an issue as it doesn't use cookies.

The following diagram shows this process:

![](https://camo.githubusercontent.com/5871e9f0234542cd89bab9b9c100b20c9eb5b789/68747470733a2f2f63646e2e61757468302e636f6d2f636f6e74656e742f6a77742f6a77742d6469616772616d2e706e67) 

# JWT Authentication Summary

Token based authentication schema's became immensely popular in recent times, as they provide important benefits when compared to sessions/cookies:

- CORS
- No need for CSRF protection
- Better integration with mobile
- Reduced load on authorization server
- No need for distributed session store

Some trade-offs have to be made with this approach:

- More vulnerable to XSS attacks
- Access token can contain outdated authorization claims (e.g when some of the user privileges are revoked)
- Access tokens can grow in size in case of increased number of claims
- File download API can be tricky to implement
- True statelessness and revocation are mutually exclusive

**JWT Authentication flow is very simple**

1. User obtains Refresh and Access tokens by providing credentials to the Authorization server
2. User sends Access token with each request to access protected API resource
3. Access token is signed and contains user identity (e.g. user id) and authorization claims.

It's important to note that authorization claims will be included with the Access token. Why is this important? Well, let's say that authorization claims (e.g user privileges in the database) are changed during the life time of Access token. Those changes will not become effective until new Access token is issued. In most cases this is not big issue, because Access tokens are short-lived. Otherwise go with the opaque token pattern.

# Implementation Details

Let's see how can we implement the JWT token based authentication using Java and Spring, while trying to reuse the Spring security default behavior where we can. The Spring Security framework comes with plug-in classes that already deal with authorization mechanisms such as: session cookies, HTTP Basic, and HTTP Digest. Nevertheless, it lacks from native support for JWT, and we need to get our hands dirty to make it work.

## POSTGRES DB

This demo is currently using an POSTGRES database called **test_db** 


```
server.port=${SERVER_PORT:8080}
server.servlet.context-path=${API_BASE_PATH:/api}

springfox.documentation.swagger-ui.base-url=/documentation
springfox.documentation.swagger.v2.use-model-v3=false
logging.level.springfox.documentation=DEBUG

spring.datasource.url= jdbc:postgresql://${POSTGRES_HOST:localhost}:${POSTGRES_PORT:5432}/${POSTGRES_DB:Spring}?useSSL=false&useUnicode=yes&characterEncoding=UTF-8
spring.datasource.username= ${POSTGRES_USER:postgres}
spring.datasource.password= ${POSTGRES_PASSWORD:123456}

spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation= true
spring.jpa.properties.hibernate.dialect= org.hibernate.dialect.PostgreSQLDialect

# Hibernate ddl auto (create, create-drop, validate, update)
spring.jpa.hibernate.ddl-auto= update

jwt.secret= ${JWT_SECRET:R1BYcTVXVGNDU2JmWHVnZ1lnN0FKeGR3cU1RUU45QXV4SDJONFZ3ckhwS1N0ZjNCYVkzZ0F4RVBSS1UzRENwRw==}
jwt.expirationms= ${JWT_EXPIRATIONMS:86400000}
```



## Core Code

1. `JwtTokenFilter`
2. `JwtTokenFilterConfigurer`
3. `JwtTokenProvider`
4. `MyUserDetails`
5. `WebSecurityConfig`

**JwtTokenFilter**

The `JwtTokenFilter` filter is applied to each API (`/**`) with exception of the signin token endpoint (`/users/signin`) and singup endpoint (`/users/signup`).

This filter has the following responsibilities:

1. Check for access token in Authorization header. If Access token is found in the header, delegate authentication to `JwtTokenProvider` otherwise throw authentication exception
2. Invokes success or failure strategies based on the outcome of authentication process performed by JwtTokenProvider

Please ensure that `chain.doFilter(request, response)` is invoked upon successful authentication. You want processing of the request to advance to the next filter, because very last one filter *FilterSecurityInterceptor#doFilter* is responsible to actually invoke method in your controller that is handling requested API resource.

```java
String token = jwtTokenProvider.resolveToken((HttpServletRequest) req);
if (token != null && jwtTokenProvider.validateToken(token)) {
  Authentication auth = jwtTokenProvider.getAuthentication(token);
  SecurityContextHolder.getContext().setAuthentication(auth);
}
filterChain.doFilter(req, res);
```

**JwtTokenFilterConfigurer**

Adds the `JwtTokenFilter` to the `DefaultSecurityFilterChain` of spring boot security.

```java
JwtTokenFilter customFilter = new JwtTokenFilter(jwtTokenProvider);
http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
```

**JwtTokenProvider**

The `JwtTokenProvider` has the following responsibilities:

1. Verify the access token's signature
2. Extract identity and authorization claims from Access token and use them to create UserContext
3. If Access token is malformed, expired or simply if token is not signed with the appropriate signing key Authentication exception will be thrown

**MyUserDetails**

Implements `UserDetailsService` in order to define our own custom *loadUserbyUsername* function. The `UserDetailsService` interface is used to retrieve user-related data. It has one method named *loadUserByUsername* which finds a user entity based on the username and can be overridden to customize the process of finding the user.

It is used by the `DaoAuthenticationProvider` to load details about the user during authentication.

**WebSecurityConfig**

The `WebSecurityConfig` class extends `WebSecurityConfigurerAdapter` to provide custom security configuration.

Following beans are configured and instantiated in this class:

1. `JwtTokenFilter`
3. `PasswordEncoder`

Also, inside `WebSecurityConfig#configure(HttpSecurity http)` method we'll configure patterns to define protected/unprotected API endpoints. Please note that we have disabled CSRF protection because we are not using Cookies.

```java
// Disable CSRF (cross site request forgery)
http.csrf().disable();

// No session will be created or used by spring security
http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

// Entry points
http.authorizeRequests()//
  .antMatchers("/users/signin").permitAll()//
  .antMatchers("/users/signup").permitAll()//
  // Disallow everything else..
  .anyRequest().authenticated();

// If a user try to access a resource without having enough permissions
http.exceptionHandling().accessDeniedPage("/login");

// Apply JWT
http.apply(new JwtTokenFilterConfigurer(jwtTokenProvider));

// Optional, if you want to test the API from a browser
// http.httpBasic();
```

# How to use this code?

1. Make sure you have [Java 8](https://www.java.com/download/) and [Maven](https://maven.apache.org) installed

2. Fork this repository and clone it
  
```
$ git clone https://github.com/<your-user>/spring-boot-jwt
```

3. Navigate into the folder  

```
$ cd spring-boot-jwt
```

4. Install dependencies

```
$ mvn install
```

5. Run the project

```
$ mvn spring-boot:run
```

6. Navigate to `http://localhost:8080/swagger-ui.html` in your browser to check everything is working correctly. You can change the default port in the `application.yml` file

```yml
server:
  port: 8080
```

7. Make a GET request to `/users/me` to check you're not authenticated. You should receive a response with a `403` with an `Access Denied` message since you haven't set your valid JWT token yet

```
$ curl -X GET http://localhost:8080/users/me
```

8. Make a POST request to `/users/signin` with the default admin user we programatically created to get a valid JWT token

```
$ curl -X POST 'http://localhost:8080/users/signin?username=admin&password=admin'
```

9. Add the JWT token as a Header parameter and make the initial GET request to `/users/me` again

```
$ curl -X GET http://localhost:8080/users/me -H 'Authorization: Bearer <JWT_TOKEN>'
```

10. And that's it, congrats! You should get a similar response to this one, meaning that you're now authenticated

```javascript
{
  "id": 1,
  "username": "admin",
  "email": "admin@email.com",
  "roles": [
    "ROLE_ADMIN"
  ]
}
```

# Contribution

- Report issues
- Open pull request with improvements
- Spread the word
- Reach out to me directly at <patricio.moya.anton@gmail.com>
